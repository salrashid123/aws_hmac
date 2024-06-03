package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"os"

	"flag"

	gcpkms "github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"google.golang.org/protobuf/proto"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/subtle"

	common_go_proto "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	tagSize = 32

	// $ touch empty.txt
	// $ sha256sum empty.txt
	//   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.txt

	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var (
	accessKeyID     = flag.String("accessKeyID", "", "AWS AccessKeyID")
	secretAccessKey = flag.String("secretAccessKey", "", "AWS SecretAccessKey")
	keyURI          = flag.String("keyURI", "projects/PROJECT_ID/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1", "KMS Key Uri")
	out             = flag.String("out", "key.json", "Where to write the keyset file")
)

func main() {
	flag.Parse()

	// ***************************************************************************

	log.Println("   Initializing GCP KMS Encrypted Tink Keyset embedding AWS Secret")

	if *keyURI == "" {
		log.Fatal("keyURI must be set if mode=tink")
	}

	id := rand.Uint32()

	tk, err := subtle.NewHMAC(common_go_proto.HashType_name[int32(common_go_proto.HashType_SHA256)], []byte("AWS4"+*secretAccessKey), tagSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	// note that the tk.Key was removed
	//  but whatever, i'm still gonna do this:
	//   https://github.com/tink-crypto/tink-go/commit/12f5f9ea983779ee811d95c473414bb05e60e5d2
	//   github.com/salrashid123/aws_hmac/tink/signer
	// go get github.com/tink-crypto/tink-go/v2@v2.1.0
	k := &hmacpb.HmacKey{
		Version: 0,
		Params: &hmacpb.HmacParams{
			Hash:    common_go_proto.HashType_SHA256,
			TagSize: tagSize,
		},
		KeyValue: tk.Key,
	}
	//log.Printf("    Tink HmacKey Key: %v", base64.StdEncoding.EncodeToString(k.GetKeyValue()))

	keyserialized, err := proto.Marshal(k)
	if err != nil {
		log.Fatal(err)
	}

	// construct a keyset and place the serialized key into that
	keysetKey := &tinkpb.Keyset_Key{
		KeyData: &tinkpb.KeyData{
			TypeUrl:         "type.googleapis.com/google.crypto.tink.HmacKey",
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			Value:           keyserialized,
		},
		KeyId:            id,
		Status:           tinkpb.KeyStatusType_ENABLED,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}

	ks := &tinkpb.Keyset{
		PrimaryKeyId: id,
		Key:          []*tinkpb.Keyset_Key{keysetKey},
	}

	// Serialize the whole keyset
	rawSerialized, err := proto.Marshal(ks)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Encrypt the serialized keyset with kms
	gcpClient, err := gcpkms.NewClientWithOptions(ctx, "gcp-kms://")
	if err != nil {
		log.Fatal(err)
	}
	backend, err := gcpClient.GetAEAD("gcp-kms://" + *keyURI)
	if err != nil {
		log.Printf("Could not acquire KMS Hmac %v", err)
		return
	}

	ciphertext, err := backend.Encrypt(rawSerialized, []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	// Create  an EncryptedKeyset and embed the encrypted key into that
	ksi := &tinkpb.KeysetInfo{
		PrimaryKeyId: keysetKey.KeyId,
		KeyInfo: []*tinkpb.KeysetInfo_KeyInfo{
			{
				TypeUrl:          keysetKey.KeyData.TypeUrl,
				Status:           keysetKey.Status,
				KeyId:            keysetKey.KeyId,
				OutputPrefixType: keysetKey.OutputPrefixType,
			},
		},
	}

	eks := &tinkpb.EncryptedKeyset{
		EncryptedKeyset: ciphertext,
		KeysetInfo:      ksi,
	}

	eksSerialized, err := proto.Marshal(eks)
	if err != nil {
		log.Fatal(err)
	}

	// Print the Encrypted Keyset

	eks2 := &tinkpb.EncryptedKeyset{}
	err = proto.Unmarshal(eksSerialized, eks2)
	if err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	if err := w.WriteEncrypted(eks2); err != nil {
		log.Printf("Could not write encrypted keyhandle %v", err)
		return
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	if err != nil {
		log.Fatalf("JSON parse error: %v ", err)
	}
	log.Println("   Tink Keyset:\n", string(prettyJSON.Bytes()))

	err = os.WriteFile(*out, prettyJSON.Bytes(), 0644)
	if err != nil {
		log.Fatalf("error writing file: %v ", err)
	}
	// ********************************************

}
