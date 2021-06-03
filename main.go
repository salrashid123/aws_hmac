package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac/subtle"
	common_go_proto "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/tink"
	"github.com/miekg/pkcs11"

	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"

	"flag"

	hmacsigner "github.com/salrashid123/hmacsigner"
	hmaccred "github.com/salrashid123/hmacsigner/credentials"
)

const (
	NonRawPrefixSize = 5
	RawPrefixSize    = 0
	TinkPrefixSize   = NonRawPrefixSize
	TinkStartByte    = byte(1)
	RawPrefix        = ""

	tagSize = 32

	awsAlgorithm           = "AWS4-HMAC-SHA256"
	awsRequestType         = "aws4_request"
	awsSecurityTokenHeader = "x-amz-security-token"
	awsDateHeader          = "x-amz-date"
	awsTimeFormatLong      = "20060102T150405Z"
	awsTimeFormatShort     = "20060102"
)

var (
	keyURI          = flag.String("keyURI", "projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1", "KMS Key Uri")
	hsmLibrary      = flag.String("hsmLibrary", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "HSM  Library to load")
	accessKeyID     = flag.String("accessKeyID", "AKIAUH3H6EGKERNFQLHJ", "AWS AccessKeyID")
	secretAccessKey = flag.String("secretAccessKey", "YRJ86SK5qTOZQzZTI1u-redacted", "AWS SecretAccessKey")

	awsRegion = flag.String("awsRegion", "us-east-2", "AWS Region")
	mode      = flag.String("mode", "pkcs", "What to test: pkcs|tink")
	a         tink.MAC
)

func main() {
	flag.Parse()

	if *accessKeyID == "" || *secretAccessKey == "" {
		log.Fatal("accessKeyID and secretAccessKey must be set")
	}

	var cc *hmaccred.HMACCredential

	// // // **************  STS

	// log.Println("Using  Standard AWS v4Signer")
	// creds := credentials.NewStaticCredentials(*accessKeyID, *secretAccessKey, "")
	// rbody := strings.NewReader("")
	// signer := v4.NewSigner(creds)
	// req, err := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", rbody)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// _, err = signer.Sign(req, rbody, "sts", "us-east-1", time.Now())
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// res, err := http.DefaultClient.Do(req)
	// if err != nil {
	// 	log.Fatalf("failed to call remote service: (%v)\n", err)
	// }

	// defer res.Body.Close()
	// if res.StatusCode != 200 {
	// 	fmt.Printf("service returned a status not 200: (%d)\n", res.StatusCode)
	// 	//return
	// }
	// b, err := ioutil.ReadAll(res.Body)
	// if err != nil {
	// 	log.Println(err)
	// }

	// log.Printf("   Response using AWS STS NewStaticCredentials and Standard v4.Singer \n%s", string(b))

	// ***************************************************************************

	if *mode == "tink" {
		if *keyURI == "" {
			log.Fatal("keyURI must be set if mode=tink")
		}

		log.Println("   Create tink subtle.HMAC using secret")
		id := rand.Uint32()

		tk, err := subtle.NewHMAC(common_go_proto.HashType_name[int32(common_go_proto.HashType_SHA256)], []byte("AWS4"+*secretAccessKey), tagSize)
		if err != nil {
			log.Fatal(err.Error())
		}

		k := &hmacpb.HmacKey{
			Version: 0,
			Params: &hmacpb.HmacParams{
				Hash:    common_go_proto.HashType_SHA256,
				TagSize: tagSize,
			},
			KeyValue: tk.Key,
		}
		// log.Printf("    Tink HmacKey Key: %v", base64.StdEncoding.EncodeToString(k.GetKeyValue()))

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

		// Encrypt the serialized keyset with kms
		gcpClient, err := gcpkms.NewClient("gcp-kms://")
		if err != nil {
			log.Fatal(err)
		}
		registry.RegisterKMSClient(gcpClient)

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
		error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
		if error != nil {
			log.Fatalf("JSON parse error: %v ", error)

		}
		log.Println("   Tink Keyset:\n", string(prettyJSON.Bytes()))

		cc, err = hmaccred.NewHMACCredential(&hmaccred.HMACCredentialConfig{
			TinkConfig: hmaccred.TinkConfig{
				KmsBackend: backend,
				JSONBytes:  prettyJSON.Bytes(),
			},
			AccessKeyID: *accessKeyID,
		})
		if err != nil {
			log.Fatalln(err)
		}

	} else if *mode == "pkcs" {
		pin := "mynewpin"
		// Init PKCS

		p := pkcs11.New(*hsmLibrary)
		err := p.Initialize()
		if err != nil {
			panic(err)
		}

		defer p.Destroy()
		defer p.Finalize()

		slots, err := p.GetSlotList(true)
		if err != nil {
			panic(err)
		}

		session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			panic(err)
		}
		//defer p.CloseSession(session)

		err = p.Login(session, pkcs11.CKU_USER, pin)
		if err != nil {
			panic(err)
		}
		defer p.Logout(session)

		info, err := p.GetInfo()
		if err != nil {
			panic(err)
		}
		fmt.Printf("CryptokiVersion.Major %v", info.CryptokiVersion.Major)

		fmt.Println()
		buf := new(bytes.Buffer)
		var num uint16 = 1
		err = binary.Write(buf, binary.LittleEndian, num)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
		}
		id := buf.Bytes()

		hmacKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_SHA256_HMAC),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
			pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // we do not need to extract this
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("AWS4"+*secretAccessKey)),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "HMACKey"), /* Name of Key */
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}

		// i'm recreating a new object everytime...ofcourse you can skip thisstep if the object with that name already exists..
		hmacKey, err := p.CreateObject(session, hmacKeyTemplate)
		if err != nil {
			panic(fmt.Sprintf("GenerateKey() failed %s\n", err))
		}
		err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_HMAC, nil)}, hmacKey)
		if err != nil {
			log.Fatalf("Signing Initiation failed (%s)\n", err.Error())
		}

		log.Printf("Created HMAC Key: %v", hmacKey)
		p.Logout(session)
		p.CloseSession(session)
		p.Finalize()
		p.Destroy()

		cc, err = hmaccred.NewHMACCredential(&hmaccred.HMACCredentialConfig{
			PKCSConfig: hmaccred.PKCSConfig{
				Library: "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
				Slot:    0,
				Label:   "HMACKey",
				PIN:     "mynewpin",
				Id:      id,
			},
			AccessKeyID: *accessKeyID,
		})
		if err != nil {
			log.Fatalln(err)
		}

	} else {
		log.Fatal("Mode must be either pkcs or tink")
	}

	ctx := context.Background()
	hs := hmacsigner.NewSigner()

	body := strings.NewReader("")
	sreq, err := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", body)
	if err != nil {
		log.Fatalln(err)
	}

	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hs.SignHTTP(ctx, *cc, sreq, payloadHash, "sts", "us-east-1", time.Now())
	if err != nil {
		log.Fatalf("%v", err)
	}

	log.Printf("    Signed RequestURI: %v\n", sreq.RequestURI)

	sres, err := http.DefaultClient.Do(sreq)
	if err != nil {
		log.Fatalf("%v", err)
	}

	defer sres.Body.Close()
	if sres.StatusCode != 200 {
		log.Printf("Response is not 200 %v\n", err)
	}
	sb, err := ioutil.ReadAll(sres.Body)
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}

	log.Printf("    STS Response:  \n%s", string(sb))

}
