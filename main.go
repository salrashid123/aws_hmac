package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	cr "crypto/rand"
	"os"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
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

	hmacsigner "github.com/salrashid123/aws_hmac/aws"
	hmaccred "github.com/salrashid123/aws_hmac/aws/credentials"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
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

	emptyPassword                 = ""
	CmdHmacStart  tpmutil.Command = 0x0000015B
)

var (
	keyURI          = flag.String("keyURI", "projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1", "KMS Key Uri")
	hsmLibrary      = flag.String("hsmLibrary", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "HSM  Library to load")
	accessKeyID     = flag.String("accessKeyID", "", "AWS AccessKeyID")
	secretAccessKey = flag.String("secretAccessKey", "", "AWS SecretAccessKey")

	awsRegion = flag.String("awsRegion", "us-east-2", "AWS Region")
	mode      = flag.String("mode", "pkcs", "What to test: pkcs|tink|tpm")
	a         tink.MAC

	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	primaryHandle = flag.String("primaryHandle", "primary.bin", "Handle to the primary")
	hmacKeyHandle = flag.String("hmacKeyHandle", "hmac.bin", "Handle to the primary")
	flush         = flag.String("flush", "all", "Data to HMAC")

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagRestricted | tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}
)

func main() {
	flag.Parse()

	if *accessKeyID == "" || *secretAccessKey == "" {
		log.Fatal("accessKeyID and secretAccessKey must be set")
	}

	var cc *hmaccred.HMACCredential

	// // // **************  STS

	log.Println("Using  Standard AWS v4Signer")
	creds := credentials.NewStaticCredentials(*accessKeyID, *secretAccessKey, "")
	rbody := strings.NewReader("")
	signer := v4.NewSigner(creds)
	req, err := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", rbody)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = signer.Sign(req, rbody, "sts", "us-east-1", time.Now())
	if err != nil {
		log.Fatalln(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("failed to call remote service: (%v)\n", err)
	}

	defer res.Body.Close()
	if res.StatusCode != 200 {
		fmt.Printf("service returned a status not 200: (%d)\n", res.StatusCode)
		//return
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
	}

	log.Printf("   Response using AWS STS NewStaticCredentials and Standard v4.Singer \n%s", string(b))

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
	} else if *mode == "tpm" {

		rwc, err := tpm2.OpenTPM(*tpmPath)
		if err != nil {

			fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
			os.Exit(1)
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				if strings.Contains(err.Error(), "file already closed") {
					os.Exit(0)
				}
				fmt.Fprintf(os.Stderr, "Can't close TPM (may already be closed earlier) %s: %v", *tpmPath, err)
				os.Exit(1)
			}
		}()

		totalHandles := 0
		for _, handleType := range handleNames[*flush] {
			handles, err := client.Handles(rwc, handleType)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error getting handles", *tpmPath, err)
				os.Exit(1)
			}
			for _, handle := range handles {
				if err = tpm2.FlushContext(rwc, handle); err != nil {
					fmt.Fprintf(os.Stderr, "Error flushing handle 0x%x: %v\n", handle, err)
					os.Exit(1)
				}
				fmt.Printf("Handle 0x%x flushed\n", handle)
				totalHandles++
			}
		}

		pcrList := []int{}
		pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

		pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, pkh)

		pkhBytes, err := tpm2.ContextSave(rwc, pkh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for pkh %v\n", err)
			os.Exit(1)
		}

		// err = tpm2.FlushContext(rwc, pkh)
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "ContextSave failed for pkh%v\n", err)
		// 	os.Exit(1)
		// }
		err = ioutil.WriteFile(*primaryHandle, pkhBytes, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for pkh%v\n", err)
			os.Exit(1)
		}

		private := tpm2.Private{
			Type:      tpm2.AlgKeyedHash,
			AuthValue: nil,
			SeedValue: make([]byte, 32),
			Sensitive: []byte("AWS4" + *secretAccessKey),
		}
		io.ReadFull(cr.Reader, private.SeedValue)

		privArea, err := private.Encode()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  encoding  private  %v\n", err)
			os.Exit(1)
		}

		duplicate, err := tpmutil.Pack(tpmutil.U16Bytes(privArea))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  encoding  dulicate  %v\n", err)
			os.Exit(1)
		}

		privHash := crypto.SHA256.New()
		privHash.Write(private.SeedValue)
		privHash.Write(private.Sensitive)
		public := tpm2.Public{
			Type:    tpm2.AlgKeyedHash,
			NameAlg: tpm2.AlgSHA256,
			// the object really should have the following attributes but i coudn't get this to work, the error was "parameter 2, error code 0x2 : inconsistent attributes"
			//Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagSign,
			Attributes: tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagSign,
			KeyedHashParameters: &tpm2.KeyedHashParams{
				Alg:    tpm2.AlgHMAC,
				Hash:   tpm2.AlgSHA256,
				Unique: privHash.Sum(nil),
			},
		}
		pubArea, err := public.Encode()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  encoding  public  %v\n", err)
			os.Exit(1)
		}

		emptyAuth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
		privInternal, err := tpm2.Import(rwc, pkh, emptyAuth, pubArea, duplicate, nil, nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Importing hash key  %v\n", err)
			os.Exit(1)
		}

		newHandle, _, err := tpm2.Load(rwc, pkh, emptyPassword, pubArea, privInternal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  loading hash key %v\n", err)
			os.Exit(1)
		}
		defer tpm2.FlushContext(rwc, newHandle)

		// pHandle := tpmutil.Handle(0x81010002)
		// err = tpm2.EvictControl(rwc, emptyPassword, tpm2.HandleOwner, newHandle, pHandle)
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr,"Error  persisting hash key  %v\n", err)
		// 	os.Exit(1)
		// }
		// defer tpm2.FlushContext(rwc, pHandle)

		fmt.Printf("======= ContextSave (newHandle) ========\n")
		ekhBytes, err := tpm2.ContextSave(rwc, newHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for ekh %v\n", err)
			os.Exit(1)
		}
		err = ioutil.WriteFile(*hmacKeyHandle, ekhBytes, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ContextSave failed for ekh%v\n", err)
			os.Exit(1)
		}
		err = tpm2.FlushContext(rwc, newHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  flush hash key  %v\n", err)
			os.Exit(1)
		}

		err = rwc.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  Closing TPM %v\n", err)
			os.Exit(1)
		}

		/// **** Done loading, now use the embedded key

		cc, err = hmaccred.NewHMACCredential(&hmaccred.HMACCredentialConfig{
			TPMConfig: hmaccred.TPMConfig{
				TpmDevice:     *tpmPath,
				TpmHandleFile: *hmacKeyHandle,
				//TpmHandle: 0x81010002,
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
