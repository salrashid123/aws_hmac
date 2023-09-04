package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"

	"github.com/miekg/pkcs11"

	"flag"

	hmacsigner "github.com/salrashid123/aws_hmac/pkcs"
	hmaccred "github.com/salrashid123/aws_hmac/pkcs/credentials"
)

const (
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
	accessKeyID     = flag.String("accessKeyID", "", "AWS AccessKeyID")
	secretAccessKey = flag.String("secretAccessKey", "", "AWS SecretAccessKey")

	awsRegion = flag.String("awsRegion", "us-east-1", "AWS Region")
)

func main() {
	flag.Parse()

	if *accessKeyID == "" || *secretAccessKey == "" {
		log.Fatal("accessKeyID and secretAccessKey must be set")
	}

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

	pin := "mynewpin"
	// Init PKCS

	p := pkcs11.New(*hsmLibrary)
	err = p.Initialize()
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

	cc, err := hmaccred.NewHMACCredential(&hmaccred.HMACCredentialConfig{
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

	// now call the endpoint

	ctx := context.Background()
	hs := hmacsigner.NewSigner()

	body := strings.NewReader("")
	sreq, err := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", body)
	if err != nil {
		log.Fatalln(err)
	}

	// $ touch empty.txt
	// $ sha256sum empty.txt
	//   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.txt

	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hs.SignHTTP(ctx, *cc, sreq, payloadHash, "sts", *awsRegion, time.Now())
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
