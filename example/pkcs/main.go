package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/aws/aws-sdk-go/aws/credentials"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/miekg/pkcs11"

	"flag"

	"github.com/gorilla/schema"

	"github.com/salrashid123/aws_hmac/stsschema"

	hmaccred "github.com/salrashid123/aws_hmac/pkcs"
	hmacsigner "github.com/salrashid123/aws_hmac/pkcs/signer"
	hmacsignerv4 "github.com/salrashid123/aws_hmac/pkcs/signer/v4"
)

const (
	awsAlgorithm           = "AWS4-HMAC-SHA256"
	awsRequestType         = "aws4_request"
	awsSecurityTokenHeader = "x-amz-security-token"
	awsDateHeader          = "x-amz-date"
	awsTimeFormatLong      = "20060102T150405Z"
	awsTimeFormatShort     = "20060102"

	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var (
	keyURI          = flag.String("keyURI", "projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1", "KMS Key Uri")
	hsmLibrary      = flag.String("hsmLibrary", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "HSM  Library to load")
	accessKeyID     = flag.String("accessKeyID", "", "AWS AccessKeyID")
	secretAccessKey = flag.String("secretAccessKey", "", "AWS SecretAccessKey")

	awsRegion       = flag.String("awsRegion", "us-east-1", "AWS Region")
	roleARN         = flag.String("roleARN", "arn:aws:iam::291738886548:role/gcpsts", "Role to assume")
	roleSessionName = "mysession"
)

func main() {
	flag.Parse()

	if *accessKeyID == "" || *secretAccessKey == "" {
		log.Fatal("accessKeyID and secretAccessKey must be set")
	}

	// // // **************  STS

	log.Println("Using Default AWS v4Signer and StaticCredentials to make REST GET call to GetCallerIdentity")
	creds := credentials.NewStaticCredentials(*accessKeyID, *secretAccessKey, "")
	signer := v4.NewSigner(creds)
	rbody := strings.NewReader("")
	req, err := http.NewRequest(http.MethodGet, "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", rbody)
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

	log.Println("   Initializing PKCS Keyset embedding AWS Secret")

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

	ctx := context.Background()

	pkcsSigner, err := hmacsigner.NewPKCSSigner(&hmacsigner.PKCSSignerConfig{
		PKCSConfig: hmacsigner.PKCSConfig{
			Library: "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
			Slot:    0,
			Label:   "HMACKey",
			PIN:     "mynewpin",
			Id:      id,
		},
		AccessKeyID: *accessKeyID,
	})
	if err != nil {
		log.Fatalf("%v", err)
	}
	hmacSigner := hmacsignerv4.NewSigner()

	sessionCredentials, err := hmaccred.NewAWSPKCSCredentials(hmaccred.PKCSProvider{
		GetSessionTokenInput: &stsschema.GetSessionTokenInput{
			DurationSeconds: aws.Int64(3600),
		},
		Version:    "2011-06-15",
		Region:     *awsRegion,
		PKCSSigner: pkcsSigner,
	})
	if err != nil {
		log.Fatalf("Could not initialize Tink Credentials %v", err)
	}

	assumeRoleCredentials, err := hmaccred.NewAWSPKCSCredentials(hmaccred.PKCSProvider{
		AssumeRoleInput: &stsschema.AssumeRoleInput{
			RoleArn:         aws.String(*roleARN),
			RoleSessionName: aws.String(roleSessionName),
			DurationSeconds: aws.Int64(3600),
		},
		Version:    "2011-06-15",
		Region:     *awsRegion,
		PKCSSigner: pkcsSigner,
	})
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}
	// *******************************************

	fmt.Println("-------------------------------- Calling HTTP POST on  GetCallerIdentity using Tink Signer")

	getCallerIdentityRequestStruct := stsschema.GetCallerIdentityRequest{
		Action:  "GetCallerIdentity",
		Version: "2011-06-15",
	}

	postForm := url.Values{}
	err = schema.NewEncoder().Encode(getCallerIdentityRequestStruct, postForm)
	if err != nil {
		log.Fatalf("%v", err)
	}

	getCallerIdentityPostRequest, err := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com", strings.NewReader(postForm.Encode()))
	if err != nil {
		log.Fatalf("%v", err)
	}
	getCallerIdentityPostRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	hasher := sha256.New()
	hasher.Write([]byte(postForm.Encode()))
	postPayloadHash := hex.EncodeToString(hasher.Sum(nil))

	hmacSigner.SignHTTP(ctx, *pkcsSigner, getCallerIdentityPostRequest, postPayloadHash, "sts", *awsRegion, time.Now())
	if err != nil {
		log.Fatalf("%v", err)
	}

	getCallerIdentityPostResponse, err := http.DefaultClient.Do(getCallerIdentityPostRequest)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer getCallerIdentityPostResponse.Body.Close()

	if getCallerIdentityPostResponse.StatusCode != 200 {
		bodyBytes, err := io.ReadAll(getCallerIdentityPostResponse.Body)
		if err != nil {
			log.Fatal(err)
		}
		log.Fatalf("Response is not 200 %s %v\n", string(bodyBytes), err)
	}

	getResponseData, err := ioutil.ReadAll(getCallerIdentityPostResponse.Body)
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}
	var getCallerIdentityResponseStruct stsschema.GetCallerIdentityResponse
	err = xml.Unmarshal(getResponseData, &getCallerIdentityResponseStruct)
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}
	log.Printf("GetCallerIdentityResponse UserID %s\n", getCallerIdentityResponseStruct.CallerIdentityResult.UserId)

	fmt.Println("-------------------------------- GetCallerIdentity with SessionToken SDK")

	sess, err := awssession.NewSession(&aws.Config{
		Region:      aws.String(*awsRegion),
		Credentials: sessionCredentials,
	})

	stssvc := sts.New(sess, aws.NewConfig().WithRegion(*awsRegion))
	stsresp, err := stssvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}
	log.Printf("STS Identity from API %s\n", *stsresp.UserId)

	fmt.Println("-------------------------------- GetCallerIdentity with AssumeRole SDK")

	sess2, err := awssession.NewSession(&aws.Config{
		Region:      aws.String(*awsRegion),
		Credentials: assumeRoleCredentials,
	})

	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}

	stssvc2 := sts.New(sess2, aws.NewConfig().WithRegion(*awsRegion))
	stsresp2, err := stssvc2.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}
	log.Printf("Assumed role ARN: %s\n", *stsresp2.Arn)

}
