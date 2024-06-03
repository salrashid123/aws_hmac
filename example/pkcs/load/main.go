package main

import (
	"context"
	"crypto/sha256"
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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

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
	hsmLibrary  = flag.String("hsmLibrary", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "HSM  Library to load")
	accessKeyID = flag.String("accessKeyID", "", "AWS AccessKeyID")

	keyid           = flag.String("keyid", "0100", "PKCS Slot keyid")
	awsRegion       = flag.String("awsRegion", "us-east-1", "AWS Region")
	roleARN         = flag.String("roleARN", "arn:aws:iam::291738886548:role/gcpsts", "Role to assume")
	roleSessionName = "mysession"
)

func main() {
	flag.Parse()

	if *accessKeyID == "" {
		log.Fatal("accessKeyID  must be set")
	}

	// ***************************************************************************

	ctx := context.Background()

	id, err := hex.DecodeString(*keyid)
	if err != nil {
		log.Fatalf("error decoding keyid %v", err)
	}
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
		log.Fatalf("error creating pkcs signer %v", err)
	}
	hmacSigner := hmacsignerv4.NewSigner()

	sessionCredentials, err := hmaccred.NewAWSPKCSCredentials(hmaccred.PKCSProvider{
		GetSessionTokenInput: &sts.GetSessionTokenInput{
			DurationSeconds: aws.Int32(3600),
		},
		Version:    "2011-06-15",
		Region:     *awsRegion,
		PKCSSigner: pkcsSigner,
	})
	if err != nil {
		fmt.Printf("Could not initialize TPM Credentials %v\n", err)
		return
	}

	assumeRoleCredentials, err := hmaccred.NewAWSPKCSCredentials(hmaccred.PKCSProvider{
		AssumeRoleInput: &sts.AssumeRoleInput{
			RoleArn:         aws.String(*roleARN),
			RoleSessionName: aws.String(roleSessionName),
			DurationSeconds: aws.Int32(3600),
		},
		Version:    "2011-06-15",
		Region:     *awsRegion,
		PKCSSigner: pkcsSigner,
	})
	if err != nil {
		fmt.Printf("Could not read initialize TPM Credentials %v\n", err)
		return
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

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(*awsRegion), config.WithCredentialsProvider(sessionCredentials))
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v", err)
		return
	}

	stssvc := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.Region = *awsRegion
	})

	stsresp, err := stssvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v\n", err)
		return
	}
	fmt.Printf("STS Identity from API %s\n", *stsresp.UserId)

	fmt.Println("-------------------------------- GetCallerIdentity with AssumeRole SDK")

	cfg2, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(*awsRegion), config.WithCredentialsProvider(assumeRoleCredentials))
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v", err)
		return
	}

	stssvc2 := sts.NewFromConfig(cfg2, func(o *sts.Options) {
		o.Region = *awsRegion
	})
	stsresp2, err := stssvc2.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Printf("Could not read response Body%v", err)
		return
	}
	fmt.Printf("Assumed role ARN: %s\n", *stsresp2.Arn)

}
