package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/gorilla/schema"

	"github.com/salrashid123/aws_hmac/stsschema"

	hmaccred "github.com/salrashid123/aws_hmac/vault"
	hmacsigner "github.com/salrashid123/aws_hmac/vault/signer"
	hmacsignerv4 "github.com/salrashid123/aws_hmac/vault/signer/v4"
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
	accessKeyID     = flag.String("accessKeyID", "", "AWS AccessKeyID")
	secretAccessKey = flag.String("secretAccessKey", "", "AWS SecretAccessKey")

	awsRegion = flag.String("awsRegion", "us-east-1", "AWS Region")

	roleARN         = flag.String("roleARN", "arn:aws:iam::291738886548:role/gcpsts", "Role to assume")
	roleSessionName = "mysession"

	vaultCAcert = flag.String("vaultCAcert", "vault_resources/ca.pem", "CA for the vault server")
	vaultAddr   = flag.String("vaultAddr", "https://vault.domain.com:8200", "Address of the vault server")
	vaultToken  = flag.String("vaultToken", "", "Vault Token")
	vaultPath   = flag.String("vaultPath", "transit/hmac/aws-key-1/sha2-256", "Path to the HMAC Key")
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

	if *vaultToken == "" {
		log.Fatal("vaultToken must be set if")
	}

	vaultSigner, err := hmacsigner.NewVaultSigner(&hmacsigner.VaultSignerConfig{
		VaultConfig: hmacsigner.VaultConfig{
			VaultToken:  *vaultToken,
			VaultCAcert: *vaultCAcert,
			VaultPath:   *vaultPath,
			VaultAddr:   *vaultAddr,
		},
		AccessKeyID: *accessKeyID,
	})
	if err != nil {
		fmt.Printf("%v", err)
		return
	}

	hmacSigner := hmacsignerv4.NewSigner()

	sessionCredentials, err := hmaccred.NewAWSVaultCredentials(hmaccred.VaultProvider{
		GetSessionTokenInput: &stsschema.GetSessionTokenInput{
			DurationSeconds: aws.Int64(3600),
		},
		Version:     "2011-06-15",
		Region:      *awsRegion,
		VaultSigner: vaultSigner,
	})
	if err != nil {
		log.Fatalf("Could not initialize Tink Credentials %v", err)
	}

	assumeRoleCredentials, err := hmaccred.NewAWSVaultCredentials(hmaccred.VaultProvider{
		AssumeRoleInput: &stsschema.AssumeRoleInput{
			RoleArn:         aws.String(*roleARN),
			RoleSessionName: aws.String(roleSessionName),
			DurationSeconds: aws.Int64(3600),
		},
		Version:     "2011-06-15",
		Region:      *awsRegion,
		VaultSigner: vaultSigner,
	})
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}

	ctx := context.Background()

	// *******************************************

	fmt.Println("-------------------------------- Calling HTTP POST on  GetCallerIdentity using Vault Signer")

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

	hmacSigner.SignHTTP(ctx, *vaultSigner, getCallerIdentityPostRequest, postPayloadHash, "sts", *awsRegion, time.Now())
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

	sess, err := session.NewSession(&aws.Config{
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

	sess2, err := session.NewSession(&aws.Config{
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
