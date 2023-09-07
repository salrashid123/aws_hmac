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
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"

	"flag"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/gorilla/schema"

	"github.com/salrashid123/aws_hmac/stsschema"

	hmaccred "github.com/salrashid123/aws_hmac/tpm"
	hmacsigner "github.com/salrashid123/aws_hmac/tpm/signer"
	hmacsignerv4 "github.com/salrashid123/aws_hmac/tpm/signer/v4"
)

const (
	awsAlgorithm           = "AWS4-HMAC-SHA256"
	awsRequestType         = "aws4_request"
	awsSecurityTokenHeader = "x-amz-security-token"
	awsDateHeader          = "x-amz-date"
	awsTimeFormatLong      = "20060102T150405Z"
	awsTimeFormatShort     = "20060102"

	emptyPassword                   = ""
	defaultPassword                 = ""
	CmdHmacStart    tpmutil.Command = 0x0000015B
)

var (
	accessKeyID     = flag.String("accessKeyID", "", "AWS AccessKeyID")
	secretAccessKey = flag.String("secretAccessKey", "", "AWS SecretAccessKey")

	awsRegion = flag.String("awsRegion", "us-east-1", "AWS Region")

	roleARN         = flag.String("roleARN", "arn:aws:iam::291738886548:role/gcpsts", "Role to assume")
	roleSessionName = "mysession"

	evict            = flag.Bool("evict", false, "evict handle")
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	flush            = flag.String("flush", "all", "Data to HMAC")
	persistentHandle = flag.Uint("persistentHandle", 0x81008003, "Handle value")

	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt | tpm2.FlagRestricted | tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		AuthPolicy: []byte(defaultPassword),
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

	public := tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    tpm2.AlgSHA256,
		AuthPolicy: []byte(defaultPassword),
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagUserWithAuth | tpm2.FlagSign, // | tpm2.FlagSensitiveDataOrigin
		KeyedHashParameters: &tpm2.KeyedHashParams{
			Alg:  tpm2.AlgHMAC,
			Hash: tpm2.AlgSHA256,
		},
	}

	hmacKeyBytes := []byte("AWS4" + *secretAccessKey)
	privInternal, pubArea, _, _, _, err := tpm2.CreateKeyWithSensitive(rwc, pkh, pcrSelection, defaultPassword, defaultPassword, public, hmacKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  creating Sensitive %v\n", err)
		os.Exit(1)
	}

	newHandle, _, err := tpm2.Load(rwc, pkh, emptyPassword, pubArea, privInternal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  loading hash key %v\n", err)
		os.Exit(1)
	}

	pHandle := tpmutil.Handle(*persistentHandle)

	if *evict {
		err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, pHandle, pHandle)
		if err != nil {
			fmt.Printf("     Unable evict persistentHandle: %v ", err)
			//os.Exit(1)
		}
	}
	err = tpm2.EvictControl(rwc, emptyPassword, tpm2.HandleOwner, newHandle, pHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  persisting hash key  %v\n", err)
		os.Exit(1)
	}

	tpm2.FlushContext(rwc, newHandle)
	tpm2.FlushContext(rwc, pHandle)

	/// **** Done loading, now use the embedded key

	tpmSigner, err := hmacsigner.NewTPMSigner(&hmacsigner.TPMSignerConfig{
		TPMConfig: hmacsigner.TPMConfig{
			TPMDevice: rwc,
			TpmHandle: tpmutil.Handle(*persistentHandle),
		},
		AccessKeyID: *accessKeyID,
	})  
	if err != nil {
		fmt.Printf("%v", err)
		return
	}

	hmacSigner := hmacsignerv4.NewSigner()

	sessionCredentials, err := hmaccred.NewAWSTPMCredentials(hmaccred.TPMProvider{
		GetSessionTokenInput: &stsschema.GetSessionTokenInput{
			DurationSeconds: aws.Int64(3600),
		},
		Version:   "2011-06-15",
		Region:    *awsRegion,
		TPMSigner: tpmSigner,
	})
	if err != nil {
		log.Fatalf("Could not initialize Tink Credentials %v", err)
	}

	assumeRoleCredentials, err := hmaccred.NewAWSTPMCredentials(hmaccred.TPMProvider{
		AssumeRoleInput: &stsschema.AssumeRoleInput{
			RoleArn:         aws.String(*roleARN),
			RoleSessionName: aws.String(roleSessionName),
			DurationSeconds: aws.Int64(3600),
		},
		Version:     "2011-06-15",
		Region:      *awsRegion,
		TPMSigner: tpmSigner,
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

	hmacSigner.SignHTTP(ctx, *tpmSigner, getCallerIdentityPostRequest, postPayloadHash, "sts", *awsRegion, time.Now())
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
