package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/gorilla/schema"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"

	"flag"

	"github.com/salrashid123/aws_hmac/stsschema"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac/subtle"
	common_go_proto "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	hmaccred "github.com/salrashid123/aws_hmac/tink"
	hmacsigner "github.com/salrashid123/aws_hmac/tink/signer"
	hmacsignerv4 "github.com/salrashid123/aws_hmac/tink/signer/v4"
)

const (
	awsAlgorithm           = "AWS4-HMAC-SHA256"
	awsRequestType         = "aws4_request"
	awsSecurityTokenHeader = "x-amz-security-token"
	awsDateHeader          = "x-amz-date"
	awsTimeFormatLong      = "20060102T150405Z"
	awsTimeFormatShort     = "20060102"

	NonRawPrefixSize = 5
	RawPrefixSize    = 0
	TinkPrefixSize   = NonRawPrefixSize
	TinkStartByte    = byte(1)
	RawPrefix        = ""

	tagSize = 32

	// $ touch empty.txt
	// $ sha256sum empty.txt
	//   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.txt

	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var (
	accessKeyID     = flag.String("accessKeyID", "", "AWS AccessKeyID")
	secretAccessKey = flag.String("secretAccessKey", "", "AWS SecretAccessKey")
	awsRegion       = flag.String("awsRegion", "us-east-1", "AWS Region")
	keyURI          = flag.String("keyURI", "projects/PROJECT_ID/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1", "KMS Key Uri")
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

	log.Println("   Initializing GCP KMS Encrypted Tink Keyset embedding AWS Secret")

	if *keyURI == "" {
		log.Fatal("keyURI must be set if mode=tink")
	}

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

	// ********************************************

	ctx := context.Background()

	tinkSigner, err := hmacsigner.NewTinkSigner(&hmacsigner.TinkSignerConfig{
		TinkConfig: hmacsigner.TinkConfig{
			KmsBackend: backend,
			JSONBytes:  prettyJSON.Bytes(),
		},
		AccessKeyID: *accessKeyID,
	})
	if err != nil {
		log.Fatalf("%v", err)
	}
	hmacSigner := hmacsignerv4.NewSigner()

	sessionCredentials, err := hmaccred.NewAWSTinkCredentials(hmaccred.TINKProvider{
		GetSessionTokenInput: &stsschema.GetSessionTokenInput{
			DurationSeconds: aws.Int64(3600),
		},
		Version:    "2011-06-15",
		Region:     *awsRegion,
		TinkSigner: tinkSigner,
	})
	if err != nil {
		log.Fatalf("Could not initialize Tink Credentials %v", err)
	}

	assumeRoleCredentials, err := hmaccred.NewAWSTinkCredentials(hmaccred.TINKProvider{
		AssumeRoleInput: &stsschema.AssumeRoleInput{
			RoleArn:         aws.String(*roleARN),
			RoleSessionName: aws.String(roleSessionName),
			DurationSeconds: aws.Int64(3600),
		},
		Version:    "2011-06-15",
		Region:     *awsRegion,
		TinkSigner: tinkSigner,
	})
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}
	// *******************************************
	fmt.Println("-------------------------------- Calling HTTP GET on  GetCallerIdentity using Tink Signer")

	emptyBody := strings.NewReader("")
	getCallerIdentityRequest, err := http.NewRequest(http.MethodGet, "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", emptyBody)
	if err != nil {
		log.Fatalln(err)
	}

	hmacSigner.SignHTTP(ctx, *tinkSigner, getCallerIdentityRequest, emptyPayloadHash, "sts", *awsRegion, time.Now())
	if err != nil {
		log.Fatalf("%v", err)
	}

	getResponse, err := http.DefaultClient.Do(getCallerIdentityRequest)
	if err != nil {
		log.Fatalf("%v", err)
	}

	defer getResponse.Body.Close()
	if getResponse.StatusCode != 200 {
		log.Printf("Response is not 200 %v\n", err)
	}

	var getCallerIdentityResponseStruct stsschema.GetCallerIdentityResponse

	getResponseData, err := ioutil.ReadAll(getResponse.Body)
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}
	err = xml.Unmarshal(getResponseData, &getCallerIdentityResponseStruct)
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}

	log.Printf("GetCallerIdentityResponse UserID %s\n", getCallerIdentityResponseStruct.CallerIdentityResult.UserId)

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

	hmacSigner.SignHTTP(ctx, *tinkSigner, getCallerIdentityPostRequest, postPayloadHash, "sts", *awsRegion, time.Now())
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

	getResponseData, err = ioutil.ReadAll(getCallerIdentityPostResponse.Body)
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}
	err = xml.Unmarshal(getResponseData, &getCallerIdentityResponseStruct)
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}
	log.Printf("GetCallerIdentityResponse UserID %s\n", getCallerIdentityResponseStruct.CallerIdentityResult.UserId)

	fmt.Println("-------------------------------- Calling  AWS SDK sts.GetCallerIdentity using Tink Signer")

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

	//**********************************************************************

	fmt.Println("-------------------------------- Calling HTTP GET on  AssumeRole using Tink Signer")

	assumeRoleRequest, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://sts.amazonaws.com?Action=AssumeRole&Version=2011-06-15&RoleArn=%s&RoleSessionName=%s", *roleARN, roleSessionName), emptyBody)
	if err != nil {
		log.Fatalln(err)
	}

	hmacSigner.SignHTTP(ctx, *tinkSigner, assumeRoleRequest, emptyPayloadHash, "sts", *awsRegion, time.Now())
	if err != nil {
		log.Fatalf("%v", err)
	}

	assumeRoleResponse, err := http.DefaultClient.Do(assumeRoleRequest)
	if err != nil {
		log.Fatalf("%v", err)
	}

	defer assumeRoleResponse.Body.Close()
	if assumeRoleResponse.StatusCode != 200 {
		log.Printf("Response is not 200 %v\n", err)
	}

	var assumeRoleOutput stsschema.AssumeRoleResponse

	assumeRoleResponseBytes, err := ioutil.ReadAll(assumeRoleResponse.Body)
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}
	err = xml.Unmarshal(assumeRoleResponseBytes, &assumeRoleOutput)
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}

	log.Printf("AssumeResponse %s\n", assumeRoleOutput.AssumeRoleResult.Credentials.AccessKeyId)

	fmt.Println("-------------------------------- Calling s3 list buckets using StaticCredentials pupulated TinkSigner POST with  AssumeRole")

	log.Println("Listing Buckets using s3 client library")

	log.Println("-------------------------------- List buckets with NewStaticCredentials")
	sess, err = session.NewSession(&aws.Config{
		Region:      aws.String(*awsRegion),
		Credentials: credentials.NewStaticCredentials(assumeRoleOutput.AssumeRoleResult.Credentials.AccessKeyId, assumeRoleOutput.AssumeRoleResult.Credentials.SecretAccessKey, assumeRoleOutput.AssumeRoleResult.Credentials.SessionToken),
	})

	s3svc := s3.New(sess, aws.NewConfig().WithRegion(*awsRegion))
	input := &s3.ListBucketsInput{}

	result, err := s3svc.ListBuckets(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {

			fmt.Println(err.Error())
		}
		return
	}

	log.Println(result.Buckets)

	// *********************************

	fmt.Println("-------------------------------- Calling s3 list buckets using Tink Signer with AssumeRole")

	sess2, err := session.NewSession(&aws.Config{
		Region:      aws.String(*awsRegion),
		Credentials: assumeRoleCredentials,
	})

	svc2 := s3.New(sess2, aws.NewConfig().WithRegion(*awsRegion))
	input2 := &s3.ListBucketsInput{}

	result2, err := svc2.ListBuckets(input2)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {

			fmt.Println(err.Error())
		}
		return
	}
	log.Println(result2.Buckets)

	fmt.Println("-------------------------------- Calling s3 list buckets using Tink Signer with GetSessionTOken")

	sess, err = session.NewSession(&aws.Config{
		Region:      aws.String(*awsRegion),
		Credentials: sessionCredentials,
	})

	s3svc = s3.New(sess, aws.NewConfig().WithRegion(*awsRegion))
	listBucketInput := &s3.ListBucketsInput{}

	listBucketResult, err := s3svc.ListBuckets(listBucketInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {

			fmt.Println(err.Error())
		}
		return
	}
	log.Println(listBucketResult.Buckets)

	fmt.Println("-------------------------------- Calling ec2 list regions using Tink Signer with AssumeRole")
	sess, err = session.NewSession(&aws.Config{
		Region:      aws.String(*awsRegion),
		Credentials: assumeRoleCredentials,
	})

	ec2svc := ec2.New(sess, aws.NewConfig().WithRegion(*awsRegion))
	regions, err := ec2svc.DescribeRegions(&ec2.DescribeRegionsInput{})
	if err != nil {
		log.Fatalf("Could not read response Body%v", err)
	}

	log.Printf("Region count %d\n", len(regions.Regions))

}
