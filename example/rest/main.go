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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"google.golang.org/protobuf/proto"

	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/gorilla/schema"

	"flag"

	"github.com/salrashid123/aws_hmac/stsschema"

	gcpkms "github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/subtle"
	common_go_proto "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"

	hmaccred "github.com/salrashid123/aws_hmac/tink"
	hmacsigner "github.com/salrashid123/aws_hmac/tink/signer"
	hmacsignerv4 "github.com/salrashid123/aws_hmac/tink/signer/v4"
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

	ctx := context.Background()
	gcpClient, err := gcpkms.NewClientWithOptions(ctx, "gcp-kms://")
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt the serialized keyset with kms
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
		GetSessionTokenInput: &sts.GetSessionTokenInput{
			DurationSeconds: aws.Int32(3600),
		},
		Version:    "2011-06-15",
		Region:     *awsRegion,
		TinkSigner: tinkSigner,
	})
	if err != nil {
		fmt.Printf("Could not initialize TPM Credentials %v\n", err)
		return
	}

	assumeRoleCredentials, err := hmaccred.NewAWSTinkCredentials(hmaccred.TINKProvider{
		AssumeRoleInput: &sts.AssumeRoleInput{
			RoleArn:         aws.String(*roleARN),
			RoleSessionName: aws.String(roleSessionName),
			DurationSeconds: aws.Int32(3600),
		},
		Version:    "2011-06-15",
		Region:     *awsRegion,
		TinkSigner: tinkSigner,
	})
	if err != nil {
		fmt.Printf("Could not read initialize TPM Credentials %v\n", err)
		return
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

	getResponseData, err := io.ReadAll(getResponse.Body)
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

	sc := credentials.NewStaticCredentialsProvider(assumeRoleOutput.AssumeRoleResult.Credentials.AccessKeyId, assumeRoleOutput.AssumeRoleResult.Credentials.SecretAccessKey, assumeRoleOutput.AssumeRoleResult.Credentials.SessionToken)
	s3cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(*awsRegion), config.WithCredentialsProvider(sc))
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v", err)
		return
	}

	s3svc := s3.NewFromConfig(s3cfg, func(o *s3.Options) {
		o.Region = *awsRegion
	})
	input := &s3.ListBucketsInput{}
	result1, err := s3svc.ListBuckets(ctx, input)
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

	log.Println(len(result1.Buckets))

	// *********************************

	fmt.Println("-------------------------------- Calling s3 list buckets using Tink Signer with AssumeRole")

	s3cfg2, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(*awsRegion), config.WithCredentialsProvider(assumeRoleCredentials))
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v", err)
		return
	}

	s3svc2 := s3.NewFromConfig(s3cfg2, func(o *s3.Options) {
		o.Region = *awsRegion
	})

	result2, err := s3svc2.ListBuckets(ctx, input)
	if err != nil {
		fmt.Printf("Could not reading bucket response %v", err)
		return
	}
	log.Println(len(result2.Buckets))

	fmt.Println("-------------------------------- Calling s3 list buckets using Tink Signer with GetSessionTOken")

	s3cfg3, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(*awsRegion), config.WithCredentialsProvider(sessionCredentials))
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v", err)
		return
	}

	s3svc3 := s3.NewFromConfig(s3cfg3, func(o *s3.Options) {
		o.Region = *awsRegion
	})
	result3, err := s3svc3.ListBuckets(ctx, input)
	if err != nil {
		fmt.Printf("Could not reading bucket response %v", err)
		return
	}
	log.Println(len(result3.Buckets))

}
