package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"flag"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/gorilla/schema"

	"github.com/salrashid123/aws_hmac/stsschema"

	hmaccred "github.com/salrashid123/aws_hmac/tpm"
	hmacsigner "github.com/salrashid123/aws_hmac/tpm/signer"
	hmacsignerv4 "github.com/salrashid123/aws_hmac/tpm/signer/v4"
)

const ()

var (
	accessKeyID     = flag.String("accessKeyID", "", "AWS AccessKeyID")
	awsRegion       = flag.String("awsRegion", "us-east-1", "AWS Region")
	roleARN         = flag.String("roleARN", "arn:aws:iam::291738886548:role/gcpsts", "Role to assume")
	roleSessionName = "mysession"

	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008001, "Handle value")

	in = flag.String("in", "private.pem", "privateKey File")

	ECCSRKHTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Parse()

	// ***************************************************************************

	//rwc, err := OpenTPM("simulator")
	// rwc, err := OpenTPM("127.0.0.1:2321")
	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("can't open TPM  %v", err)
		return
	}

	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(ECCSRKHTemplate),
	}.Execute(rwr)
	if err != nil {
		fmt.Printf("can't create primary %q: %v\n", *tpmPath, err)
		return
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	/// **** Done loading, now use the embedded key
	// if using persistentHandle, read the public to acquire the name

	// // from tpm2_evictcontrol -C o -c hmac.ctx 0x81008001
	// persistentHmacKey := tpm2.TPMHandle(persistentHandle)
	// persistentHmacPublic, err := tpm2.ReadPublic{
	// 	ObjectHandle: persistentHmacKey,
	// }.Execute(rwr)
	// if err != nil {
	// 	fmt.Printf("can't load hmac key from handle %v", err)
	//  return
	// }

	c, err := os.ReadFile(*in)
	if err != nil {
		fmt.Printf("error reading private keyfile: %v\n", err)
		return
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		fmt.Printf("failed decoding key: %v\n", err)
		return
	}

	hmacKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)
	if err != nil {
		fmt.Printf("can't load  hmacKey: %v\n", err)
		return
	}

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(rwr)
		if err != nil {
			fmt.Printf("can't close hmackey handle: %v", err)
			os.Exit(1)
		}
	}()

	// acquire a well-known key you know to be on the system
	// and use this for session encryption (eg, encrypting traffic on the hardware cpu<->tpm bus)
	//  this step is optional but recommended, In the following example, i'm using the EK
	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}
	createEKRsp, err := createEKCmd.Execute(rwr)
	if err != nil {
		fmt.Printf("can't acquire acquire ek %v\n", err)
		return
	}
	encryptionPub, err := createEKRsp.OutPublic.Contents()
	if err != nil {
		fmt.Printf("can't create ekpub blob %v\n", err)
		return
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKRsp.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pub, err := tpm2.ReadPublic{
		ObjectHandle: hmacKey.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		fmt.Printf("can't read public %v\n", err)
		return
	}

	tpmSigner, err := hmacsigner.NewTPMSigner(&hmacsigner.TPMSignerConfig{
		TPMConfig: hmacsigner.TPMConfig{
			TPMDevice: rwc,
			NamedHandle: tpm2.NamedHandle{
				Handle: hmacKey.ObjectHandle,
				Name:   pub.Name,
			},
			EncryptionHandle: createEKRsp.ObjectHandle,
			EncryptionPub:    encryptionPub,
		},
		AccessKeyID: *accessKeyID,
	})
	if err != nil {
		fmt.Printf("Error creating Signer %v\n", err)
		return
	}

	hmacSigner := hmacsignerv4.NewSigner()

	sessionCredentials, err := hmaccred.NewAWSTPMCredentials(hmaccred.TPMProvider{
		GetSessionTokenInput: &sts.GetSessionTokenInput{
			DurationSeconds: aws.Int32(3600),
		},
		Version:   "2011-06-15",
		Region:    *awsRegion,
		TPMSigner: tpmSigner,
	})
	if err != nil {
		fmt.Printf("Could not initialize TPM Credentials %v\n", err)
		return
	}

	assumeRoleCredentials, err := hmaccred.NewAWSTPMCredentials(hmaccred.TPMProvider{
		AssumeRoleInput: &sts.AssumeRoleInput{
			RoleArn:         aws.String(*roleARN),
			RoleSessionName: aws.String(roleSessionName),
			DurationSeconds: aws.Int32(3600),
		},
		Version:   "2011-06-15",
		Region:    *awsRegion,
		TPMSigner: tpmSigner,
	})
	if err != nil {
		fmt.Printf("Could not read initialize TPM Credentials %v\n", err)
		return
	}

	ctx := context.Background()

	// *******************************************

	fmt.Println("-------------------------------- Calling HTTP POST on  GetCallerIdentity using TPM Signer")

	getCallerIdentityRequestStruct := stsschema.GetCallerIdentityRequest{
		Action:  "GetCallerIdentity",
		Version: "2011-06-15",
	}

	postForm := url.Values{}
	err = schema.NewEncoder().Encode(getCallerIdentityRequestStruct, postForm)
	if err != nil {
		fmt.Printf("Error encoding request schema %v\n", err)
		return
	}

	getCallerIdentityPostRequest, err := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com", strings.NewReader(postForm.Encode()))
	if err != nil {
		fmt.Printf("error getCallerIdentityPostRequest %v", err)
		return
	}
	getCallerIdentityPostRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	hasher := sha256.New()
	hasher.Write([]byte(postForm.Encode()))
	postPayloadHash := hex.EncodeToString(hasher.Sum(nil))

	hmacSigner.SignHTTP(ctx, *tpmSigner, getCallerIdentityPostRequest, postPayloadHash, "sts", *awsRegion, time.Now())
	if err != nil {
		fmt.Printf("error SignHTTP %v", err)
		return
	}

	getCallerIdentityPostResponse, err := http.DefaultClient.Do(getCallerIdentityPostRequest)
	if err != nil {
		fmt.Printf("Error getCallerIdentityPostRequest %v", err)
		return
	}
	defer getCallerIdentityPostResponse.Body.Close()

	if getCallerIdentityPostResponse.StatusCode != 200 {
		bodyBytes, err := io.ReadAll(getCallerIdentityPostResponse.Body)
		if err != nil {
			fmt.Printf("Error reading respone body %v\n", err)
			return
		}
		fmt.Printf("Response is not 200 %s %v\n", string(bodyBytes), err)
		return
	}

	getResponseData, err := io.ReadAll(getCallerIdentityPostResponse.Body)
	if err != nil {
		fmt.Printf("Could not read response Body %v\n", err)
		return
	}
	var getCallerIdentityResponseStruct stsschema.GetCallerIdentityResponse
	err = xml.Unmarshal(getResponseData, &getCallerIdentityResponseStruct)
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentityResponse response Body %v\n", err)
		return
	}
	fmt.Printf("GetCallerIdentityResponse UserID %s\n", getCallerIdentityResponseStruct.CallerIdentityResult.UserId)

	fmt.Println("-------------------------------- GetCallerIdentity with SessionToken SDK")

	// sess, err := session.NewSession(&aws.Config{
	// 	Region:      *awsRegion,
	// 	Credentials: sessionCredentials,
	// })

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
