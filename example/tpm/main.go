package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"

	"flag"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	hmaccred "github.com/salrashid123/aws_hmac/tpm"
	hmacsigner "github.com/salrashid123/aws_hmac/tpm/v4"
)

/*
go run main.go  --accessKeyID=redacted --secretAccessKey=redacted --persistentHandle=0x81008001 --flush=all  --evict

tpm2_getcap handles-persistent
- 0x81008001

tpm2_evictcontrol -C o -c 0x81008001
*/
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

	cc, err := hmaccred.NewHMACCredential(&hmaccred.HMACCredentialConfig{
		TPMConfig: hmaccred.TPMConfig{
			TPMDevice: rwc,
			TpmHandle: tpmutil.Handle(*persistentHandle),
		},
		AccessKeyID: *accessKeyID,
	})
	if err != nil {
		log.Printf("%v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	hs := hmacsigner.NewSigner()

	body := strings.NewReader("")
	sreq, err := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", body)
	if err != nil {
		log.Printf("%v\n", err)
		os.Exit(1)
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
