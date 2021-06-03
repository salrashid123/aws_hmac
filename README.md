## AWS v4 Signer With TINK Encryption and HSM embedded AWS Secret Access Key

Sample procedure to encrypt AWS Access [Secret Access Key](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys) using [GCP Tink](https://developers.google.com/tink/how-tink-works) and a way to embed the the Key into an HSM device supporting [PKCS #11](https://en.wikipedia.org/wiki/PKCS_11).

AWS secret key and ID can be thought of as a username/password and should be carefully managed, rotated, secured as described in [Best practices for managing AWS access keys](https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html).   However, if you need to invoke AWS from remote systems which do not provide ambient federation (eg on [GCP using OIDC tokens](https://github.com/salrashid123/awscompat)), then you must either utilize an AWS credentials file or set them dynamically as an environment variable.  

This repo provides two ways to protect the aws secret:

1. Wrap the secret using KMS and access it via TINK.
2. Embed the secret into an HSM an access it via PKCS11


>> NOTE: This code is NOT Supported by Google; its just a POC. caveat emptor

>> Most of the code under the `aws/` folder is taken from [https://github.com/aws/aws-sdk-go-v2/blob/main/aws/signer/v4/v4.go](https://github.com/aws/aws-sdk-go-v2/blob/main/aws/signer/v4/v4.go) which i modified for TINK and PKCS11
---

In (1) you are using KMS to encrypt the Secret and save it in encrypted format.  When you need to access the Secret to make it generate an AWS v4 signing request, the raw Secret is automatically decrypted by TINK using KMS and made to HMAC sign.  The user will never need to "see" the secret but it is true that the key gets decoded in memory.  You will also need to have access to KMS in the first place so this example is a bit convoluted.   Use this if you already have access to another cloud providers KMS (eg GCP KMS), then use that decrypt the Key and then make it sign:

The encrypted Key would look like the following:

```json
{
	"encryptedKeyset": "CiUAmT+VVWAVKQZfFW6UheHPI1E3VmvTFlv2C4cspNaqpbxc8YvEEqUBACsKZVI1IW8U+86r2Yset0WOKwnggDitP0hi0oUapgOrF4W7Pklrbso93gfMoNDVw2QCWW4HwJwKzElQRi3zWHuL6NJP4t/t2VtIWORgWLz76zpH7+JWn6IrlqA/M4sammN0kAn+ZcgiG6kCvoMXzczUz3jzyk96Uz6U2LIuZb+bFaCasMYyka2fpSndMQ2SxpmHbVSe2AvhBVMLhM29LOcio41D",
	"keysetInfo": {
		"primaryKeyId": 2596996162,
		"keyInfo": [
			{
				"typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
				"status": "ENABLED",
				"keyId": 2596996162,
				"outputPrefixType": "RAW"
			}
		]
	}
}
```

---

In (2), you are embedding the HMAC key *INTO* an HSM.  When you then need to access the secret, you ask the HSM to generate an HMAC for the AWS v4 signing process.   At no time does the client ever see the secret after it is embedded: the actual HMAC is done within the HSM. 

Once the key is embedded into an HSM, you can access it to sign, verify, etc but the key is ever exposed

```bash
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
	Secret Key Object; unknown key algorithm 43
	label:      HMACKey
	ID:         0100
	Usage:      verify
	Access:     sensitive
```

---

The big advantage of (2) is clear, the HSM owns the key and is not exportable:  nobody will see the raw key once thats done but yet you can use it to create an AWS s4 sign.


### AWS v4 Signing Protocol

The [AWS S4 Signing](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html) protocol uses the AWS Secret to create an HMAC signature by first adding a small prefix to the key

- ![images/sign_protocol.png](images/sign_protocol.png)

The implementations for the golang aws signer is here

- [github.com/aws/aws-sdk-go-v2/aws/signer/v4](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws/signer/v4#Signer)

This repo provides an AWS Credential and Signerv4 which is intended  to be used standalone

#### References

Some references for TINK and PKCS11:

- [Go PKCS11 Samples](https://github.com/salrashid123/go_pkcs11)
- [Importing external HMAC as TINK EncryptedKeySet](https://github.com/salrashid123/tink_samples/tree/main/external_hmac)


## TINK

To use TINK, we will assume you are a GCP customer with access to GCP KMS and want to access AWS via v4 Signing

First create a KMS keychain,key for Symmetric Encryption:

```bash
export PROJECT_ID=`gcloud config get-value core/project`
export PROJECT_NUMBER=`gcloud projects describe $PROJECT_ID --format='value(projectNumber)'`
export LOCATION=us-central1
export USER=`gcloud config get-value core/account`

# create keyring
gcloud kms keyrings create mykeyring --location $LOCATION

# create key
gcloud kms keys create key1 --keyring=mykeyring --purpose=encryption --location=$LOCATION

gcloud kms keys add-iam-policy-binding key1 \
    --keyring mykeyring \
    --location $LOCATION \
    --member user:$USER \
    --role roles/cloudkms.cryptoKeyDecrypter
```

Now create an EncryptedKeySet with Tink, then read in that KeySet and make Tink generate an HMAC signature:

```bash
export AWS_ACCESS_KEY_ID=AKIAUH3H6EGKERNFQLHJ
export AWS_SECRET_ACCESS_KEY=YRJ86SK5qTOZQzZTI1u-redacted

$ go run main.go --mode=tink \ \
  --keyURI "projects/$PROJECT_ID/locations/$LOCATION/keyRings/mykeyring/cryptoKeys/key1" \
  --awsRegion=us-east-2 -accessKeyID $AWS_ACCESS_KEY_ID \
  -secretAccessKey $AWS_SECRET_ACCESS_KEY

		2021/06/02 17:50:44    Create tink subtle.HMAC using secret
		2021/06/02 17:50:44    Tink Keyset:
		{
			"encryptedKeyset": "CiUAmT+VVfqKvEJIXDR1j+kuMjx1fatYYcFmxmrPjtPMhD+p+/E8EqUBACsKZVKCnrihcBHGUoD2ql1CqLsMVzM2MnZkYrKalNdhxB7vUs3y3CScnnsdH+80cTSiVr8ybugaG7c4LKMDw4dB06ox8TS1YbB/hL5+W3IX2yOWPqyFN/t/RVe2QyjGQr7rPqQGM0gOJHDEyTdMX8a9YzG6D7sVM15QQmQtLwKkXNYWr2c0O8iRNRiBcV0ekFwouenMj7+VseyeN0m/dyHNM610",
			"keysetInfo": {
				"primaryKeyId": 2596996162,
				"keyInfo": [
					{
						"typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
						"status": "ENABLED",
						"keyId": 2596996162,
						"outputPrefixType": "RAW"
					}
				]
			}
		}
		2021/06/02 17:50:44     Constructing MAC with TINK
		2021/06/02 17:50:44     Signed RequestURI: 
		2021/06/02 17:50:44     STS Response:  
		<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
		<GetCallerIdentityResult>
			<Arn>arn:aws:iam::291738886548:user/svcacct1</Arn>
			<UserId>AIDAUH3H6EGKDO36JYJH3</UserId>
			<Account>291738886548</Account>
		</GetCallerIdentityResult>
		<ResponseMetadata>
			<RequestId>985a21aa-42b3-47af-ab12-9602de5f4a88</RequestId>
		</ResponseMetadata>
		</GetCallerIdentityResponse>
```

The relevant code that read in TINK is:

```golang

import (

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac/subtle"
	common_go_proto "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/tink"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"

	hmacsigner "github.com/salrashid123/hmacsigner"
	hmaccred "github.com/salrashid123/hmacsigner/credentials"
)

	// register the backend KMS, in this case its GCP
		gcpClient, err := gcpkms.NewClient("gcp-kms://")
		registry.RegisterKMSClient(gcpClient)

		backend, err := gcpClient.GetAEAD("gcp-kms://" + *keyURI)

	// read the KeySetJSON as 
		var prettyJSON bytes.Buffer
		error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")

	// create credentials
		cc, err = hmaccred.NewHMACCredential(&hmaccred.HMACCredentialConfig{
			TinkConfig: hmaccred.TinkConfig{
				KmsBackend: backend,
				JSONBytes:  prettyJSON.Bytes(),
			},
			AccessKeyID: *accessKeyID,
		})

	hs := hmacsigner.NewSigner()

	body := strings.NewReader("")
	sreq, err := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", body)

	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Sign the request
	hs.SignHTTP(ctx, *cc, sreq, payloadHash, "sts", "us-east-1", time.Now())

    // use signedURL
	sres, err := http.DefaultClient.Do(sreq)

```

---

## PKCS11

For PKCS, we will use [SoftHSM](https://github.com/opendnssec/SoftHSMv2) which supports the PKCS mechanism to use HMAC. You should be able to use other HSM like yubikey, etc but unfortunately, TPM's CLi i used for PKCS does not support HMAC imports:  see [Support TPM HMAC Import](https://github.com/tpm2-software/tpm2-pkcs11/issues/688).


Anyway, first install SoftHSM and confirm you have the library linked properly (i used linux)

```bash
$ ldd /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
	linux-vdso.so.1 (0x00007fff91bd7000)
	libcrypto.so.1.1 => /lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007f56ad1a1000)
	libstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f56acfd4000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f56ace0f000)
	libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f56acdf5000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f56acdef000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f56acdcd000)
	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f56acc87000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f56ad589000)
```

Now initialize the SoftHSM device:

```bash
edit aws_hmac/softhsm/softhsm.conf
# set directories.tokendir = /path/to/aws_hmac/softhsm/tokens

export SOFTHSM2_CONF=`pwd`/softhsm/softhsm.conf

# initialize softHSM and list supported mechanisms
rm -rf /tmp/tokens
mkdir /tmp/tokens
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin
pcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
```

At this point, we are ready to run the sample application which will

1. COnnect to the HSM
2. Embed the AccessKey into the HSM
3. Use the embedded HMAC key to create AWS V4 signature
4. Access AWS API

note, after step2, the AWS secret is embedded inside the HSM and can only be used to make HMAC signatures.

```bash
export AWS_ACCESS_KEY_ID=AKIAUH3H6EGKERNFQLHJ
export AWS_SECRET_ACCESS_KEY=YRJ86SK5qTOZQzZTI1u-redacted

go run main.go --mode=pkcs \
  --hsmLibrary /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  \
  --awsRegion=us-east-2 -accessKeyID $AWS_ACCESS_KEY_ID \
  -secretAccessKey $AWS_SECRET_ACCESS_KEY
```

The output of this will run `STS.GetCallerIdentity`

```log
$ go run main.go --mode=pkcs --hsmLibrary /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    --awsRegion=us-east-2 -accessKeyID $AWS_ACCESS_KEY_ID \
	-secretAccessKey $AWS_SECRET_ACCESS_KEY
	
		Using slot with index 0 (0x0)
		Token successfully initialized
		Using slot 0 with a present token (0x42f8fd2b)
		User PIN successfully initialized
		bash: pcs11-tool: command not found
		CryptokiVersion.Major 2
		2021/06/02 20:19:01 Created HMAC Key: 2
		2021/06/02 20:19:01     Signed RequestURI: 
		2021/06/02 20:19:01     STS Response:  
		<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
		<GetCallerIdentityResult>
			<Arn>arn:aws:iam::291738886548:user/svcacct1</Arn>
			<UserId>AIDAUH3H6EGKDO36JYJH3</UserId>
			<Account>291738886548</Account>
		</GetCallerIdentityResult>
		<ResponseMetadata>
			<RequestId>b273ed3f-279f-43f8-af07-e97a04d0a1ef</RequestId>
		</ResponseMetadata>
		</GetCallerIdentityResponse>
```

The this code does is the magic:

```golang
    // crate a credential which will use the HSM embedded AWS Secret:
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

    // create a signer
	ctx := context.Background()
	hs := hmacsigner.NewSigner()

    // create the request
	body := strings.NewReader("")
	sreq, err := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", body)

	// sign the request
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hs.SignHTTP(ctx, *cc, sreq, payloadHash, "sts", "us-east-1", time.Now())

    // make the api call and print the result
	sres, err := http.DefaultClient.Do(sreq)
	sb, err := ioutil.ReadAll(sres.Body)
```

---

### Conclusion

THis is just a POC, caveat emptor