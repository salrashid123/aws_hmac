## AWS v4 Signer for embedding Access Secrets to PKCS11, Vault and Trusted Platform Module (TPM)

Sample procedure to encrypt AWS Access [Secret Access Key](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys) using [GCP Tink](https://developers.google.com/tink/how-tink-works) and a way to embed the the Key into an HSM device supporting [PKCS #11](https://en.wikipedia.org/wiki/PKCS_11), [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module) and [Hashicorp Vault](https://www.vaultproject.io/)

AWS secret key and ID can be thought of as a username/password and should be carefully managed, rotated, secured as described in [Best practices for managing AWS access keys](https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html).   However, if you need to invoke AWS from remote systems which do not provide ambient federation (eg on [GCP using OIDC tokens](https://github.com/salrashid123/awscompat)), then you must either utilize an AWS credentials file or set them dynamically as an environment variable.  

This repo provides three ways to protect the aws secret:

1. Wrap the secret using `KMS` and access it via `TINK`. 
  * `"github.com/salrashid123/aws_hmac/tink"`

2. Embed the secret into an `HSM` an access it via `PKCS11` 
  * `"github.com/salrashid123/aws_hmac/pkcs"`

3. Embed the secret into an `TPM` an access it via `go-tpm`  
  * `"github.com/salrashid123/aws_hmac/tpm"`

4. Embed the secret into an `Vault` an access it via `Vault` APIs 
  * `"github.com/salrashid123/aws_hmac/vault"`

>> NOTE: This code is NOT Supported by Google; its just a POC. caveat emptor

>> Most of the code under the `credentials/` and `internal/` folder is taken from [https://github.com/aws/aws-sdk-go-v2/blob/main/aws/signer/v4/v4.go](https://github.com/aws/aws-sdk-go-v2/blob/main/aws/signer/v4/v4.go)

---

#### PKCS Usage Overview

With this, you are embedding the HMAC key *INTO* an HSM.  When you then need to access the secret, you ask the HSM to generate an HMAC for the AWS v4 signing process.   At no time does the client ever see the secret after it is embedded: the actual HMAC is done within the HSM. 

Once the key is embedded into an HSM, you can access it to sign, verify, etc but the key is ever exposed

```bash
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
	Secret Key Object; unknown key algorithm 43
	label:      HMACKey
	ID:         0100
	Usage:      verify
	Access:     sensitive
```

The big advantage of (2) is clear, the HSM owns the key and is not exportable:  nobody will see the raw key once thats done but yet you can use it to create an AWS s4 sign.

#### TPM Usage Overview

Similar to PKCS but here you are not using the cumbersome overlay that PKCS requires and directly using the embedded token from a `Trusted Platform Module (TPM)`

#### Vault Usage Overview

For this, the AWS key is saved into HashiCorp Vaults [Transit Engine](https://www.vaultproject.io/api-docs/secret/transit).

While Vault already has a [secrets engine for AWS](https://www.vaultproject.io/docs/secrets/aws) which returns temp AWS Access keys to you, this instead embeds an AWS Secret *INTO* vault and use Vault's own [transit hmac](https://www.vaultproject.io/api-docs/secret/transit#generate-hmac) to sign the AWS request.


#### TINK Usage Overview

In (1) you are using KMS to encrypt the Secret and save it in encrypted format.  When you need to access the Secret to make it generate an AWS v4 signing request, the raw Secret is automatically decrypted by TINK using KMS and made to HMAC sign.  The user will never need to "see" the secret but it is true that the key gets decrypted locally...  You will also need to have access to KMS in the first place so this example is a bit convoluted.   Use this if you already have access to another cloud providers KMS (eg GCP KMS), then use that decrypt the Key and then make it sign though the utility of this mechanism is limited since the hmac key is decrypted locally ultimately.

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

---

## Usage PKCS11

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

# initialize softHSM and list supported mechanisms
cd example/pkcs
export SOFTHSM2_CONF=`pwd`/softhsm/softhsm.conf

rm -rf /tmp/tokens
mkdir /tmp/tokens
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
```

At this point, we are ready to run the sample application which will

1. Connect to the HSM
2. Embed the AccessKey into the HSM
3. Use the embedded HMAC key to create AWS V4 signature
4. Access AWS API

note, after step2, the AWS secret is embedded inside the HSM and can only be used to make HMAC signatures.

```bash
export AWS_ACCESS_KEY_ID=AKIAUH3H6EGKERNFQLHJ
export AWS_SECRET_ACCESS_KEY=YRJ86SK5qTOZQzZTI1u-redacted

go run main.go \
  --hsmLibrary /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  \
  --awsRegion=us-east-2 -accessKeyID $AWS_ACCESS_KEY_ID \
  -secretAccessKey $AWS_SECRET_ACCESS_KEY
```

The output of this will run `STS.GetCallerIdentity`

```log
$ go run main.go --hsmLibrary /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
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
	// $ touch empty.txt
    // $ sha256sum empty.txt 
    //   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.txt	
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hs.SignHTTP(ctx, *cc, sreq, payloadHash, "sts", "us-east-1", time.Now())

    // make the api call and print the result
	sres, err := http.DefaultClient.Do(sreq)
	sb, err := ioutil.ReadAll(sres.Body)
```


## Usage TPM

In this variation, you will embed the AWS HMAC key into a Trusted Platform Module (TPM).  One embedded, the key will never leave the device can only be accessed to "sign" similar to the PKCS example above.  To note, the TPM itself has a PKCS interface but at the moment, it does not support  HMAC operations like import.  See [Issue #688](https://github.com/tpm2-software/tpm2-pkcs11/issues/688).  On the other end, go-tpm does not support pretty much any hmac operations: [Issue 249](https://github.com/google/go-tpm/issues/249)


also see [awsv4signer: aws-sdk-go pluggable request signer](https://github.com/psanford/awsv4signer)

Usage:

-  Create a VM with a vTPM anywhere

import your aws secret using `go-tpm-tools` or or via `tpm2_tools`.  You can also securely transfer/duplicate an HMAC key from one TPM to another.  For that flow, see [Duplicate an externally loaded HMAC key](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate#duplicate-an-externally-loaded-hmac-key).

For this tutorial, we will just do a plain import

#### Import HMAC key using tpm2_tools

If you installed `tpm2_tools`, then you can either directly import a key or do a secure sealed duplication (see [tpm2_duplicate](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate))

The following does a direct import

```bash
export AWS_SECRET_ACCESS_KEY="change this password to a secret"
export plain="foo"

echo -n $AWS_SECRET_ACCESS_KEY > hmac.key
hexkey=$(xxd -p -c 256 < hmac.key)
echo $hexkey
echo -n $plain > data.in

openssl dgst -sha256 -mac hmac -macopt hexkey:$hexkey data.in
 
### create primary object on owner auith
tpm2 createprimary -Q -G rsa -g sha256 -C o -c primary.ctx
tpm2 import -C primary.ctx -G hmac -i hmac.key -u hmac.pub -r hmac.priv
tpm2 load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx

# evict it to handle 0x81008001
tpm2_evictcontrol -C o -c hmac.ctx 0x81008001 
# to remove the persistent handle handle
##  tpm2_evictcontrol -C o -c 0x81008001

echo -n $plain | tpm2_hmac -g sha256 -c 0x81008001 | xxd -p -c 256

### after a system reboot, reacquire use the persistent handle or reload the primary key tree
### with persistent handle
echo -n $plain | tpm2_hmac -g sha256 -c 0x81008001 | xxd -p -c 256

### with files
tpm2 createprimary -Q -G rsa -g sha256 -C o -c primary.ctx
tpm2 load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx
echo -n $plain | tpm2_hmac -g sha256 -c hmac.ctx | xxd -p -c 256
```

Also see [Importing External HMAC and performing HMAC Signature](https://github.com/salrashid123/tpm2/tree/master/hmac_import))

#### Import HMAC key using go-tpm-tools

One you installed go, just git clone this repo, export the env-vars and run

```bash
cd example/tpm
go run main.go \
    --awsRegion=us-east-2 -accessKeyID $AWS_ACCESS_KEY_ID \
	-secretAccessKey $AWS_SECRET_ACCESS_KEY --persistentHandle=0x81008001 --flush=all  --evict
```

What the script above does is 

1. opens tpm
2. creates a primary tpm context
3. creates a tpm public and private sections for HMAC
4. set the 'sensitive' part of the private key to the raw AWS secret
5. imports the public hmac key to the tpm
6. writes the _handle_ to that hmac to a persistent handle (you can also write to files once ([go-tpm-tools issue#349](https://github.com/google/go-tpm-tools/issues/349) is ready)).

After the key is embedded to the persistent handle, you can reuse that between reboots (no need to reimport the raw key)

Note, this example does an import of a key every time...you can ofcorse stop do the import and just use the snippet to sign repeatedly (since the handle is persisted)

this bit bootstraps the tpm and the file handle:

```golang
		cc, err = hmaccred.NewHMACCredential(&hmaccred.HMACCredentialConfig{
			TPMConfig: hmaccred.TPMConfig{
			TPMDevice: rwc,
			TpmHandle: tpmutil.Handle(*persistentHandle),
			},
			AccessKeyID: *accessKeyID,
		})
```

```log
$ go run main.go   \
    --awsRegion=us-east-2 -accessKeyID $AWS_ACCESS_KEY_ID \
	-secretAccessKey $AWS_SECRET_ACCESS_KEY \
	--persistentHandle=0x81008001 --flush=all  --evict

		2021/06/10 13:55:51 Using  Standard AWS v4Signer
		2021/06/10 13:55:52    Response using AWS STS NewStaticCredentials and Standard v4.Singer 
		<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
		<GetCallerIdentityResult>
			<Arn>arn:aws:iam::291738886548:user/svcacct1</Arn>
			<UserId>AIDAUH3H6EGKDO36JYJH3</UserId>
			<Account>291738886548</Account>
		</GetCallerIdentityResult>
		<ResponseMetadata>
			<RequestId>8bab0855-1536-4689-854a-10fe2fdd9500</RequestId>
		</ResponseMetadata>
		</GetCallerIdentityResponse>

		2021/06/10 13:55:52     Signed RequestURI: 
		2021/06/10 13:55:52     STS Response:  
		<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
		<GetCallerIdentityResult>
			<Arn>arn:aws:iam::291738886548:user/svcacct1</Arn>
			<UserId>AIDAUH3H6EGKDO36JYJH3</UserId>
			<Account>291738886548</Account>
		</GetCallerIdentityResult>
		<ResponseMetadata>
			<RequestId>fe67e9dd-1d58-4ace-9678-3021fd6e90eb</RequestId>
		</ResponseMetadata>
		</GetCallerIdentityResponse>
```

* Note, the key we generate has the following attributes

```bash
# tpm2_readpublic -c 0x81010002

name: 000b8fb81fa736a1cc6aae780f7ff5d32d6efc3b495ce1854af8aac9dc56dec287ee
qualified name: 000b23eba35005caaacdfa30defedc83a9c4986ed43be8728d544cbb93223d5b8045
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|userwithauth|sign
  raw: 0x40052
type:
  value: keyedhash
  raw: 0x8
algorithm: 
  value: hmac
  raw: 0x5
hash-alg:
  value: sha256
  raw: 0xb
keyedhash: 3d2733a76ef6723e5ddb7e1ab88eab0c5e9b2728606756334cc9639570b26cea

```

Anyway this is a POC on using TPM embedded AWS keys. 


## Usage TINK

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

$ go run main.go \
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

	hmaccred "github.com/salrashid123/aws_hmac/tink"
	hmacsigner "github.com/salrashid123/aws_hmac/tink/v4"	
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


## Usage Hashicorp Vault

In this variation, you will embed the `AWS HMAC` key into a Vault's [Transit Engine](https://www.vaultproject.io/api-docs/secret/transit)

Vault already has a [secrets engine for AWS](https://www.vaultproject.io/docs/secrets/aws) which returns temp AWS Access keys to you.

However, in this we are doing something different:  we are going to embed an AWS Secret *INTO* vault and use Vault's own [transit hmac](https://www.vaultproject.io/api-docs/secret/transit#generate-hmac) to sign the AWS request

Usage:

```bash
# add to /etc/hosts
#    127.0.0.1 vault.domain.com

# start vault
cd example/vault/vault_resources
vault server -config=server.conf 


# new window
export VAULT_ADDR='https://vault.domain.com:8200'
export VAULT_CACERT=/full/path/to/aws_hmac/example/vault/vault_resources/ca.pem
vault  operator init
# note down the UNSEAL_KEYS and the INITIAL_ROOT_TOKEN

## unseal vault
vault  operator unseal $UNSEAL_KEYS_N

export VAULT_TOKEN=$INITIAL_ROOT_TOKEN
vault secrets enable transit

## Create a temp transit key


export AWS_ACCESS_KEY_ID=AKIAUH3H6EGKF4ZY5GGQ
export AWS_SECRET_ACCESS_KEY=HMrL6cNwJCNQzRX8oN-redacted

## this is critical...append AWS4 to the secret_access_key and use that as the hmac key to import
export IMPORT_AWS_SECRET_ACCESS_KEY=`echo -n "AWS4$AWS_SECRET_ACCESS_KEY" | base64`
echo $IMPORT_AWS_SECRET_ACCESS_KEY
```

Edit `key_backup.json` and specify the `IMPORT_AWS_SECRET_ACCESS_KEY` as the `hmac_key` value

```json
"hmac_key": "QVdTNEhNckw2Y053SkNOUXpSWDhvTjNtbm8vamlLT-redacted",
```

Now import the key into vault

```bash
export BACKUP_B64="$(cat key_backup.json | base64)"
vault write transit/restore/aws-key-1 backup="${BACKUP_B64}"
vault read transit/keys/aws-key-1

# check hmac works
echo -n "foo" | base64 | vault write transit/hmac/aws-key-1/sha2-256  input=-
```

Create a vault policy to test the signer

```bash
vault policy write token-policy  token_policy.hcl
vault policy write secrets-policy  secrets_policy.hcl

# create a token with those policies (VAULT_TOKEN_FROM_POLICY)
vault token create -policy=token-policy -policy=secrets-policy

## export the token
export VAULT_TOKEN_FROM_POLICY=s.Upzqu1UwJ-redacted
```

Now run the vault client application

```log
$ go run main.go  --awsRegion=us-east-1 \
   -accessKeyID $AWS_ACCESS_KEY_ID \
   -secretAccessKey $AWS_SECRET_ACCESS_KEY \
   -vaultToken=$VAULT_TOKEN_FROM_POLICY
```

---


THis is just a POC, caveat emptor
