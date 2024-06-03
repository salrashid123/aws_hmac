
## Usage TINK

To use TINK, we will assume you are a GCP customer with access to GCP KMS and want to access AWS via v4 Signing


First create a KMS keychain,key for Symmetric Encryption:

### Create Keyset:

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

Now create an EncryptedKeySet with Tink

```bash
export AWS_ACCESS_KEY_ID=AKIAUH3H6EGKERNFQLHJ
export AWS_SECRET_ACCESS_KEY=YRJ86SK5qTOZQzZTI1u-redacted

$ go run create/main.go   \
   --keyURI "projects/$PROJECT_ID/locations/$LOCATION/keyRings/mykeyring/cryptoKeys/key1" \
    -accessKeyID $AWS_ACCESS_KEY_ID   -secretAccessKey $AWS_SECRET_ACCESS_KEY 


$ cat key.json 
{
	"encryptedKeyset": "CiQAK3qMTvWOyFMfxuwp1F51gsw2IhKL+Ik3LbpGLh4kGnxD2M0SpQEA19oTT/8fQWj1EatySJyPea+B8BVmsfGL3hZaccIFRU4QsSAA9AVpqmQLa0TNr8MObU0gu6jG0AfgHEk4LKzQL8T3yAcdRpMxD2JBCB95k4y0rmc7FRKA1VLFoUNPMLDT4qfqxnQBOo5U+o94UUY+iD3hKTA4oc79BhSwP7rF9VxNkc00fLZuWO3nlYM7UbtlwKYCfTpdlEr32WRzCVRvir8g+UU=",
	"keysetInfo": {
		"primaryKeyId": 1541495373,
		"keyInfo": [
			{
				"typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
				"status": "ENABLED",
				"keyId": 1541495373,
				"outputPrefixType": "RAW"
			}
		]
	}
}

```

### Run AWS Client

```bash
go run load/main.go --in key.json --keyURI "projects/$PROJECT_ID/locations/$LOCATION/keyRings/mykeyring/cryptoKeys/key1"  \
     --accessKeyID=$AWS_ACCESS_KEY_ID --roleARN="arn:aws:iam::291738886548:role/gcpsts"

-------------------------------- Calling HTTP POST on  GetCallerIdentity using Tink Signer
GetCallerIdentityResponse UserID AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with SessionToken SDK
STS Identity from API AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with AssumeRole SDK
Assumed role ARN: arn:aws:sts::291738886548:assumed-role/gcpsts/mysession
```

also see: [Import and use an external HMAC Key as KMS EncryptedKeySet](https://github.com/salrashid123/tink_samples/tree/main/external_hmac)
