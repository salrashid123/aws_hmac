
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

$ go run main.go   \
   --keyURI "projects/$PROJECT_ID/locations/$LOCATION/keyRings/mykeyring/cryptoKeys/key1" \
   --awsRegion=us-east-1 -accessKeyID $AWS_ACCESS_KEY_ID   -secretAccessKey $AWS_SECRET_ACCESS_KEY 

2023/09/06 18:06:11 Using Default AWS v4Signer and StaticCredentials to make REST GET call to GetCallerIdentity
2023/09/06 18:06:11    Response using AWS STS NewStaticCredentials and Standard v4.Singer 
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::291738886548:user/svcacct1</Arn>
    <UserId>AIDAUH3H6EGKDO36JYJH3</UserId>
    <Account>291738886548</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>b3d47e61-0953-4286-8257-ac8c782e0bd5</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>

2023/09/06 18:06:11    Initializing GCP KMS Encrypted Tink Keyset embedding AWS Secret
2023/09/06 18:06:12    Tink Keyset:
 {
	"encryptedKeyset": "CiQASRStDN8qoTkHO1NI1C5kS1E/g0bKRHZt8z43HM//St+sIHISpQEASMovZ7YafWaOTK9MlTyuBonbM0sGcL4wbPPa5w9wX9mX5jtNGAq/sUI0D6s1C5CQwseJSOwbJ343dQrI4Y9tWWvmrZ5LM9xcy1Md50GBoHBJGiJgKaFWlvT6ALArDuXtFc6s+W8bbrqSHmCa9GbgtGjS0Zo6huc8nFMrIC+v85TN4+DPyhLSctrIsW2HW7IDbw/8Ad0S1t3wKcQvwVw23k/LELs=",
	"keysetInfo": {
		"primaryKeyId": 488738866,
		"keyInfo": [
			{
				"typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
				"status": "ENABLED",
				"keyId": 488738866,
				"outputPrefixType": "RAW"
			}
		]
	}
}
-------------------------------- Calling HTTP POST on  GetCallerIdentity using Tink Signer
2023/09/06 18:06:12 GetCallerIdentityResponse UserID AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with SessionToken SDK
2023/09/06 18:06:12 STS Identity from API AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with AssumeRole SDK
2023/09/06 18:06:12 Assumed role ARN: arn:aws:sts::291738886548:assumed-role/gcpsts/mysession

```
