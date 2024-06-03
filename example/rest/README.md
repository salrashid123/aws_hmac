### AWS REST (GET/POST) API using Tink Signer and Credentials

The following uses the same setup as the `Tink` example folder but goes into the specific flow where the raw REST request is used to construct a GET and POST request to get a session token and to assume_role.


```log
$ go run main.go   --keyURI "projects/$PROJECT_ID/locations/$LOCATION/keyRings/mykeyring/cryptoKeys/key1"  \
   --awsRegion=us-east-1 -accessKeyID $AWS_ACCESS_KEY_ID   -secretAccessKey $AWS_SECRET_ACCESS_KEY 

2024/06/02 13:17:50    Initializing GCP KMS Encrypted Tink Keyset embedding AWS Secret
2024/06/02 13:17:50    Tink Keyset:
 {
	"encryptedKeyset": "CiQAK3qMTnhm4qjncnZHWomtc+UxuBYAGBrACAiFCJu1NKoKToYSpQEA19oTT/G79cTgmFD3R7m2zSFRIK2Znumn0G7GCVDRPzc5wN5/bQq65+UewHQub4mnJ4x/8Qt33V4O+l457Ic8+k2dEWHmfe5Eclw1Z2VD7rqstrjL59yCyd4KBqNyPuRMx4EY0RI8w5tPNf57KO4IfCvf8FuidBLNfUXo6cJ7wEuTc0LfenoEAEysbnweczgKeODSqM29hhNFcdZaEciOqR1/d90=",
	"keysetInfo": {
		"primaryKeyId": 3449280728,
		"keyInfo": [
			{
				"typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
				"status": "ENABLED",
				"keyId": 3449280728,
				"outputPrefixType": "RAW"
			}
		]
	}
}
-------------------------------- Calling HTTP GET on  GetCallerIdentity using Tink Signer
2024/06/02 13:17:51 GetCallerIdentityResponse UserID AIDAUH3H6EGKDO36JYJH3
-------------------------------- Calling HTTP POST on  GetCallerIdentity using Tink Signer
2024/06/02 13:17:51 GetCallerIdentityResponse UserID AIDAUH3H6EGKDO36JYJH3
-------------------------------- Calling  AWS SDK sts.GetCallerIdentity using Tink Signer
2024/06/02 13:17:51 STS Identity from API AIDAUH3H6EGKDO36JYJH3
-------------------------------- Calling HTTP GET on  AssumeRole using Tink Signer
2024/06/02 13:17:51 AssumeResponse ASIAUH3H6EGKASMDDGSR
-------------------------------- Calling s3 list buckets using StaticCredentials pupulated TinkSigner POST with  AssumeRole
2024/06/02 13:17:51 Listing Buckets using s3 client library
2024/06/02 13:17:51 -------------------------------- List buckets with NewStaticCredentials
2024/06/02 13:17:51 1
-------------------------------- Calling s3 list buckets using Tink Signer with AssumeRole
2024/06/02 13:17:51 1
-------------------------------- Calling s3 list buckets using Tink Signer with GetSessionTOken
2024/06/02 13:17:51 1

```