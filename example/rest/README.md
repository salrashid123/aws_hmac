### AWS REST (GET/POST) API using Tink Signer and Credentials

The following uses the same setup as the `Tink` example folder but goes into the specific flow where the raw REST request is used to construct a GET and POST request to get a session token and to assume_role.


```log
$ go run main.go   --keyURI "projects/$PROJECT_ID/locations/$LOCATION/keyRings/mykeyring/cryptoKeys/key1"  \
   --awsRegion=us-east-1 -accessKeyID $AWS_ACCESS_KEY_ID   -secretAccessKey $AWS_SECRET_ACCESS_KEY 

2023/09/06 18:14:40 Using Default AWS v4Signer and StaticCredentials to make REST GET call to GetCallerIdentity
2023/09/06 18:14:40    Response using AWS STS NewStaticCredentials and Standard v4.Singer 
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::291738886548:user/svcacct1</Arn>
    <UserId>AIDAUH3H6EGKDO36JYJH3</UserId>
    <Account>291738886548</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>d8741953-c285-4ffd-a709-43bfdcd2f201</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>
2023/09/06 18:14:40    Initializing GCP KMS Encrypted Tink Keyset embedding AWS Secret
2023/09/06 18:14:40    Tink Keyset:
 {
	"encryptedKeyset": "CiQASRStDD6SygsG3EUEv1ELHpJmB9eqP1HNaZbijW0iWBa1LSwSpQEASMovZx4CtjMlXoVTDa/rTcEWLUKNsDMlThGMszbU87Qg1E1rOakKmwiwG8kXtt+hJ+3cdWh9CECrwoAwV+eiLwEhYv+MRToKwpM4H7k6Ne0NBCf9idGtiIQzhGQaQ/v+SZwo8HtgVz8zEby8aCZVmIazNQJ0Afl3ItO57z2sgkiSwrA9EBVAOD6EOk/JfEJO0quL0XIg7kF6gWSfl36UbaRW07o=",
	"keysetInfo": {
		"primaryKeyId": 3118633800,
		"keyInfo": [
			{
				"typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
				"status": "ENABLED",
				"keyId": 3118633800,
				"outputPrefixType": "RAW"
			}
		]
	}
}
-------------------------------- Calling HTTP GET on  GetCallerIdentity using Tink Signer
2023/09/06 18:14:40 GetCallerIdentityResponse UserID AIDAUH3H6EGKDO36JYJH3

-------------------------------- Calling HTTP POST on  GetCallerIdentity using Tink Signer
2023/09/06 18:14:40 GetCallerIdentityResponse UserID AIDAUH3H6EGKDO36JYJH3

-------------------------------- Calling  AWS SDK sts.GetCallerIdentity using Tink Signer
2023/09/06 18:14:40 STS Identity from API AIDAUH3H6EGKDO36JYJH3

-------------------------------- Calling HTTP GET on  AssumeRole using Tink Signer
2023/09/06 18:14:40 AssumeResponse ASIAUH3H6EGKJI4NP6V5

-------------------------------- Calling s3 list buckets using StaticCredentials pupulated TinkSigner POST with  AssumeRole
2023/09/06 18:14:40 Listing Buckets using s3 client library
2023/09/06 18:14:40 -------------------------------- List buckets with NewStaticCredentials
2023/09/06 18:14:40 [{
  CreationDate: 2020-05-30 03:02:12 +0000 UTC,
  Name: "mineral-minutia"
}]

-------------------------------- Calling s3 list buckets using Tink Signer with AssumeRole
2023/09/06 18:14:40 [{
  CreationDate: 2020-05-30 03:02:12 +0000 UTC,
  Name: "mineral-minutia"
}]

-------------------------------- Calling s3 list buckets using Tink Signer with GetSessionTOken
2023/09/06 18:14:40 [{
  CreationDate: 2020-05-30 03:02:12 +0000 UTC,
  Name: "mineral-minutia"
}]

-------------------------------- Calling ec2 list regions using Tink Signer with AssumeRole
2023/09/06 18:14:41 Region count 17
```