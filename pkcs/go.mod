module github.com/salrashid123/aws_hmac/pkcs

go 1.21

require (
	github.com/aws/aws-sdk-go v1.45.3
	github.com/gorilla/schema v1.2.0
	github.com/salrashid123/aws_hmac/pkcs/signer v0.0.0-20230907025004-21e21d0dabc4
	github.com/salrashid123/aws_hmac/pkcs/signer/v4 v4.0.0-20230907030921-a484b3780719
	github.com/salrashid123/aws_hmac/stsschema v0.0.0-20230907030921-a484b3780719
	// github.com/salrashid123/aws_hmac/pkcs/signer/v4 v4.0.0
	// github.com/salrashid123/aws_hmac/stsschema v0.0.0-00010101000000-000000000000
)

require (
	github.com/aws/smithy-go v1.14.2 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
)

replace (
	// github.com/salrashid123/aws_hmac/pkcs/signer => ./signer
	// github.com/salrashid123/aws_hmac/pkcs/signer/v4 => ./signer/v4
	// github.com/salrashid123/aws_hmac/stsschema => ../stsschema
)