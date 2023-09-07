module main

go 1.21

require (
	github.com/aws/aws-sdk-go v1.45.4
	github.com/gorilla/schema v1.2.0
	github.com/miekg/pkcs11 v1.1.1
	github.com/salrashid123/aws_hmac/pkcs v0.0.0-00010101000000-000000000000
	github.com/salrashid123/aws_hmac/pkcs/signer v0.0.0
	github.com/salrashid123/aws_hmac/pkcs/signer/v4 v4.0.0
	github.com/salrashid123/aws_hmac/stsschema v0.0.0

)

require (
	github.com/aws/smithy-go v1.14.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
)

replace (
	github.com/salrashid123/aws_hmac/pkcs => ../../pkcs
	github.com/salrashid123/aws_hmac/pkcs/signer => ../../pkcs/signer
	github.com/salrashid123/aws_hmac/pkcs/signer/v4 => ../../pkcs/signer/v4
	github.com/salrashid123/aws_hmac/stsschema => ../../stsschema
)
