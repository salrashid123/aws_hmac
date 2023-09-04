module main

go 1.20

require (
	github.com/aws/aws-sdk-go v1.43.9
	github.com/miekg/pkcs11 v1.1.1
	github.com/salrashid123/aws_hmac/pkcs v0.0.0
	github.com/salrashid123/aws_hmac/pkcs/credentials v0.0.0
)

require (
	github.com/aws/smithy-go v1.14.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
)

replace (
	github.com/salrashid123/aws_hmac/pkcs => ../../pkcs
	github.com/salrashid123/aws_hmac/pkcs/credentials => ../../pkcs/credentials
)
