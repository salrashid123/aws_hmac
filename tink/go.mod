module github.com/salrashid123/aws_hmac/tink

go 1.21

require (
	github.com/aws/aws-sdk-go v1.45.3
	github.com/gorilla/schema v1.2.0
	github.com/salrashid123/aws_hmac/stsschema v0.0.0-00010101000000-000000000000
	github.com/salrashid123/aws_hmac/tink/signer v0.0.0
	github.com/salrashid123/aws_hmac/tink/signer/v4 v4.0.0
)

require (
	github.com/aws/smithy-go v1.14.2 // indirect
	github.com/google/tink/go v1.7.0 // indirect
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace (
	github.com/salrashid123/aws_hmac/stsschema => ../stsschema
	github.com/salrashid123/aws_hmac/tink/signer => ./signer
	github.com/salrashid123/aws_hmac/tink/signer/v4 => ./signer/v4
)
