module main

go 1.15

require (
	github.com/aws/aws-sdk-go v1.36.29
	github.com/aws/aws-sdk-go-v2 v1.6.0 // indirect
	github.com/golang/protobuf v1.5.2
	github.com/google/tink/go v1.6.0
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/salrashid123/aws_hmac/aws v0.0.0
	github.com/salrashid123/aws_hmac/aws/credentials v0.0.0
	github.com/salrashid123/aws_hmac/aws/internal v0.0.0
)

replace (
	github.com/salrashid123/aws_hmac/aws => ./aws
	github.com/salrashid123/aws_hmac/aws/credentials => ./aws/credentials
	github.com/salrashid123/aws_hmac/aws/internal => ./aws/internal
)
