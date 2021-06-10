module main

go 1.15

require (
	github.com/aws/aws-sdk-go v1.36.29
	github.com/aws/smithy-go v1.4.0 // indirect
	github.com/golang/protobuf v1.5.2
	github.com/google/tink/go v1.6.0
	github.com/miekg/pkcs11 v1.0.3
	github.com/salrashid123/aws_hmac/aws v0.0.0
	github.com/salrashid123/aws_hmac/aws/credentials v0.0.0
	github.com/salrashid123/aws_hmac/aws/internal v0.0.0 // indirect
	golang.org/x/sys v0.0.0-20201207223542-d4d67f95c62d // indirect

	github.com/google/go-tpm v0.3.3-0.20210409082102-d3310770bfec
	github.com/google/go-tpm-tools v0.2.2-0.20210609182153-59d8543b236d

)

replace (
	github.com/salrashid123/aws_hmac/aws => ./aws
	github.com/salrashid123/aws_hmac/aws/credentials => ./aws/credentials
	github.com/salrashid123/aws_hmac/aws/internal => ./aws/internal
)
