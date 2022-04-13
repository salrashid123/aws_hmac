module main

go 1.15

require (
	github.com/aws/aws-sdk-go v1.37.0
	github.com/golang/protobuf v1.5.2
	github.com/google/go-tpm v0.3.3
	github.com/google/go-tpm-tools v0.3.7
	github.com/google/tink/go v1.6.1
	github.com/googleapis/gax-go/v2 v2.0.5 // indirect
	github.com/miekg/pkcs11 v1.1.1
	github.com/salrashid123/aws_hmac/aws v0.0.0-20220413155232-4a52cc2d9305
	github.com/salrashid123/aws_hmac/aws/credentials v0.0.0-20220413155232-4a52cc2d9305
// github.com/salrashid123/aws_hmac/aws v0.0.0
// github.com/salrashid123/aws_hmac/aws/credentials v0.0.0
// github.com/salrashid123/aws_hmac/aws/internal v0.0.0 // indirect

)

// replace (
// 	github.com/salrashid123/aws_hmac/aws => ./aws
// 	github.com/salrashid123/aws_hmac/aws/credentials => ./aws/credentials
// 	github.com/salrashid123/aws_hmac/aws/internal => ./aws/internal
// )
