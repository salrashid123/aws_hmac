module github.com/salrashid123/aws_hmac/tpm

go 1.22

toolchain go1.22.2

require (
	github.com/aws/aws-sdk-go-v2 v1.27.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.28.10
	github.com/gorilla/schema v1.3.0
	github.com/salrashid123/aws_hmac/stsschema v0.0.0-20240603113244-90c0fa02c6a3
	github.com/salrashid123/aws_hmac/tpm/signer v0.0.0-20240603115806-b0a186b8b4b4
	github.com/salrashid123/aws_hmac/tpm/signer/v4 v4.0.0-20240603113244-90c0fa02c6a3
)

require (
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.9 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	github.com/google/go-tpm v0.9.1-0.20240514145214-58e3e47cd434 // indirect
	golang.org/x/sys v0.20.0 // indirect
)
