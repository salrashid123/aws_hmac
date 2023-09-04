module main

go 1.20

require (
	github.com/aws/aws-sdk-go v1.43.9
	github.com/google/go-tpm v0.9.0
	github.com/google/go-tpm-tools v0.4.0
	github.com/salrashid123/aws_hmac/tpm v0.0.0
	github.com/salrashid123/aws_hmac/tpm/v4 v4.0.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-sev-guest v0.6.1 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/pborman/uuid v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/sys v0.8.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

require (
	github.com/aws/smithy-go v1.14.2 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	golang.org/x/crypto v0.6.0 // indirect
)

replace (
	github.com/salrashid123/aws_hmac/tpm => ../../tpm
	github.com/salrashid123/aws_hmac/tpm/v4 => ../../tpm/v4
)
