module main

go 1.22.0

toolchain go1.22.2

require (
	github.com/aws/aws-sdk-go v1.55.6
	github.com/aws/aws-sdk-go-v2 v1.36.3
	github.com/aws/aws-sdk-go-v2/config v1.29.9
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.17
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20250318194951-cba49fbf70fa
	github.com/google/go-tpm v0.9.1-0.20240514145214-58e3e47cd434
	github.com/google/go-tpm-tools v0.4.4
	github.com/gorilla/schema v1.3.0
	github.com/salrashid123/aws_hmac/stsschema v0.0.0
	github.com/salrashid123/aws_hmac/tpm v0.0.0
// github.com/salrashid123/aws_hmac/tpm/signer v0.0.0
// github.com/salrashid123/aws_hmac/tpm/signer/v4 v4.0.0
)

require (
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.17.62 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.29.1 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	// github.com/salrashid123/aws_hmac/stsschema v0.0.0-20240603113244-90c0fa02c6a3 // indirect
	// github.com/salrashid123/aws_hmac/tpm v0.0.0-20240603121259-f254d7e77c0c // indirect
	// github.com/salrashid123/aws_hmac/tpm/signer v0.0.0-20240603115806-b0a186b8b4b4 // indirect
	// github.com/salrashid123/aws_hmac/tpm/signer/v4 v4.0.0-20240603113244-90c0fa02c6a3 // indirect
	golang.org/x/crypto v0.19.0 // indirect
)

replace (
	github.com/salrashid123/aws_hmac/stsschema => ../../stsschema
	github.com/salrashid123/aws_hmac/tpm => ../../tpm
// github.com/salrashid123/aws_hmac/tpm/signer => ../../tpm/signer
// github.com/salrashid123/aws_hmac/tpm/signer/v4 => ../../tpm/signer/v4
)
