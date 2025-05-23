module main

go 1.21

require (
	github.com/aws/aws-sdk-go-v2 v1.27.0
	github.com/aws/aws-sdk-go-v2/config v1.27.16
	github.com/aws/aws-sdk-go-v2/service/sts v1.28.10
	github.com/gorilla/schema v1.2.0
	github.com/miekg/pkcs11 v1.1.1
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.17.16 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.24.3 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	github.com/salrashid123/aws_hmac/pkcs v0.0.0-20250324113806-6d5ca0008d64 // indirect
	github.com/salrashid123/aws_hmac/stsschema v0.0.0-20250324113806-6d5ca0008d64 // indirect
)

// replace (
// 	github.com/salrashid123/aws_hmac/pkcs => ../../pkcs
// 	github.com/salrashid123/aws_hmac/stsschema => ../../stsschema
// )
