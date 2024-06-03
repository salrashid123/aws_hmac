module github.com/salrashid123/aws_hmac/pkcs

go 1.21

require (
	github.com/aws/aws-sdk-go-v2/service/sts v1.28.10
	github.com/gorilla/schema v1.2.0
	github.com/salrashid123/aws_hmac/pkcs/signer v0.0.0
	github.com/salrashid123/aws_hmac/pkcs/signer/v4 v4.0.0
	github.com/salrashid123/aws_hmac/stsschema v0.0.0

)

require (
	github.com/aws/aws-sdk-go-v2 v1.27.0
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.9 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
)

replace (
	github.com/salrashid123/aws_hmac/pkcs/signer => ./signer
	github.com/salrashid123/aws_hmac/pkcs/signer/v4 => ./signer/v4
	github.com/salrashid123/aws_hmac/stsschema => ../stsschema
)
