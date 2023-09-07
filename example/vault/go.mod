module main

go 1.21

require github.com/aws/aws-sdk-go v1.45.3

require (
	github.com/gorilla/schema v1.2.0
	github.com/salrashid123/aws_hmac/stsschema v0.0.0-20230907030222-03be18507813
	github.com/salrashid123/aws_hmac/vault v0.0.0-20230907030222-03be18507813
	github.com/salrashid123/aws_hmac/vault/signer v0.0.0-20230907025004-21e21d0dabc4
	github.com/salrashid123/aws_hmac/vault/signer/v4 v4.0.0-20230907024207-0899a3ac266a

	// github.com/salrashid123/aws_hmac/stsschema v0.0.0
	// github.com/salrashid123/aws_hmac/vault v0.0.0-00010101000000-000000000000
	// github.com/salrashid123/aws_hmac/vault/signer v0.0.0
	// github.com/salrashid123/aws_hmac/vault/signer/v4 v4.0.0
)

require (
	github.com/aws/smithy-go v1.14.2 // indirect
	github.com/cenkalti/backoff/v3 v3.0.0 // indirect
	github.com/go-jose/go-jose/v3 v3.0.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.6 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.6 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/vault/api v1.10.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	golang.org/x/time v0.0.0-20200416051211-89c76fbcd5d1 // indirect
)

replace (
	// github.com/salrashid123/aws_hmac/stsschema => ../../stsschema
	// github.com/salrashid123/aws_hmac/vault => ../../vault
	// github.com/salrashid123/aws_hmac/vault/signer => ../../vault/signer
	// github.com/salrashid123/aws_hmac/vault/signer/v4 => ../../vault/signer/v4
)
