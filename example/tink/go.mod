module main

go 1.21

require (
	github.com/aws/aws-sdk-go v1.45.3
	github.com/golang/protobuf v1.5.3
	github.com/google/tink/go v1.7.0
	github.com/gorilla/schema v1.2.0
	github.com/salrashid123/aws_hmac/stsschema v0.0.0-20230907030921-a484b3780719
	github.com/salrashid123/aws_hmac/tink v0.0.0-20230907030222-03be18507813
	github.com/salrashid123/aws_hmac/tink/signer v0.0.0-20230907025004-21e21d0dabc4
	github.com/salrashid123/aws_hmac/tink/signer/v4 v4.0.0-20230907030921-a484b3780719
// github.com/salrashid123/aws_hmac/stsschema v0.0.0
// github.com/salrashid123/aws_hmac/tink v0.0.0-00010101000000-000000000000
// github.com/salrashid123/aws_hmac/tink/signer v0.0.0
// github.com/salrashid123/aws_hmac/tink/signer/v4 v4.0.0
)

require (
	cloud.google.com/go/compute v1.3.0 // indirect
	github.com/aws/smithy-go v1.14.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/googleapis/gax-go/v2 v2.1.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/oauth2 v0.0.0-20220223155221-ee480838109b // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	google.golang.org/api v0.70.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220218161850-94dd64e39d7c // indirect
	google.golang.org/grpc v1.44.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace (
	github.com/salrashid123/aws_hmac/stsschema => ../../stsschema
	github.com/salrashid123/aws_hmac/tink => ../../tink
	github.com/salrashid123/aws_hmac/tink/signer => ../../tink/signer
	github.com/salrashid123/aws_hmac/tink/signer/v4 => ../../tink/signer/v4
)
