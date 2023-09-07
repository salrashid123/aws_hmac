## Usage TPM

In this variation, you will embed the AWS HMAC key into a Trusted Platform Module (TPM).  One embedded, the key will never leave the device can only be accessed to "sign" similar to the PKCS example above.  To note, the TPM itself has a PKCS interface but at the moment, it does not support  HMAC operations like import.  See [Issue #688](https://github.com/tpm2-software/tpm2-pkcs11/issues/688).  On the other end, go-tpm does not support pretty much any hmac operations: [Issue 249](https://github.com/google/go-tpm/issues/249)


also see [awsv4signer: aws-sdk-go pluggable request signer](https://github.com/psanford/awsv4signer)

Usage:

-  Create a VM with a vTPM anywhere

import your aws secret using `go-tpm-tools` or or via `tpm2_tools`.  You can also securely transfer/duplicate an HMAC key from one TPM to another.  For that flow, see [Duplicate an externally loaded HMAC key](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate#duplicate-an-externally-loaded-hmac-key).

For this tutorial, we will just do a plain import

#### Import HMAC key using tpm2_tools

If you installed `tpm2_tools`, then you can either directly import a key or do a secure sealed duplication (see [tpm2_duplicate](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate))

The following does a direct import

```bash
export AWS_SECRET_ACCESS_KEY="change this password to a secret"
export plain="foo"

echo -n $AWS_SECRET_ACCESS_KEY > hmac.key
hexkey=$(xxd -p -c 256 < hmac.key)
echo $hexkey
echo -n $plain > data.in

openssl dgst -sha256 -mac hmac -macopt hexkey:$hexkey data.in
 
### create primary object on owner auith
tpm2 createprimary -Q -G rsa -g sha256 -C o -c primary.ctx
tpm2 import -C primary.ctx -G hmac -i hmac.key -u hmac.pub -r hmac.priv
tpm2 load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx

# evict it to handle 0x81008001
tpm2_evictcontrol -C o -c hmac.ctx 0x81008001 
# to remove the persistent handle handle
##  tpm2_evictcontrol -C o -c 0x81008001

echo -n $plain | tpm2_hmac -g sha256 -c 0x81008001 | xxd -p -c 256

### after a system reboot, reacquire use the persistent handle or reload the primary key tree
### with persistent handle
echo -n $plain | tpm2_hmac -g sha256 -c 0x81008001 | xxd -p -c 256

### with files
tpm2 createprimary -Q -G rsa -g sha256 -C o -c primary.ctx
tpm2 load -C primary.ctx -u hmac.pub -r hmac.priv -c hmac.ctx
echo -n $plain | tpm2_hmac -g sha256 -c hmac.ctx | xxd -p -c 256
```

Also see [Importing External HMAC and performing HMAC Signature](https://github.com/salrashid123/tpm2/tree/master/hmac_import))

#### Import HMAC key using go-tpm-tools

One you installed go, just git clone this repo, export the env-vars and run

```bash
cd example/tpm

go run main.go     --awsRegion=us-east-1 -accessKeyID $AWS_ACCESS_KEY_ID   \
       -secretAccessKey $AWS_SECRET_ACCESS_KEY --persistentHandle=0x81008001 --flush=all  --evict

2023/09/07 01:44:54 Using Default AWS v4Signer and StaticCredentials to make REST GET call to GetCallerIdentity
2023/09/07 01:44:55    Response using AWS STS NewStaticCredentials and Standard v4.Singer 
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::291738886548:user/svcacct1</Arn>
    <UserId>AIDAUH3H6EGKDO36JYJH3</UserId>
    <Account>291738886548</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>757527fb-c90c-4f14-9a6e-8555c924ab25</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>
-------------------------------- Calling HTTP POST on  GetCallerIdentity using Vault Signer
2023/09/07 01:44:55 GetCallerIdentityResponse UserID AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with SessionToken SDK
2023/09/07 01:44:55 STS Identity from API AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with AssumeRole SDK
2023/09/07 01:44:55 Assumed role ARN: arn:aws:sts::291738886548:assumed-role/gcpsts/mysession
```

What the script above does is 

1. opens tpm
2. creates a primary tpm context
3. creates a tpm public and private sections for HMAC
4. set the 'sensitive' part of the private key to the raw AWS secret
5. imports the public hmac key to the tpm
6. writes the _handle_ to that hmac to a persistent handle (you can also write to files once ([go-tpm-tools issue#349](https://github.com/google/go-tpm-tools/issues/349) is ready)).

After the key is embedded to the persistent handle, you can reuse that between reboots (no need to reimport the raw key)

Note, this example does an import of a key every time...you can ofcorse stop do the import and just use the snippet to sign repeatedly (since the handle is persisted)



* Note, the key we generate has the following attributes

```bash
# tpm2_readpublic -c 0x81010002

name: 000b8fb81fa736a1cc6aae780f7ff5d32d6efc3b495ce1854af8aac9dc56dec287ee
qualified name: 000b23eba35005caaacdfa30defedc83a9c4986ed43be8728d544cbb93223d5b8045
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|userwithauth|sign
  raw: 0x40052
type:
  value: keyedhash
  raw: 0x8
algorithm: 
  value: hmac
  raw: 0x5
hash-alg:
  value: sha256
  raw: 0xb
keyedhash: 3d2733a76ef6723e5ddb7e1ab88eab0c5e9b2728606756334cc9639570b26cea

```



