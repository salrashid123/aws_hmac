## Usage PKCS11

For PKCS, we will use [SoftHSM](https://github.com/opendnssec/SoftHSMv2) which supports the PKCS mechanism to use HMAC. You should be able to use other HSM like yubikey, etc but unfortunately, TPM's CLi i used for PKCS does not support HMAC imports:  see [Support TPM HMAC Import](https://github.com/tpm2-software/tpm2-pkcs11/issues/688).


Anyway, first install SoftHSM and confirm you have the library linked properly (i used linux)

```bash
$ ldd /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
	linux-vdso.so.1 (0x00007fff91bd7000)
	libcrypto.so.1.1 => /lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007f56ad1a1000)
	libstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f56acfd4000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f56ace0f000)
	libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f56acdf5000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f56acdef000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f56acdcd000)
	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f56acc87000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f56ad589000)
```

Now initialize the SoftHSM device:

```bash

# initialize softHSM and list supported mechanisms
cd example/pkcs
export SOFTHSM2_CONF=`pwd`/softhsm/softhsm.conf

rm -rf /tmp/tokens
mkdir /tmp/tokens
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
```

At this point, we are ready to run the sample application which will

1. Connect to the HSM
2. Embed the AccessKey into the HSM
3. Use the embedded HMAC key to create AWS V4 signature
4. Access AWS API

note, after step2, the AWS secret is embedded inside the HSM and can only be used to make HMAC signatures.


### Load key:

for step1 and 2, load the key to the HSM first

```bash
export AWS_ACCESS_KEY_ID=AKIAUH3H6EGKERNFQLHJ
export AWS_SECRET_ACCESS_KEY=YRJ86SK5qTOZQzZTI1u-redacted
```

```bash
$ go run create/main.go   --hsmLibrary /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
     -accessKeyID $AWS_ACCESS_KEY_ID   -secretAccessKey $AWS_SECRET_ACCESS_KEY

## optionally list the key
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
Using slot 0 with a present token (0x6a6ef465)
Secret Key Object; unknown key algorithm 43
  label:      HMACKey
  ID:         0100
  Usage:      sign, verify
  Access:     sensitive
```


### Use AWS SDK

Now run 

```golang

go run load/main.go --keyid=0100 --hsmLibrary /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  \
     --accessKeyID=$AWS_ACCESS_KEY_ID --roleARN="arn:aws:iam::291738886548:role/gcpsts"

-------------------------------- Calling HTTP POST on  GetCallerIdentity using Tink Signer
GetCallerIdentityResponse UserID AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with SessionToken SDK
STS Identity from API AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with AssumeRole SDK
Assumed role ARN: arn:aws:sts::291738886548:assumed-role/gcpsts/mysession

```