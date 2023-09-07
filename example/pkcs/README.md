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

```bash
export AWS_ACCESS_KEY_ID=AKIAUH3H6EGKERNFQLHJ
export AWS_SECRET_ACCESS_KEY=YRJ86SK5qTOZQzZTI1u-redacted
```

The output of this will run `STS.GetCallerIdentity`

```log
$ $ go run main.go   --hsmLibrary /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so   \

   --awsRegion=us-east-1 -accessKeyID $AWS_ACCESS_KEY_ID   -secretAccessKey $AWS_SECRET_ACCESS_KEY
2023/09/06 20:18:16 Using Default AWS v4Signer and StaticCredentials to make REST GET call to GetCallerIdentity
2023/09/06 20:18:16    Response using AWS STS NewStaticCredentials and Standard v4.Singer 
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::291738886548:user/svcacct1</Arn>
    <UserId>AIDAUH3H6EGKDO36JYJH3</UserId>
    <Account>291738886548</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>971cfd48-c993-497e-a08e-3bbee95274c4</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>
2023/09/06 20:18:16    Initializing PKCS Keyset embedding AWS Secret
CryptokiVersion.Major 2
2023/09/06 20:18:16 Created HMAC Key: 2
-------------------------------- Calling HTTP POST on  GetCallerIdentity using Tink Signer
2023/09/06 20:18:16 GetCallerIdentityResponse UserID AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with SessionToken SDK
2023/09/06 20:18:17 STS Identity from API AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with AssumeRole SDK
2023/09/06 20:18:17 Assumed role ARN: arn:aws:sts::291738886548:assumed-role/gcpsts/mysession
```

The specific part that initializes the signer and creds:

```golang
	pkcsSigner, err := hmacsigner.NewPKCSSigner(&hmacsigner.PKCSSignerConfig{
		PKCSConfig: hmacsigner.PKCSConfig{
			Library: "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
			Slot:    0,
			Label:   "HMACKey",
			PIN:     "mynewpin",
			Id:      id,
		},
		AccessKeyID: *accessKeyID,
	})


	hmacSigner := hmacsignerv4.NewSigner()

	sessionCredentials, err := hmaccred.NewAWSPKCSCredentials(hmaccred.PKCSProvider{
		GetSessionTokenInput: &stsschema.GetSessionTokenInput{
			DurationSeconds: aws.Int64(3600),
		},
		Version:    "2011-06-15",
		Region:     *awsRegion,
		PKCSSigner: pkcsSigner,
	})


	assumeRoleCredentials, err := hmaccred.NewAWSPKCSCredentials(hmaccred.PKCSProvider{
		AssumeRoleInput: &stsschema.AssumeRoleInput{
			RoleArn:         aws.String(*roleARN),
			RoleSessionName: aws.String(roleSessionName),
			DurationSeconds: aws.Int64(3600),
		},
		Version:    "2011-06-15",
		Region:     *awsRegion,
		PKCSSigner: pkcsSigner,
	})
```