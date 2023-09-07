## Usage Hashicorp Vault

In this variation, you will embed the `AWS HMAC` key into a Vault's [Transit Engine](https://www.vaultproject.io/api-docs/secret/transit)

Vault already has a [secrets engine for AWS](https://www.vaultproject.io/docs/secrets/aws) which returns temp AWS Access keys to you.

However, in this we are doing something different:  we are going to embed an AWS Secret *INTO* vault and use Vault's own [transit hmac](https://www.vaultproject.io/api-docs/secret/transit#generate-hmac) to sign the AWS request

Usage:

```bash
# add to /etc/hosts
#    127.0.0.1 vault.domain.com

# start vault
cd example/vault/vault_resources
vault server -config=server.conf 


# new window
export VAULT_ADDR='https://vault.domain.com:8200'
export VAULT_CACERT=/full/path/to/aws_hmac/example/vault/vault_resources/ca.pem
vault  operator init
# note down the UNSEAL_KEYS and the INITIAL_ROOT_TOKEN

## unseal vault
vault  operator unseal $UNSEAL_KEYS_N

export VAULT_TOKEN=$INITIAL_ROOT_TOKEN
vault secrets enable transit

## Create a temp transit key


export AWS_ACCESS_KEY_ID=AKIAUH3H6EGKF4ZY5GGQ
export AWS_SECRET_ACCESS_KEY=HMrL6cNwJCNQzRX8oN-redacted

## this is critical...append AWS4 to the secret_access_key and use that as the hmac key to import
export IMPORT_AWS_SECRET_ACCESS_KEY=`echo -n "AWS4$AWS_SECRET_ACCESS_KEY" | base64`
echo $IMPORT_AWS_SECRET_ACCESS_KEY
```

Edit `key_backup.json` and specify the `IMPORT_AWS_SECRET_ACCESS_KEY` as the `hmac_key` value

```json
"hmac_key": "QVdTNEhNckw2Y053SkNOUXpSWDhvTjNtbm8vamlLT-redacted",
```

Now import the key into vault

```bash
export BACKUP_B64="$(cat key_backup.json | base64)"
vault write transit/restore/aws-key-1 backup="${BACKUP_B64}"
vault read transit/keys/aws-key-1

# check hmac works
echo -n "foo" | base64 | vault write transit/hmac/aws-key-1/sha2-256  input=-
```

Create a vault policy to test the signer

```bash
vault policy write token-policy  token_policy.hcl
vault policy write secrets-policy  secrets_policy.hcl

# create a token with those policies (VAULT_TOKEN_FROM_POLICY)
vault token create -policy=token-policy -policy=secrets-policy

## export the token
export VAULT_TOKEN_FROM_POLICY=s.Upzqu1UwJ-redacted
```

Now run the vault client application

```log
$ go run main.go  --awsRegion=us-east-1 \
   -accessKeyID $AWS_ACCESS_KEY_ID \
   -secretAccessKey $AWS_SECRET_ACCESS_KEY \
   -vaultToken=$VAULT_TOKEN_FROM_POLICY

2023/09/06 21:12:51 Using Default AWS v4Signer and StaticCredentials to make REST GET call to GetCallerIdentity
2023/09/06 21:12:51    Response using AWS STS NewStaticCredentials and Standard v4.Singer 
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::291738886548:user/svcacct1</Arn>
    <UserId>AIDAUH3H6EGKDO36JYJH3</UserId>
    <Account>291738886548</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>63fcc011-fad9-4494-959c-f033189274d7</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>
-------------------------------- Calling HTTP POST on  GetCallerIdentity using Vault Signer
2023/09/06 21:12:51 GetCallerIdentityResponse UserID AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with SessionToken SDK
2023/09/06 21:12:51 STS Identity from API AIDAUH3H6EGKDO36JYJH3
-------------------------------- GetCallerIdentity with AssumeRole SDK
2023/09/06 21:12:51 Assumed role ARN: arn:aws:sts::291738886548:assumed-role/gcpsts/mysession

```
