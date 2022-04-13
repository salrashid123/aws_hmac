
path "auth/approle/role/observatory/secret-id" {
  capabilities = ["read", "create", "update", "list"]
}

path "transit/hmac/aws-key-1/sha2-256" {
  capabilities = ["update"]
}

