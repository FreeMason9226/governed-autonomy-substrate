# Vault policy for sandbox workers (matches VaultSecretProvider's KV v2 path layout).
path "gas/data/policies/*" {
  capabilities = ["read"]
}

path "gas/data/control-plane/*" {
  capabilities = ["deny"]
}
