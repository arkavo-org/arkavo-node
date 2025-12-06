# Contract Deployment Guide

Deploy Ink! smart contracts to Arkavo Node using `cargo-contract` CLI.

## Prerequisites

### Install cargo-contract

```bash
# Install cargo-contract v5.x+ (required for pallet-revive support)
cargo install cargo-contract --locked

# Verify installation
cargo contract --version
```

### Build Contracts

```bash
cd contracts
cargo contract build --manifest-path access_registry/Cargo.toml
cargo contract build --manifest-path attribute_store/Cargo.toml
cargo contract build --manifest-path policy_engine/Cargo.toml
cargo contract build --manifest-path payment_integration/Cargo.toml
cargo contract build --manifest-path user_registry/Cargo.toml
```

Contract artifacts are located in `contracts/target/ink/<contract_name>/`.

## Deploy to Testnet

### Configuration

```bash
# Set the endpoint (testnet via localhost proxy)
export URL=ws://localhost:80

# For local development node
# export URL=ws://127.0.0.1:9944
```

### Deployment Order

Contracts must be deployed in this order due to cross-contract dependencies:

1. `access_registry` (standalone)
2. `attribute_store` (standalone)
3. `user_registry` (standalone - for DID-to-account linking)
4. `policy_engine` (requires access_registry and attribute_store addresses)
5. `payment_integration` (requires access_registry address)

### Step 1: Deploy access_registry

```bash
cargo contract instantiate \
  --url $URL \
  --suri //Alice \
  --constructor new \
  --skip-confirm \
  --execute \
  contracts/target/ink/access_registry/access_registry.contract
```

Note the contract address from the output and export it:

```bash
export ACCESS_REGISTRY=0x...
```

### Step 2: Deploy attribute_store

```bash
cargo contract instantiate \
  --url $URL \
  --suri //Alice \
  --constructor new \
  --skip-confirm \
  --execute \
  contracts/target/ink/attribute_store/attribute_store.contract
```

```bash
export ATTRIBUTE_STORE=0x...
```

### Step 3: Deploy user_registry

```bash
cargo contract instantiate \
  --url $URL \
  --suri //Alice \
  --constructor new \
  --skip-confirm \
  --execute \
  contracts/target/ink/user_registry/user_registry.contract
```

```bash
export USER_REGISTRY=0x...
```

### Step 4: Deploy and Configure policy_engine

```bash
cargo contract instantiate \
  --url $URL \
  --suri //Alice \
  --constructor new \
  --skip-confirm \
  --execute \
  contracts/target/ink/policy_engine/policy_engine.contract
```

```bash
export POLICY_ENGINE=0x...
```

Configure cross-contract references (note: step numbers updated):

```bash
# Set access_registry address
cargo contract call \
  --url $URL \
  --contract $POLICY_ENGINE \
  --message set_access_registry \
  --args $ACCESS_REGISTRY \
  --suri //Alice \
  --skip-confirm \
  --execute \
  contracts/target/ink/policy_engine/policy_engine.contract

# Set attribute_store address
cargo contract call \
  --url $URL \
  --contract $POLICY_ENGINE \
  --message set_attribute_store \
  --args $ATTRIBUTE_STORE \
  --suri //Alice \
  --skip-confirm \
  --execute \
  contracts/target/ink/policy_engine/policy_engine.contract
```

### Step 5: Deploy and Configure payment_integration

```bash
cargo contract instantiate \
  --url $URL \
  --suri //Alice \
  --constructor new \
  --skip-confirm \
  --execute \
  contracts/target/ink/payment_integration/payment_integration.contract
```

```bash
export PAYMENT_INTEGRATION=0x...
```

Configure cross-contract reference:

```bash
cargo contract call \
  --url $URL \
  --contract $PAYMENT_INTEGRATION \
  --message set_access_registry \
  --args $ACCESS_REGISTRY \
  --suri //Alice \
  --skip-confirm \
  --execute \
  contracts/target/ink/payment_integration/payment_integration.contract
```

## Query Contract State

### Check Contract Owner

```bash
cargo contract call \
  --url $URL \
  --contract $ACCESS_REGISTRY \
  --message owner \
  --suri //Alice \
  contracts/target/ink/access_registry/access_registry.contract
```

### Check Entitlement Level

```bash
cargo contract call \
  --url $URL \
  --contract $ACCESS_REGISTRY \
  --message get_entitlement \
  --args "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" \
  --suri //Alice \
  contracts/target/ink/access_registry/access_registry.contract
```

### Get Attribute

```bash
cargo contract call \
  --url $URL \
  --contract $ATTRIBUTE_STORE \
  --message get_attribute \
  --args "5GrwvaEF..." "opentdf" "role" \
  --suri //Alice \
  contracts/target/ink/attribute_store/attribute_store.contract
```

### Get Account by DID (user_registry)

```bash
cargo contract call \
  --url $URL \
  --contract $USER_REGISTRY \
  --message get_account_by_did \
  --args "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" \
  --suri //Alice \
  contracts/target/ink/user_registry/user_registry.contract
```

### Check if Account is Linked (user_registry)

```bash
cargo contract call \
  --url $URL \
  --contract $USER_REGISTRY \
  --message is_linked \
  --args "0x0101010101010101010101010101010101010101" \
  --suri //Alice \
  contracts/target/ink/user_registry/user_registry.contract
```

## Execute State Changes

### Grant Entitlement (Owner Only)

```bash
cargo contract call \
  --url $URL \
  --contract $ACCESS_REGISTRY \
  --message grant_entitlement \
  --args "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" "Premium" \
  --suri //Alice \
  --skip-confirm \
  --execute \
  contracts/target/ink/access_registry/access_registry.contract
```

### Set Attribute

```bash
cargo contract call \
  --url $URL \
  --contract $ATTRIBUTE_STORE \
  --message set_attribute \
  --args "5GrwvaEF..." "opentdf" "role" "admin" \
  --suri //Alice \
  --skip-confirm \
  --execute \
  contracts/target/ink/attribute_store/attribute_store.contract
```

### Revoke Entitlement

```bash
cargo contract call \
  --url $URL \
  --contract $ACCESS_REGISTRY \
  --message revoke_entitlement \
  --args "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" \
  --suri //Alice \
  --skip-confirm \
  --execute \
  contracts/target/ink/access_registry/access_registry.contract
```

### Link Account to DID (user_registry)

This is a one-time, permanent operation. Once linked, the binding cannot be changed.

```bash
cargo contract call \
  --url $URL \
  --contract $USER_REGISTRY \
  --message link_account \
  --args "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" \
  --suri //Bob \
  --skip-confirm \
  --execute \
  contracts/target/ink/user_registry/user_registry.contract
```

Note: The caller's address (derived from --suri) will be permanently linked to the DID.

## Development Accounts

The following development accounts are pre-funded on the dev chain:

| Account | SURI |
|---------|------|
| Alice | `//Alice` |
| Bob | `//Bob` |
| Charlie | `//Charlie` |
| Dave | `//Dave` |
| Eve | `//Eve` |
| Ferdie | `//Ferdie` |

## Cross-Contract Dependencies

| Contract | Configuration Required |
|----------|----------------------|
| access_registry | None (standalone) |
| attribute_store | None (standalone) |
| user_registry | None (standalone) |
| policy_engine | `set_access_registry()`, `set_attribute_store()` |
| payment_integration | `set_access_registry()` |

## Troubleshooting

### Connection Refused

```
Error: Connection refused
```

Ensure the node is running:

```bash
./target/debug/arkavo-node --dev
```

### Contract Not Found

```
Error: Contract not found at address
```

Verify the contract address is correct and the contract was successfully deployed.

### Insufficient Balance

```
Error: Insufficient balance
```

Use a pre-funded development account (Alice, Bob, etc.) or fund the account.

### Permission Denied

```
Error: NotOwner
```

Only the contract owner (deployer) can call owner-restricted functions like `grant_entitlement`.

## Resources

- [cargo-contract Documentation](https://github.com/use-ink/cargo-contract)
- [ink! Documentation](https://use.ink/)
- [Substrate Documentation](https://docs.substrate.io/)
