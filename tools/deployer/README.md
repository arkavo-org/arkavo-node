# Deployer Tool

Command-line utility for deploying and managing Ink! smart contracts on the Arkavo blockchain.

## Overview

The deployer tool provides a streamlined interface for uploading contract code, instantiating contracts, and querying contract state on a running Arkavo node. Built with Subxt for type-safe Substrate interactions.

## Features

- **Upload**: Deploy contract WASM code to the chain
- **Instantiate**: Create contract instances from uploaded code
- **Deploy All**: Batch deployment of multiple contracts
- **Query**: Read contract state and call view functions
- **Account Management**: Built-in support for development accounts (Alice, Bob, etc.)

## Building

```bash
# Build the deployer tool
cargo build --package deployer

# Build release version
cargo build --release --package deployer
```

**Binary Location**: `target/debug/deployer` or `target/release/deployer`

## Usage

### General Syntax

```bash
deployer [OPTIONS] <COMMAND>

Options:
  -e, --endpoint <ENDPOINT>  WebSocket endpoint URL [default: ws://127.0.0.1:9944]
  -h, --help                 Print help
```

### Upload Contract Code

Upload a contract's WASM code to the chain:

```bash
deployer upload \
  --wasm contracts/access_registry/target/ink/access_registry.wasm \
  --account alice
```

**Parameters**:
- `--wasm, -w`: Path to the contract `.wasm` file (required)
- `--account, -a`: Account to use for upload (default: "alice")

**Supported Accounts**: alice, bob, charlie, dave, eve, ferdie

**Output**: Returns the code hash for use in instantiation

### Instantiate Contract

Create a contract instance from uploaded code:

```bash
deployer instantiate \
  --code-hash 0x1234... \
  --selector 0x9bae9d5e \
  --args "" \
  --value 0 \
  --gas-limit 500000000000 \
  --account alice
```

**Parameters**:
- `--code-hash, -c`: Code hash from upload step (required)
- `--selector, -s`: Constructor selector in hex (default: "0x9bae9d5e" for `new()`)
- `--args, -a`: Constructor arguments in hex (default: "")
- `--value, -v`: Initial balance to transfer (default: 0)
- `--gas-limit, -g`: Gas limit for instantiation (default: 500000000000)
- `--account, -a`: Account to use for instantiation (default: "alice")

**Common Selectors**:
- `0x9bae9d5e`: Default `new()` constructor with no arguments

**Output**: Returns the deployed contract address

### Deploy All Contracts

Batch deploy multiple contracts from a directory:

```bash
deployer deploy-all \
  --contracts-dir ./target/ink \
  --account alice
```

**Parameters**:
- `--contracts-dir, -c`: Directory containing `.wasm` and `.json` files (default: "./target/ink")
- `--account, -a`: Account to use for deployment (default: "alice")

**Requirements**:
- Directory must contain both `.wasm` and `.json` files for each contract
- Contract metadata (`.json`) used to determine constructor signature

**Process**:
1. Scans directory for contract artifacts
2. Uploads all WASM code
3. Instantiates each contract with default constructor
4. Reports deployment addresses

### Query Contract State

Call a read-only contract function:

```bash
deployer query \
  --address 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY \
  --selector 0x6d4ce63c \
  --args ""
```

**Parameters**:
- `--address, -a`: Contract address (required)
- `--selector, -s`: Message selector in hex (required)
- `--args, -r`: Message arguments in hex (default: "")

**Finding Selectors**: Use contract metadata JSON file to find function selectors

## Examples

### Deploy Access Registry

```bash
# 1. Build the contract
cd contracts/access_registry
cargo contract build --release

# 2. Upload code
CODE_HASH=$(deployer upload \
  --wasm target/ink/access_registry.wasm \
  --account alice)

# 3. Instantiate contract
CONTRACT_ADDR=$(deployer instantiate \
  --code-hash $CODE_HASH \
  --account alice)

echo "Access Registry deployed at: $CONTRACT_ADDR"
```

### Deploy All Contracts

```bash
# Build all contracts first
cd contracts
cargo contract build --release --manifest-path access_registry/Cargo.toml
cargo contract build --release --manifest-path attribute_store/Cargo.toml
cargo contract build --release --manifest-path policy_engine/Cargo.toml
cargo contract build --release --manifest-path payment_integration/Cargo.toml

# Deploy all at once
deployer deploy-all --account alice
```

### Query Owner

```bash
# Query the owner of access_registry contract
deployer query \
  --address 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY \
  --selector 0x6d4ce63c  # owner() selector
```

## Configuration

### Endpoint Selection

Connect to different nodes:

```bash
# Local development node
deployer --endpoint ws://127.0.0.1:9944 upload --wasm contract.wasm

# Remote node
deployer --endpoint wss://arkavo.example.com:9944 upload --wasm contract.wasm

# Custom port
deployer --endpoint ws://127.0.0.1:9955 upload --wasm contract.wasm
```

### Account Selection

Use different development accounts:

```bash
# Alice (default authority)
deployer upload --wasm contract.wasm --account alice

# Bob (second validator)
deployer upload --wasm contract.wasm --account bob

# Other test accounts
deployer upload --wasm contract.wasm --account charlie
deployer upload --wasm contract.wasm --account dave
```

**Account Funding**: Development accounts are pre-funded in dev chain genesis

## Logging

Control log verbosity with the `RUST_LOG` environment variable:

```bash
# Info level (default)
RUST_LOG=info deployer upload --wasm contract.wasm

# Debug level
RUST_LOG=debug deployer upload --wasm contract.wasm

# Trace level (very verbose)
RUST_LOG=trace deployer upload --wasm contract.wasm

# Specific module
RUST_LOG=deployer=debug deployer upload --wasm contract.wasm
```

## Dependencies

### Substrate/Polkadot SDK

- **subxt 0.37**: Type-safe Substrate RPC client
- **sp-core 34.0**: Core Substrate primitives
- **sp-keyring 39.0**: Development account keyring

### Runtime

- **tokio 1.38**: Async runtime with full features

### CLI

- **clap 4.5**: Command-line argument parsing with derive macros
- **anyhow 1.0**: Error handling with context
- **serde/serde_json 1.0**: JSON serialization for metadata

### Logging

- **tracing 0.1**: Structured logging
- **tracing-subscriber 0.3**: Log formatting and filtering

## Troubleshooting

### Connection Refused

```
Error: Connection refused (os error 111)
```

**Solution**: Ensure Arkavo node is running:
```bash
./target/debug/arkavo-node --dev
```

### Code Hash Not Found

```
Error: Code hash not found on chain
```

**Solution**: Upload the contract code first before instantiating

### Insufficient Balance

```
Error: Account has insufficient balance
```

**Solution**: Use a pre-funded development account (alice, bob, etc.) or fund the account

### Invalid Selector

```
Error: Invalid selector format
```

**Solution**: Ensure selector is hex format with `0x` prefix (e.g., `0x9bae9d5e`)

## Integration with Test Suite

The deployer is used by the automated test suite:

```bash
# From tools/test-suite.sh
cargo run --package deployer -- \
  --endpoint ws://127.0.0.1:9944 \
  deploy-all \
  --account alice
```

## Development

### Project Structure

```
tools/deployer/
├── Cargo.toml          # Dependencies and package config
├── src/
│   └── main.rs         # CLI implementation
└── README.md           # This file
```

### Adding New Commands

1. Add command variant to `Commands` enum
2. Implement command handler in `main()`
3. Update help text and documentation

### Testing Locally

```bash
# Start local node
./target/debug/arkavo-node --dev --tmp

# Test upload
cargo run --package deployer -- upload \
  --wasm contracts/access_registry/target/ink/access_registry.wasm

# Test instantiate
cargo run --package deployer -- instantiate \
  --code-hash <hash-from-upload>
```

## Future Enhancements

- [ ] Contract call (non-query) support
- [ ] Custom account from seed phrase
- [ ] Deployment plan files (YAML/JSON)
- [ ] Contract upgrade support
- [ ] Multi-chain deployment
- [ ] Contract verification
- [ ] Gas estimation
- [ ] Interactive mode

## License

GPL-3.0
