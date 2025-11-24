# Arkavo Node

A Substrate-based blockchain optimized for Ink! smart contracts, designed for OpenTDF integration with attribute-based access control (ABAC) and entitlement management.

## Overview

Arkavo Node provides a blockchain infrastructure for decentralized access control and entitlement management. It integrates with OpenTDF to enable secure, policy-driven data sharing through smart contracts.

### Key Features

- **Access Registry**: Manage entitlements and VIP membership levels
- **Attribute Store**: Store and query ABAC attributes for policy evaluation
- **Policy Engine**: Define and evaluate access policies for resources
- **Payment Integration**: Link Apple Pay (and other payment providers) to entitlements

## Architecture

```
arkavo-node/
├── node/              # Blockchain node implementation
├── runtime/           # Runtime logic and pallet configuration
├── contracts/         # Ink! smart contracts
│   ├── access_registry/
│   ├── attribute_store/
│   ├── policy_engine/
│   └── payment_integration/
├── tools/             # Deployment and utility tools
│   └── deployer/
├── docker/            # Docker configuration
└── .github/           # CI/CD workflows
```

## Prerequisites

- Rust (stable toolchain)
- `wasm32-unknown-unknown` target
- `cargo-contract` CLI tool
- Docker (optional, for containerized deployment)

### Installation

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install WASM target
rustup target add wasm32-unknown-unknown

# Install cargo-contract
cargo install --locked cargo-contract
```

## Building

### Build the Node

```bash
# Build in release mode
cargo build --release --package arkavo-node

# The binary will be at target/release/arkavo-node
```

### Build the Contracts

**Note**: Contracts use a separate workspace (`contracts/Cargo.toml`) and must be built with `cargo-contract`.

```bash
# Build all contracts from contracts directory
cd contracts
cargo contract build --release --manifest-path access_registry/Cargo.toml
cargo contract build --release --manifest-path attribute_store/Cargo.toml
cargo contract build --release --manifest-path policy_engine/Cargo.toml
cargo contract build --release --manifest-path payment_integration/Cargo.toml

# Or build individual contract
cd contracts/access_registry
cargo contract build --release
```

Contract artifacts will be available in `contracts/*/target/ink/`.

## Running

### Development Mode

```bash
# Run in development mode with temporary storage
./target/release/arkavo-node --dev

# Or with custom configuration
./target/release/arkavo-node --dev --rpc-cors all --rpc-external
```

The node will expose:
- **WebSocket**: `ws://127.0.0.1:9944`
- **HTTP RPC**: `http://127.0.0.1:9933`
- **P2P**: `30333`

### Production Mode

```bash
# Run with persistent storage
./target/release/arkavo-node \
  --base-path /data/arkavo \
  --chain local \
  --name "Arkavo Node"
```

### Docker

```bash
# Build and run with Docker Compose
cd docker
docker-compose up -d

# View logs
docker-compose logs -f arkavo-node

# Access the Polkadot.js Apps UI
open http://localhost:3000
```

## Deploying Contracts

### Using the Deployer Tool

```bash
# Build the deployer
cargo build --release --package deployer

# Upload a contract
cargo run --package deployer -- \
  --endpoint ws://127.0.0.1:9944 \
  upload \
  --wasm contracts/access_registry/target/ink/access_registry.wasm \
  --account alice

# Deploy all contracts
cargo run --package deployer -- \
  --endpoint ws://127.0.0.1:9944 \
  deploy-all \
  --contracts-dir ./target/ink \
  --account alice
```

### Manual Deployment

You can also deploy contracts using the Polkadot.js Apps UI:

1. Navigate to `http://localhost:3000`
2. Connect to your local node
3. Go to **Developer > Contracts**
4. Upload and instantiate contracts

## Smart Contracts

### Access Registry

Manages entitlements for accounts:

```rust
// Grant VIP entitlement
grant_entitlement(account, EntitlementLevel::VIP)

// Check entitlement
has_entitlement(account, EntitlementLevel::Premium)
```

### Attribute Store

Store ABAC attributes:

```rust
// Set attribute
set_attribute(account, "opentdf", "role", "admin")

// Get attribute
get_attribute(account, "opentdf", "role")
```

### Policy Engine

Evaluate access policies:

```rust
// Create policy
create_policy(resource_id, required_attributes, min_entitlement)

// Evaluate access
evaluate_access(account, policy_id)
```

### Payment Integration

Link payments to entitlements:

```rust
// Record payment
record_payment(account, "apple", transaction_id, amount, entitlement_level)

// Complete payment and grant entitlement
complete_payment(payment_id)
```

## Integration with OpenTDF

The Arkavo Node is designed to integrate with OpenTDF's `authnz-rs` service:

1. **Configure** `authnz-rs` to connect to your Arkavo node WebSocket endpoint
2. **Deploy** the smart contracts
3. **Configure** policy rules in the Policy Engine
4. **Query** access decisions through the contracts

Example flow:
```
User Request → authnz-rs → Arkavo Node → Smart Contracts
                ↓
         Access Decision ← Policy Engine ← Attributes + Entitlements
```

## Testing

```bash
# Test the node and runtime
cargo test --workspace --exclude access_registry --exclude attribute_store --exclude policy_engine --exclude payment_integration

# Test individual contracts
cd contracts/access_registry && cargo test
cd ../attribute_store && cargo test
cd ../policy_engine && cargo test
cd ../payment_integration && cargo test

# Run all tests (including contracts)
cargo test --workspace --exclude access_registry --exclude attribute_store --exclude policy_engine --exclude payment_integration

# Test individual contracts
cd contracts/access_registry && cargo test
cd ../attribute_store && cargo test
cd ../policy_engine && cargo test
cd ../payment_integration && cargo test
```

## Security

### Dependency Attack Surface

Substrate/Polkadot SDK introduces ~500+ transitive dependencies. We mitigate this risk with:

**Automated Security Checks** (via GitHub Actions):

```bash
# Install act for local workflow execution
brew install act

# Run security checks locally for specific jobs
act -j audit            # CVE scanning with cargo-audit
act -j deny             # License & policy checks with cargo-deny
act -j unsafe-code      # Locate unsafe code blocks
act -j supply-chain     # Check dependency sources
```

**Local Code Quality Checks:**
```bash
# Format check
cargo fmt --all -- --check

# Clippy on node & runtime
cargo clippy --package arkavo-node --package arkavo-runtime -- -D warnings

# Clippy on contracts (requires navigating to contracts dir)
cd contracts && cargo clippy --workspace -- -D warnings
```

**Build-Time Enforcement** (`.cargo/config.toml`):
- Strict Clippy lints: pedantic, cargo, nursery
- Security-focused lints: integer arithmetic, unsafe indexing, mem::forget, panics
- All warnings treated as errors (`-D warnings`)
- Warnings on: unwrap_used, expect_used, todo!, unimplemented!

**Dependency Policy** (`deny.toml`):
- Only allow crates from crates.io and Polkadot SDK git repo
- Deny known CVEs and yanked versions
- License compliance (MIT/Apache-2.0/BSD/GPL-3.0 allowed)
- Warn on duplicate dependencies

**Daily Automated Scans**:
- Security audit runs daily at 00:00 UTC via GitHub Actions
- All PRs automatically scanned for vulnerabilities and lint issues

## CI/CD

GitHub Actions workflows are configured for:

- **Build & Test**: Validates node and runtime compilation
- **Contracts**: Builds and tests all Ink! contracts
- **Docker**: Builds and pushes Docker images to GHCR

## Development

### Project Structure

- `node/`: Node implementation with chain specification and RPC configuration
- `runtime/`: Runtime configuration with `pallet-contracts` enabled
- `contracts/`: Ink! smart contracts for access control and entitlements
- `tools/deployer/`: Rust binary for contract deployment automation
- `docker/`: Docker and docker-compose configuration

### Adding New Contracts

1. Create a new directory under `contracts/`
2. Add contract to workspace in root `Cargo.toml`
3. Implement contract logic using Ink!
4. Add to deployer tool's `contract_names` list
5. Update CI/CD workflows if needed

## Troubleshooting

### Build Issues

```bash
# Clean build
cargo clean

# Update dependencies
cargo update

# Rebuild with verbose output
cargo build --release --verbose
```

### Runtime Issues

```bash
# Purge chain data
./target/release/arkavo-node purge-chain --dev

# Check runtime version
./target/release/arkavo-node --version
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and formatting
5. Submit a pull request

### Code Standards

```bash
# Format code
cargo fmt --all

# Run linter
cargo clippy --all-targets -- -D warnings

# Run tests
cargo test --workspace
```

## License

Apache-2.0

## Resources

- [Substrate Documentation](https://docs.substrate.io/)
- [Ink! Documentation](https://use.ink/)
- [OpenTDF Documentation](https://opentdf.io/)
- [Polkadot.js Apps](https://polkadot.js.org/apps/)

## Support

For issues and questions:
- [GitHub Issues](https://github.com/arkavo-org/arkavo-node/issues)
- [Arkavo Documentation](https://arkavo.com/docs)
