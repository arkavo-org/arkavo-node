# Agentic Code Assistant Guidelines

This file provides guidance to Code Assistant when working with code in this repository.

## Project Overview

Arkavo Node is a Substrate-based blockchain optimized for Ink! smart contracts, designed for OpenTDF integration with attribute-based access control (ABAC) and entitlement management. The project enables decentralized access control through on-chain smart contracts that integrate with OpenTDF's authorization service.

## Security Posture

### Dependency Management
- **Large Attack Surface**: Substrate/Polkadot SDK brings ~500+ transitive dependencies
- **Mitigation Strategy**: Stringent security checks enforced at build time
- **Git Dependencies**: All Substrate dependencies from `stable2509` branch (commit-locked)
- **Allowed Sources**: Only crates.io and github.com/paritytech/polkadot-sdk.git

### Security Tooling

**Developer Workflow** (no Makefile/justfile - use `act` to run GitHub Actions locally):
```bash
# Install act
brew install act

# Run specific security checks (via GitHub Actions locally)
act -j audit            # CVE scanning
act -j deny             # License/policy checks
act -j unsafe-code      # Find unsafe blocks
act -j supply-chain     # Verify dependency sources

# Run linting and formatting locally
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

**Build-Time Enforcement** (`.cargo/config.toml`):
- All warnings denied (`-D warnings`)
- Clippy: all, pedantic, cargo, nursery lints
- Security lints: integer arithmetic, unsafe indexing, mem::forget, panics
- Warnings on: unwrap_used, expect_used, todo!, unimplemented!

**Automated CI/CD**:
- All workflows run on push/PR to main branch
- Security audit runs daily at 00:00 UTC
- Workflows defined in `.github/workflows/`: security.yaml, lint.yaml, build.yaml, contracts.yaml

### Dependency Policy (`deny.toml`)
- **Vulnerability**: Deny all known CVEs
- **Licenses**: Allow MIT/Apache-2.0/BSD/GPL-3.0, deny GPL-2.0/AGPL-3.0
- **Sources**: Only crates.io + Polkadot SDK git repo
- **Yanked**: Deny yanked crate versions

## Architecture

### Three-Layer Design

1. **Substrate Node (`node/`)**: The blockchain client that runs the network
   - Uses Aura (consensus) and GRANDPA (finality)
   - Exposes WebSocket (9944), HTTP RPC (9933), and P2P (30333) ports
   - Chain specifications in `chain_spec.rs` define genesis state with pre-funded accounts (Alice, Bob, etc.)

2. **Runtime (`runtime/`)**: The state transition function compiled to WASM
   - Configured with `pallet-contracts` for Ink! smart contract execution
   - Block time: 6 seconds (MILLISECS_PER_BLOCK = 6000)
   - Key pallets: Balances, Timestamp, Sudo, TransactionPayment, Contracts
   - Uses `RandomnessCollectiveFlip` for contract randomness
   - Contract limits: MaxCodeLen = 123KB, MaxStorageKeyLen = 128 bytes

3. **Ink! Smart Contracts (`contracts/`)**: On-chain business logic for access control
   - **access_registry**: Manages 4-tier entitlement levels (None/Basic/Premium/VIP)
   - **attribute_store**: ABAC attribute storage with authorization (namespace.key.value triplets)
   - **policy_engine**: Policy creation and evaluation against entitlements/attributes
   - **payment_integration**: Links payment providers (Apple Pay) to entitlement grants

### Key Architectural Patterns

**Contract Interaction Flow:**
```
User Request → authnz-rs → Arkavo Node WS → Smart Contracts
                                ↓
                         Policy Engine evaluates:
                         - Entitlements (access_registry)
                         - Attributes (attribute_store)
                                ↓
                         Access Decision
```

**Entitlement Management:**
- Owner-controlled (only contract deployer can grant/revoke)
- Hierarchical levels with `level_value()` comparison
- Event emission for all state changes (EntitlementGranted, EntitlementRevoked)

**Attribute Authorization:**
- Three authorization layers: account owner, authorized writers, contract owner
- Namespace-based organization (e.g., "opentdf" namespace)
- Writer authorization with granular per-writer control

## Build Commands

### Node and Runtime

```bash
# Build everything (node + runtime + tools)
# NOTE: Contracts are in a separate workspace and NOT built by root cargo build
cargo build --quiet

# Build specific components
cargo build --quiet --package arkavo-node
cargo build --quiet --package arkavo-runtime

# Clean rebuild
cargo clean && cargo build --quiet
```

### Ink! Smart Contracts

**Important**: Contracts use a separate workspace in `contracts/Cargo.toml` and are built with `cargo-contract`, NOT regular `cargo build`.

```bash
# Build all contracts (from contracts directory)
cd contracts
cargo contract build --release --manifest-path access_registry/Cargo.toml
cargo contract build --release --manifest-path attribute_store/Cargo.toml
cargo contract build --release --manifest-path policy_engine/Cargo.toml
cargo contract build --release --manifest-path payment_integration/Cargo.toml

# Or build individual contract
cd contracts/access_registry
cargo contract build --release

# Artifacts output to: contracts/*/target/ink/*.{wasm,json}
```

### Tools

```bash
# Build deployer tool
cargo build --quiet --package deployer

# Use deployer
cargo run --package deployer -- --endpoint ws://127.0.0.1:9944 deploy-all --account alice
```

## Testing

```bash
# Test node and runtime (excludes Ink! contracts)
cargo test --workspace --exclude access_registry --exclude attribute_store --exclude policy_engine --exclude payment_integration

# Test individual contract
cd contracts/access_registry && cargo test

# Run specific test
cargo test --package arkavo-runtime test_name
```

## Running the Node

```bash
# Development mode (temporary storage, Alice as authority)
./target/release/arkavo-node --dev

# Development with external RPC access
./target/release/arkavo-node --dev --rpc-cors all --rpc-external

# Purge dev chain data
./target/release/arkavo-node purge-chain --dev

# Local testnet (persistent storage)
./target/release/arkavo-node --base-path /data/arkavo --chain local --name "Node1"
```

## Code Quality

```bash
# Format all code
cargo fmt --all

# Lint with clippy
cargo clippy --all-targets -- -D warnings
```

## Dependency Management

**Critical**: All Substrate dependencies use git sources from `stable2509` branch:
```toml
git = "https://github.com/paritytech/polkadot-sdk.git"
branch = "stable2509"
```

This ensures version compatibility across all `frame-*`, `pallet-*`, `sp-*`, and `sc-*` crates. Do NOT mix crates.io versions with git dependencies.

## Contract Development Guidelines

### Ink! Contract Structure
- Use `#![cfg_attr(not(feature = "std"), no_std, no_main)]` attribute
- Events should have `#[ink(topic)]` on indexed fields (typically AccountId)
- Error types must derive: `Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode`
- Storage uses `Mapping<K, V>` for key-value storage (not HashMap)

### Testing Contracts
- Unit tests use `#[ink::test]` attribute
- Mock AccountIds with `AccountId::from([0xNN; 32])`
- Test both success and error paths
- Verify event emission in tests

## Genesis Configuration

Development chain (`--dev`) pre-funds these accounts:
- Alice (authority + sudo)
- Bob
- Alice//stash, Bob//stash

Genesis block includes initialization of:
- System pallet with WASM runtime code
- Balances with 1 << 60 tokens per endowed account
- Aura authorities for block production
- GRANDPA authorities for finality
- Sudo key (Alice in dev mode)

## Integration Points

### OpenTDF Integration
1. Deploy smart contracts to running node
2. Configure `authnz-rs` to connect to `ws://node:9944`
3. Contracts called via standard Substrate contract RPC: `contracts_call`
4. Access decisions stored on-chain, queryable via `contracts_getStorage`

### Docker Deployment
```bash
cd docker
docker-compose up -d    # Starts node + Polkadot.js UI on localhost:3000
docker-compose logs -f arkavo-node
```

## Common Issues

**Build Failures**: If Substrate dependencies fail to resolve, ensure all use the same git branch. Run `cargo update` to refresh the Cargo.lock file.

**Runtime Panics**: Check `runtime/src/lib.rs` pallet configurations match the `construct_runtime!` macro order.

**Contract Upload Fails**: Verify `pallet-contracts` configuration in runtime, especially `MaxCodeLen` and deposit limits.

**WASM Build Errors**: Ensure `wasm32-unknown-unknown` target installed: `rustup target add wasm32-unknown-unknown`
