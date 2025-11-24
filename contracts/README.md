# Arkavo Smart Contracts

Ink! smart contracts for the Arkavo blockchain, providing decentralized access control and entitlement management.

## Overview

This workspace contains four interconnected smart contracts:

1. **access_registry** - Entitlement level management (None/Basic/Premium/VIP)
2. **attribute_store** - ABAC attribute storage with authorization
3. **policy_engine** - Policy creation and evaluation
4. **payment_integration** - Payment provider integration (Apple Pay, etc.)

## Architecture

```
contracts/
├── Cargo.toml                    # Workspace configuration
├── access_registry/              # Entitlement management
├── attribute_store/              # Attribute-based access control
├── policy_engine/                # Policy evaluation
└── payment_integration/          # Payment processing
```

## Ink! Version

All contracts use **Ink! 6.0.0-beta.1**:

```toml
[workspace.dependencies]
ink = { version = "6.0.0-beta.1", default-features = false }
```

## Building

### Build All Contracts

```bash
cd contracts
cargo contract build --release --manifest-path access_registry/Cargo.toml
cargo contract build --release --manifest-path attribute_store/Cargo.toml
cargo contract build --release --manifest-path policy_engine/Cargo.toml
cargo contract build --release --manifest-path payment_integration/Cargo.toml
```

### Build Individual Contract

```bash
cd contracts/access_registry
cargo contract build --release
```

### Build Artifacts

Compiled contracts are output to `target/ink/`:
- `*.contract` - Contract bundle (WASM + metadata)
- `*.wasm` - Contract WASM code
- `*.json` - Contract metadata (ABI)

## Testing

### Unit Tests

```bash
# Test all contracts
cd contracts
cargo test

# Test specific contract
cd contracts/access_registry
cargo test
```

### E2E Tests

```bash
cd contracts/access_registry
cargo test --features e2e-tests
```

## Deployment

### Using the Deployer Tool

```bash
# Deploy all contracts
cargo run --package deployer -- \
  --endpoint ws://127.0.0.1:9944 \
  deploy-all \
  --account alice

# Deploy specific contract
cargo run --package deployer -- \
  --endpoint ws://127.0.0.1:9944 \
  upload \
  --path contracts/access_registry/target/ink/access_registry.contract \
  --account alice
```

### Manual Deployment

Using `cargo-contract`:

```bash
cargo contract instantiate \
  --constructor new \
  --args ... \
  --suri //Alice \
  --url ws://127.0.0.1:9944
```

## Contract Interaction Flow

```
User Request
    ↓
Payment Integration → Access Registry
    ↓                      ↓
Grants Entitlement ← Checks Level
    ↓
Attribute Store ← Policy Engine
    ↓                 ↓
Stores Attributes → Evaluates Policy
    ↓
Access Decision
```

## Integration with OpenTDF

These contracts are designed to integrate with OpenTDF's authorization service:

1. **authnz-rs** connects to Arkavo node via WebSocket
2. Policy decisions query smart contracts
3. Entitlements and attributes stored on-chain
4. Immutable audit trail of access decisions

## Development

### Add New Contract

1. Create contract directory:
```bash
mkdir contracts/my_contract
```

2. Add to workspace `Cargo.toml`:
```toml
members = [
    "access_registry",
    "attribute_store",
    "policy_engine",
    "payment_integration",
    "my_contract",  # Add here
]
```

3. Create contract `Cargo.toml` using workspace dependencies

4. Implement contract logic in `lib.rs`

### Code Quality

```bash
# Format
cargo fmt --all

# Lint
cargo clippy --all-targets -- -D warnings
```

## Contract Optimization

For production deployment, contracts are compiled with:

```toml
[profile.release]
panic = "unwind"      # Proper error handling
lto = true            # Link-time optimization
opt-level = "z"       # Optimize for size
overflow-checks = true # Safety checks
```

## Security Considerations

- All contracts use owner-based access control
- Entitlements are hierarchical (VIP > Premium > Basic > None)
- Attribute writes require authorization
- Events emitted for all state changes
- No unsafe code allowed

## Resources

- [Ink! Documentation](https://use.ink/)
- [Substrate Contracts Pallet](https://docs.substrate.io/reference/frame-pallets/contracts/)
- [OpenTDF](https://opentdf.io/)

## License

GPL-3.0
