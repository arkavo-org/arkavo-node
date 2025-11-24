# Arkavo Runtime

The Substrate runtime for the Arkavo blockchain, compiled to WebAssembly for deterministic execution.

## Overview

This runtime implements the blockchain's state transition function and defines:
- **Block time**: 6 seconds (MILLISECS_PER_BLOCK = 6000)
- **Consensus**: Aura (block production) + GRANDPA (finality)
- **Smart contracts**: Ink! contract execution via `pallet-contracts`

## Key Pallets

### Core System Pallets
- **System** - Core blockchain functionality
- **Timestamp** - On-chain time tracking
- **Aura** - Authority-based block production
- **Grandpa** - Byzantine fault-tolerant finality

### Account & Balance Management
- **Balances** - Native token management
- **TransactionPayment** - Fee calculation and payment
- **Sudo** - Superuser administration (development only)

### Smart Contract Support
- **Contracts** - Ink! smart contract execution
  - Max code length: 123 KB
  - Max storage key length: 128 bytes
  - Randomness via `RandomnessCollectiveFlip`

### Custom Pallets
- **Template** - Example pallet for custom logic

## Configuration

Key runtime parameters defined in `src/lib.rs`:

```rust
const VERSION: RuntimeVersion = ...;
const MILLISECS_PER_BLOCK: u64 = 6000;
type Block = frame_system::mocking::MockBlock<Runtime>;
```

## Building

Build the runtime WASM:

```bash
cargo build --package arkavo-runtime
```

The WASM blob will be output to:
```
target/debug/wbuild/arkavo-runtime/arkavo_runtime.wasm
```

## API Implementation

Runtime APIs are defined in `src/apis.rs`:
- Core API (version, execute_block)
- Metadata API (runtime metadata)
- BlockBuilder API (block construction)
- Transaction payment API (fees)
- Account nonce API
- Aura & Grandpa APIs (consensus)
- Contracts API (smart contract execution)

## Genesis Configuration

Development genesis presets in `src/genesis_config_presets.rs`:
- Pre-funded accounts: Alice, Bob, Charlie, Dave, Eve, Ferdie
- Sudo key: Alice
- Initial authorities for Aura/GRANDPA

## Benchmarking

Runtime benchmarks defined in `src/benchmarks.rs`:

```bash
# Run benchmarks (requires --features runtime-benchmarks)
cargo build --features runtime-benchmarks
./target/release/arkavo-node benchmark pallet \
  --chain dev \
  --pallet '*' \
  --extrinsic '*'
```

## Testing

```bash
cargo test --package arkavo-runtime
```

## Upgrading

Runtime upgrades can be performed via:
1. Build new WASM: `cargo build --package arkavo-runtime`
2. Submit `set_code` extrinsic via sudo or governance
3. New runtime activates on next block

## License

GPL-3.0
