# Arkavo Node

The Substrate blockchain node client for the Arkavo network.

## Overview

This is the client implementation that runs the Arkavo blockchain. It handles:
- **Networking**: P2P communication between nodes
- **Consensus**: Block production (Aura) and finality (GRANDPA)
- **RPC**: HTTP and WebSocket endpoints for external access
- **Storage**: Persistent blockchain state database
- **Runtime execution**: Executes the WASM runtime

## Architecture

```
node/
├── src/
│   ├── main.rs           # Entry point
│   ├── cli.rs            # Command-line interface
│   ├── command.rs        # Command handlers
│   ├── service.rs        # Node service setup
│   ├── rpc.rs            # RPC extensions
│   ├── chain_spec.rs     # Chain specifications
│   └── benchmarking.rs   # Benchmark infrastructure
└── build.rs              # Build script
```

## Running the Node

### Development Mode

Quick start with temporary storage:

```bash
./target/debug/arkavo-node --dev
```

With external RPC access:

```bash
./target/debug/arkavo-node --dev --rpc-cors all --rpc-external
```

### Local Testnet

Persistent storage:

```bash
./target/debug/arkavo-node \
  --base-path /data/arkavo \
  --chain local \
  --name "Node1" \
  --validator
```

### Purge Chain Data

```bash
./target/debug/arkavo-node purge-chain --dev
```

## Configuration

### Ports

- **9944**: WebSocket RPC endpoint
- **9933**: HTTP RPC endpoint
- **30333**: P2P networking

### Chain Specifications

Defined in `src/chain_spec.rs`:
- **dev**: Development chain with Alice as authority
- **local**: Local testnet with Alice & Bob as validators

## RPC Extensions

Custom RPC methods defined in `src/rpc.rs`:
- Contracts RPC (contract queries and execution)
- Transaction payment RPC (fee estimation)

Access via WebSocket:

```javascript
// Connect to local node
const provider = new WsProvider('ws://127.0.0.1:9944');
const api = await ApiPromise.create({ provider });
```

## Service Architecture

The node service (`src/service.rs`) sets up:

1. **Partial Components**: Client, backend, task manager, import queue
2. **Block Import Pipeline**: Aura → GRANDPA → Client
3. **Network Backend**: Libp2p or Litep2p
4. **Consensus Tasks**:
   - Aura block production
   - GRANDPA finality voting
5. **Telemetry**: Optional metrics reporting

## Benchmarking

Runtime benchmarking infrastructure in `src/benchmarking.rs`:

```bash
# Run pallet benchmarks
./target/release/arkavo-node benchmark pallet \
  --chain dev \
  --pallet pallet_balances \
  --extrinsic transfer

# Machine benchmarks
./target/release/arkavo-node benchmark machine
```

## Building

```bash
# Development build
cargo build --package arkavo-node

# Release build (optimized)
cargo build --release --package arkavo-node
```

## Testing

```bash
# Run node tests
cargo test --package arkavo-node
```

## Command-Line Options

```bash
# Show all options
./target/debug/arkavo-node --help

# Show version
./target/debug/arkavo-node --version

# Export chain spec
./target/debug/arkavo-node build-spec --chain dev > chain-spec.json

# Check block
./target/debug/arkavo-node check-block --block-hash 0x...
```

## Monitoring

### Health Check

```bash
curl http://localhost:9944/health
```

Response:
```json
{
  "peers": 0,
  "isSyncing": false,
  "shouldHavePeers": false
}
```

### Logs

Enable debug logging:

```bash
RUST_LOG=debug ./target/debug/arkavo-node --dev
```

Filter by module:

```bash
RUST_LOG=sc_consensus_aura=debug ./target/debug/arkavo-node --dev
```

## Integration with Smart Contracts

The node supports Ink! smart contracts via `pallet-contracts`. Deploy and interact using:
- [cargo-contract](https://github.com/paritytech/cargo-contract)
- [Contracts UI](https://contracts-ui.substrate.io/)
- Custom deployer tool: `tools/deployer`

## License

GPL-3.0
