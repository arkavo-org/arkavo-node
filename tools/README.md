# Arkavo Node Tools

This directory contains development and testing tools for the Arkavo Node project.

## Test Suite

### Quick Start

Run the full automated test suite:

```bash
./tools/test-suite.sh
```

### What It Tests

The test suite runs through 5 phases:

#### Phase 1: Environment Validation
- ✓ Rust toolchain availability
- ✓ WebAssembly (wasm32) target installation
- ✓ `cargo-contract` (Ink! tooling)
- ✓ Git dependency access

#### Phase 2: Build Verification
- ✓ Node binary compilation
- ✓ Runtime compilation
- ✓ Runtime WASM artifact generation
- ✓ Node version check
- ✓ All 4 smart contracts compilation
- ✓ Contract artifacts (.contract and .json files)

#### Phase 3: Runtime Testing
- ✓ Node startup in development mode
- ✓ Health endpoint responsiveness
- ✓ Block production (monitors for 15 seconds)

#### Phase 4: Integration Testing
- ✓ Deployer tool compilation
- ✓ Contract deployment via deployer

#### Phase 5: Cleanup & Reporting
- ✓ Graceful node shutdown
- ✓ Report generation (markdown and console)

### Output

The test suite provides:

1. **Real-time console output** with colored indicators:
   - 🟢 ✓ Pass
   - 🔴 ✗ Fail
   - 🟡 ⚠ Skip/Warning

2. **Detailed markdown report** at `tools/test-results.md`:
   - Timestamp and environment info
   - Complete test results table
   - Error messages for failures
   - Summary statistics

### Exit Codes

- `0` - All tests passed
- `1` - Some tests failed (see report)
- `2` - Critical environment failure

### Example Output

```
╔═══════════════════════════════════════════════════════╗
║       Arkavo Node - Automated Test Suite             ║
╚═══════════════════════════════════════════════════════╝

ℹ Project root: /Users/paul/Projects/arkavo/arkavo-node
ℹ Report will be saved to: tools/test-results.md

═══════════════════════════════════════════════════════
  Phase 1: Environment Validation
═══════════════════════════════════════════════════════

✓ Rust toolchain available
✓ WebAssembly target installed
✓ Ink! cargo-contract available
✓ Git dependency access

...

═══════════════════════════════════════════════════════
  TEST SUMMARY
═══════════════════════════════════════════════════════
Total:   18
Passed:  18
Failed:  0
Skipped: 0
═══════════════════════════════════════════════════════

✓ All tests passed!
```

## Deployer

Smart contract deployment tool. See usage:

```bash
cargo run --package deployer -- --help
```

Deploy all contracts to a local node:

```bash
cargo run --package deployer -- \
  --endpoint ws://127.0.0.1:9944 \
  deploy-all \
  --account alice
```

## CI/CD Integration

The test suite can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions step
- name: Run test suite
  run: ./tools/test-suite.sh
```

## Troubleshooting

### "Node binary not found"
Run `cargo build --package arkavo-node` first.

### "cargo-contract not found"
Install with: `cargo install cargo-contract --force`

### "WebAssembly target not installed"
Install with: `rustup target add wasm32-unknown-unknown`

### "Port 9944 already in use"
Stop any existing node process: `pkill arkavo-node`

## Development

To modify the test suite, edit `tools/test-suite.sh`. Key sections:

- **Test recording**: Use `record_test "name" "PASS|FAIL|SKIP" "error msg"`
- **Cleanup**: Add cleanup logic to the `cleanup()` function
- **Report format**: Modify `generate_report()` function
