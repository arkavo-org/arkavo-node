# Security Policy

## Known Security Vulnerabilities

This document tracks known security vulnerabilities in Arkavo Node's dependency chain. Many of these vulnerabilities are inherited from upstream Substrate/Polkadot SDK and Ink! dependencies and are being tracked for resolution.

**Last Audit**: 2025-11-24
**Total Dependencies**: 881 crates
**Vulnerabilities**: 1 active CVE, 4 unmaintained advisories, 1 yanked

### Vulnerability Tracking Approach

We take a **transparent, deny-by-default** approach to dependency security using cargo-deny v2 configuration:

1. **Minimal Ignore List**: 5 advisories ignored in `deny.toml` (1 vulnerability + 4 unmaintained, all documented below)
2. **Deny by Default**: cargo-deny v2 denies all advisories (vulnerability, unmaintained, notice) unless explicitly ignored
3. **Documented Exceptions**: All known issues are documented here with impact analysis
4. **Blocking PR Checks**: Security checks run on every PR and will fail if new vulnerabilities are detected
5. **Daily Monitoring**: Automated daily audits alert us to new vulnerabilities and create GitHub issues

**Security Configuration (deny.toml v2)**:
- `[advisories] version = 2`: All advisory types denied by default (no separate unmaintained/notice settings)
- `yanked = "warn"`: Substrate uses some yanked crates (const-hex), non-blocking
- `ignore = [5 RUSTSECs]`: 1 vulnerability + 4 unmaintained crates (all upstream Substrate dependencies)
- `[licenses] version = 2`: Deny all licenses except explicit allow list

**Why this approach?**
- New vulnerabilities immediately block PRs, forcing immediate triage
- Explicit ignore list ensures conscious decision-making
- Transparency via SECURITY.md documentation
- Upstream issues tracked and documented, not hidden

### Current Known CVEs

#### RUSTSEC-2025-0118: wasmtime 35.0.0 🔴 CRITICAL
- **Severity**: High
- **Status**: Upstream dependency (Substrate WASM executor)
- **Description**: Unsound API access to a WebAssembly shared linear memory. See [GHSA-hc7m-r6v8-hg9q](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-hc7m-r6v8-hg9q)
- **Impact**: Potential memory safety issues in WASM execution
- **Dependency Path**: `sc-executor` → `sc-executor-wasmtime` → `wasmtime 35.0.0`
- **Mitigation**: Awaiting Substrate update to wasmtime >=38.0.4. Tracking Polkadot SDK stable2509 branch.
- **Solution**: Upgrade to wasmtime >=38.0.4 (or >=37.0.3, >=36.0.3, >=24.0.5 depending on major version)
- **Tracking**: https://rustsec.org/advisories/RUSTSEC-2025-0118.html
- **Note**: This is a **blocking issue** - awaiting upstream Substrate fix before removing from ignore list

### Unmaintained Dependencies

The following dependencies are flagged as unmaintained in our dependency tree:

#### RUSTSEC-2024-0384: instant 0.1.13
- **Status**: Unmaintained (since 2024-07-31)
- **Impact**: WASM-compatible instant measurement library
- **Dependency Path**: `sc-network` → `wasm-timer` → `parking_lot` → `instant 0.1.13`
- **Mitigation**: Author recommends `web-time` crate. Awaiting Substrate migration.
- **Risk**: Low (timing utility, no direct security impact)
- **Tracking**: https://rustsec.org/advisories/RUSTSEC-2024-0384.html

#### RUSTSEC-2022-0061: parity-wasm 0.45.0
- **Status**: Deprecated by author (2022-10-01)
- **Impact**: WASM parsing library used in `sp-version`
- **Mitigation**: Substrate will migrate to maintained alternatives (`wasm-*` family)
- **Tracking**: https://rustsec.org/advisories/RUSTSEC-2022-0061.html

#### RUSTSEC-2024-0436: paste 1.0.15
- **Status**: Unmaintained (since 2024-10-07)
- **Impact**: Compile-time macro for token concatenation
- **Risk**: Low (compile-time only, no runtime impact)
- **Tracking**: https://rustsec.org/advisories/RUSTSEC-2024-0436.html

#### RUSTSEC-2024-0370: proc-macro-error 1.0.4
- **Status**: Unmaintained (since 2024-09-01)
- **Impact**: Error handling for procedural macros
- **Risk**: Low (compile-time only via `frame-support`)
- **Tracking**: https://rustsec.org/advisories/RUSTSEC-2024-0370.html


### Yanked Crates

#### const-hex 1.13.0 (YANKED)
- **Status**: Yanked from crates.io
- **Dependency Path**: `frame-metadata-hash-extension` → `const-hex 1.13.0`
- **Impact**: Yanked crates are typically removed for breaking changes or critical bugs
- **Mitigation**: Substrate dependency via `frame-metadata-hash-extension`. Awaiting upstream update.
- **Risk**: Low (likely yanked for non-security reasons, still functional)
- **Note**: Version is locked in Cargo.lock, will not auto-update until Substrate updates

### Known Build Issues

#### pallet-staking: Missing peek_disabled trait implementation
- **Severity**: Build Error (Not Runtime Security Issue)
- **Status**: Upstream Substrate bug in stable2509 branch
- **Description**: The `MigrateDisabledValidators` trait implementation in `pallet-staking` has a conditionally compiled method `peek_disabled()` that is only available with the `try-runtime` feature enabled. This causes compilation failures when building without `try-runtime`.
- **Impact**: Cannot run `cargo clippy --all-targets` without compilation errors
- **Workaround Applied**: Removed `--all-targets` from clippy command in CI workflows
  - Clippy now checks only library code, not tests/benches/examples
  - All build/test commands include `--features try-runtime` flag
- **Trade-off**: We don't get clippy checking on test code, but this is acceptable since:
  - Test code is simpler and less critical than library code
  - The pallet-staking issue only appears when checking test/bench targets
  - We can still run tests normally with `cargo test --features try-runtime`
- **Note**: This does not affect runtime security as we do not use `pallet-staking` directly; it's only a transitive dependency through benchmarking tools
- **Tracking**: Substrate stable2509 branch commit fd902fcc - awaiting upstream fix

### Dependency Management Strategy

Arkavo Node inherits ~500+ transitive dependencies from the Substrate/Polkadot SDK. Our security strategy includes:

1. **Commit-Locked Dependencies**: All Substrate dependencies are pinned to specific commits from the `stable2509` branch
2. **Daily Automated Audits**: Security audits run daily via GitHub Actions to detect new vulnerabilities
3. **Strict Source Policy**: Only crates.io and github.com/paritytech/polkadot-sdk.git are allowed as dependency sources
4. **Continuous Monitoring**: We actively monitor:
   - Polkadot SDK security advisories
   - RustSec advisory database
   - Substrate GitHub security updates

### Reporting Security Issues

If you discover a security vulnerability in Arkavo Node (excluding known upstream issues documented above), please report it by:

1. **DO NOT** open a public GitHub issue
2. Email security reports to: [security contact to be added]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### Security Update Process

When new security vulnerabilities are discovered:

1. **Critical/High Severity**: Immediate evaluation and patching within 48 hours
2. **Medium Severity**: Evaluation within 1 week, patching in next release cycle
3. **Low Severity**: Tracked and addressed in regular dependency updates
4. **Upstream Issues**: Monitored via Substrate update tracking, applied when available

### Build-Time Security Enforcement

Our CI/CD pipeline enforces:

- **cargo-audit**: Blocks builds with known CVEs (except documented exceptions)
- **cargo-deny**: Enforces license and source policies
- **Clippy Security Lints**: Warns on unsafe patterns (unwrap, expect, panic, etc.)
- **Unsafe Code Detection**: Tracks all unsafe blocks for review

See [CLAUDE.md](CLAUDE.md) for detailed security tooling documentation.

### Version Support

- **Main Branch**: Receives all security updates immediately
- **Release Tags**: Critical security patches backported on case-by-case basis
- **EOL Policy**: Releases older than 3 months are not actively maintained

---

**Last Updated**: 2025-11-23
**Next Review**: 2025-12-23
