# Access Registry Contract

Ink! smart contract for managing hierarchical entitlement levels in the Arkavo blockchain.

## Overview

The Access Registry provides a foundational access control mechanism through a 4-tier entitlement system. It enables owner-controlled access grants with hierarchical level checking, designed to integrate with OpenTDF's attribute-based access control (ABAC) framework.

## Entitlement Levels

```rust
pub enum EntitlementLevel {
    None,     // Level 0 - No access
    Basic,    // Level 1 - Basic access
    Premium,  // Level 2 - Premium access
    VIP,      // Level 3 - Full access
}
```

**Hierarchical Comparison**: Levels are compared numerically (VIP > Premium > Basic > None). Users with a higher level automatically satisfy requirements for lower levels.

## Contract Functions

### Constructor

```rust
pub fn new() -> Self
```

Initializes the contract with the deployer as the owner.

### Access Control

#### `grant_entitlement`
```rust
pub fn grant_entitlement(&mut self, account: AccountId, level: EntitlementLevel) -> Result<()>
```

- **Permission**: Owner only
- **Action**: Assigns an entitlement level to an account
- **Event**: Emits `EntitlementGranted`

#### `revoke_entitlement`
```rust
pub fn revoke_entitlement(&mut self, account: AccountId) -> Result<()>
```

- **Permission**: Owner only
- **Action**: Removes entitlement (sets to `None`)
- **Event**: Emits `EntitlementRevoked`

### Queries

#### `get_entitlement`
```rust
pub fn get_entitlement(&self, account: AccountId) -> EntitlementLevel
```

Returns the current entitlement level for an account (defaults to `None` if not set).

#### `has_entitlement`
```rust
pub fn has_entitlement(&self, account: AccountId, required_level: EntitlementLevel) -> bool
```

Checks if an account meets or exceeds the required entitlement level.

**Example**:
```rust
// If account has Premium:
has_entitlement(account, Basic)    // true
has_entitlement(account, Premium)  // true
has_entitlement(account, VIP)      // false
```

#### `owner`
```rust
pub fn owner(&self) -> AccountId
```

Returns the contract owner's account ID.

## Events

### EntitlementGranted
```rust
pub struct EntitlementGranted {
    #[ink(topic)]
    account: AccountId,
    level: EntitlementLevel,
}
```

Emitted when an entitlement is granted or updated.

### EntitlementRevoked
```rust
pub struct EntitlementRevoked {
    #[ink(topic)]
    account: AccountId,
}
```

Emitted when an entitlement is removed.

## Errors

```rust
pub enum Error {
    NotOwner,              // Caller is not the contract owner
    EntitlementNotFound,   // (Currently unused)
}
```

## Building

```bash
cd contracts/access_registry
cargo contract build --release
```

**Output**: `target/ink/access_registry.{contract,wasm,json}`

## Testing

### Unit Tests

```bash
cargo test
```

**Test Coverage**:
- ✅ Constructor initialization
- ✅ Entitlement granting
- ✅ Hierarchical level checking
- ✅ Entitlement revocation

### E2E Tests

```bash
cargo test --features e2e-tests
```

## Deployment

### Using Deployer Tool

```bash
cargo run --package deployer -- \
  --endpoint ws://127.0.0.1:9944 \
  upload \
  --path contracts/access_registry/target/ink/access_registry.contract \
  --account alice
```

### Manual Deployment

```bash
cargo contract instantiate \
  --constructor new \
  --suri //Alice \
  --url ws://127.0.0.1:9944
```

## Integration

### With Payment Integration Contract

The Payment Integration contract calls `grant_entitlement` after successful payment processing:

```
Payment Completed → Access Registry → Grant Entitlement Level
```

### With Policy Engine Contract

The Policy Engine queries entitlement levels when evaluating access policies:

```
Policy Evaluation → Access Registry → Check has_entitlement() → Access Decision
```

### With OpenTDF (authnz-rs)

The authnz-rs service queries this contract to verify user entitlements during policy evaluation:

1. User requests access to protected resource
2. authnz-rs calls `get_entitlement(user_account)`
3. Returns entitlement level for policy decision

## Usage Example

```rust
// Grant Premium access to a user
access_registry.grant_entitlement(
    user_account,
    EntitlementLevel::Premium
)?;

// Check if user has at least Basic access
if access_registry.has_entitlement(user_account, EntitlementLevel::Basic) {
    // Grant access
}

// Revoke access
access_registry.revoke_entitlement(user_account)?;
```

## Security Considerations

- **Owner Control**: Only the contract owner can grant/revoke entitlements
- **Immutable Audit Trail**: All grants and revocations emit events for tracking
- **Hierarchical Safety**: Level comparison prevents privilege escalation errors
- **No Self-Grant**: Users cannot grant themselves entitlements

## Storage Layout

```
entitlements: Mapping<AccountId, EntitlementLevel>
owner: AccountId
```

**Gas Efficiency**: Single storage read for entitlement checks, single write for grants.

## License

GPL-3.0
