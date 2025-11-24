# Attribute Store Contract

Ink! smart contract for managing attribute-based access control (ABAC) attributes in the Arkavo blockchain.

## Overview

The Attribute Store provides decentralized storage for ABAC attributes using a namespace-based organization. It supports flexible authorization with three-tier write permissions: account owners, authorized writers, and contract owner. Designed for OpenTDF integration.

## Attribute Model

```rust
pub struct Attribute {
    pub namespace: String,  // e.g., "opentdf"
    pub key: String,        // e.g., "role" or "department"
    pub value: String,      // e.g., "admin" or "engineering"
}
```

**Storage Key**: Attributes are indexed by `(AccountId, namespace, key)` tuple.

**Example Attributes**:
- `(alice, "opentdf", "role") -> "admin"`
- `(alice, "opentdf", "department") -> "engineering"`
- `(bob, "custom", "clearance") -> "secret"`

## Contract Functions

### Constructor

```rust
pub fn new() -> Self
```

Initializes the contract with the deployer as the owner.

### Attribute Management

#### `set_attribute`
```rust
pub fn set_attribute(
    &mut self,
    account: AccountId,
    namespace: String,
    key: String,
    value: String,
) -> Result<()>
```

- **Permission**: Account owner, authorized writer, or contract owner
- **Action**: Sets or updates an attribute value
- **Event**: Emits `AttributeSet`

#### `remove_attribute`
```rust
pub fn remove_attribute(
    &mut self,
    account: AccountId,
    namespace: String,
    key: String,
) -> Result<()>
```

- **Permission**: Account owner, authorized writer, or contract owner
- **Action**: Deletes an attribute
- **Event**: Emits `AttributeRemoved`

#### `get_attribute`
```rust
pub fn get_attribute(
    &self,
    account: AccountId,
    namespace: String,
    key: String,
) -> Option<String>
```

- **Permission**: Public (read-only)
- **Returns**: Attribute value or `None` if not found

### Authorization Management

#### `authorize_writer`
```rust
pub fn authorize_writer(&mut self, writer: AccountId) -> Result<()>
```

- **Permission**: Account owner (caller authorizes writer for their own account)
- **Action**: Grants write permission to another account
- **Event**: Emits `WriterAuthorized`
- **Use Case**: Allow external services to manage attributes on behalf of users

#### `revoke_writer`
```rust
pub fn revoke_writer(&mut self, writer: AccountId) -> Result<()>
```

- **Permission**: Account owner
- **Action**: Removes write permission from an account
- **Event**: Emits `WriterRevoked`

#### `can_write`
```rust
pub fn can_write(&self, caller: AccountId, account: AccountId) -> bool
```

- **Permission**: Public (read-only)
- **Returns**: `true` if caller can write attributes for the account

**Authorization Logic**:
1. Contract owner can write to any account
2. Account owner can write to their own attributes
3. Authorized writers can write to accounts that authorized them

### Queries

#### `owner`
```rust
pub fn owner(&self) -> AccountId
```

Returns the contract owner's account ID.

## Events

### AttributeSet
```rust
pub struct AttributeSet {
    #[ink(topic)]
    account: AccountId,
    namespace: String,
    key: String,
    value: String,
}
```

### AttributeRemoved
```rust
pub struct AttributeRemoved {
    #[ink(topic)]
    account: AccountId,
    namespace: String,
    key: String,
}
```

### WriterAuthorized
```rust
pub struct WriterAuthorized {
    #[ink(topic)]
    account: AccountId,
    #[ink(topic)]
    writer: AccountId,
}
```

### WriterRevoked
```rust
pub struct WriterRevoked {
    #[ink(topic)]
    account: AccountId,
    #[ink(topic)]
    writer: AccountId,
}
```

## Errors

```rust
pub enum Error {
    NotAuthorized,       // Caller lacks write permission
    AttributeNotFound,   // (Currently unused)
}
```

## Building

```bash
cd contracts/attribute_store
cargo contract build --release
```

**Output**: `target/ink/attribute_store.{contract,wasm,json}`

## Testing

### Unit Tests

```bash
cargo test
```

**Test Coverage**:
- ✅ Constructor initialization
- ✅ Set and get attributes
- ✅ Remove attributes
- ✅ Authorize/revoke writers
- ✅ Write permission checks

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
  --path contracts/attribute_store/target/ink/attribute_store.contract \
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

### With Policy Engine Contract

The Policy Engine queries attributes when evaluating access policies:

```
Policy Evaluation → Attribute Store → get_attribute() → Check Required Attributes
```

**Example Policy Check**:
```rust
// Policy requires: role = "admin" and department = "engineering"
let role = attribute_store.get_attribute(user, "opentdf", "role");
let dept = attribute_store.get_attribute(user, "opentdf", "department");

if role == Some("admin") && dept == Some("engineering") {
    // Grant access
}
```

### With OpenTDF (authnz-rs)

The authnz-rs service uses attributes for fine-grained access control:

1. User requests access to protected resource
2. authnz-rs fetches user attributes from this contract
3. Evaluates policy against attributes
4. Returns access decision

### External Writer Pattern

Services can be authorized to manage user attributes:

```rust
// User authorizes an identity provider
attribute_store.authorize_writer(idp_account)?;

// IDP can now set attributes for the user
attribute_store.set_attribute(
    user_account,
    "opentdf",
    "role",
    "admin"
)?;
```

## Usage Example

```rust
// Set user attributes
attribute_store.set_attribute(
    user_account,
    "opentdf".to_string(),
    "role".to_string(),
    "admin".to_string(),
)?;

attribute_store.set_attribute(
    user_account,
    "opentdf".to_string(),
    "department".to_string(),
    "engineering".to_string(),
)?;

// Query attributes
if let Some(role) = attribute_store.get_attribute(
    user_account,
    "opentdf".to_string(),
    "role".to_string(),
) {
    println!("User role: {}", role);
}

// Authorize external service
attribute_store.authorize_writer(service_account)?;

// Remove attribute
attribute_store.remove_attribute(
    user_account,
    "opentdf".to_string(),
    "role".to_string(),
)?;
```

## Security Considerations

- **Three-Tier Authorization**: Flexible write permissions with clear hierarchy
- **Namespace Isolation**: Prevents attribute key collisions across different systems
- **Immutable Audit Trail**: All attribute changes emit events
- **Read-Only by Default**: Anyone can read, but writing requires authorization
- **No Attribute Overwrite Protection**: Last write wins (consider in authorization model)

## Storage Layout

```
attributes: Mapping<(AccountId, String, String), String>
authorized_writers: Mapping<(AccountId, AccountId), bool>
owner: AccountId
```

**Gas Efficiency**:
- Single storage read for get operations
- Single write for set operations
- Composite key indexing for efficient lookups

## OpenTDF Integration Notes

This contract implements on-chain storage for OpenTDF attributes:

- **Namespace**: Use "opentdf" for standard OpenTDF attributes
- **Attribute Format**: Store as string triplets (namespace, key, value)
- **Policy Evaluation**: authnz-rs queries this contract during authorization
- **Decentralized ABAC**: Attributes stored on-chain, immutable and auditable

## License

GPL-3.0
