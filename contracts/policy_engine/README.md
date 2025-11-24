# Policy Engine Contract

Ink! smart contract for creating, managing, and evaluating access control policies in the Arkavo blockchain.

## Overview

The Policy Engine provides a decentralized policy decision point (PDP) for attribute-based access control. It defines access policies combining entitlement levels and required attributes, designed to integrate with the Access Registry and Attribute Store contracts.

## Policy Model

```rust
pub struct PolicyRule {
    pub resource_id: String,                        // Resource identifier
    pub required_attributes: Vec<(String, String)>, // Required attribute key-value pairs
    pub min_entitlement: u8,                        // Minimum entitlement level (0-3)
    pub active: bool,                               // Policy active status
}
```

**Policy Structure**:
- **Resource ID**: Identifies the protected resource (e.g., "file-123", "api-endpoint")
- **Required Attributes**: List of namespace.key -> value requirements
- **Min Entitlement**: Minimum access level from Access Registry (0=None, 1=Basic, 2=Premium, 3=VIP)
- **Active Flag**: Allows temporary policy disablement without deletion

## Contract Functions

### Constructor

```rust
pub fn new() -> Self
```

Initializes the contract with:
- Empty policy storage
- Policy ID counter at 0
- Deployer as owner
- No external contract addresses configured

### Configuration

#### `set_access_registry`
```rust
pub fn set_access_registry(&mut self, address: AccountId) -> Result<()>
```

- **Permission**: Owner only
- **Action**: Configures the Access Registry contract address for entitlement checks

#### `set_attribute_store`
```rust
pub fn set_attribute_store(&mut self, address: AccountId) -> Result<()>
```

- **Permission**: Owner only
- **Action**: Configures the Attribute Store contract address for attribute lookups

### Policy Management

#### `create_policy`
```rust
pub fn create_policy(
    &mut self,
    resource_id: String,
    required_attributes: Vec<(String, String)>,
    min_entitlement: u8,
) -> Result<u32>
```

- **Permission**: Owner only
- **Action**: Creates a new policy rule with active status
- **Returns**: Policy ID (auto-incremented)
- **Event**: Emits `PolicyCreated`

**Example**:
```rust
let policy_id = policy_engine.create_policy(
    "document-42".to_string(),
    vec![
        ("opentdf.role".to_string(), "admin".to_string()),
        ("opentdf.department".to_string(), "engineering".to_string()),
    ],
    2, // Premium level required
)?;
```

#### `update_policy`
```rust
pub fn update_policy(
    &mut self,
    policy_id: u32,
    required_attributes: Vec<(String, String)>,
    min_entitlement: u8,
    active: bool,
) -> Result<()>
```

- **Permission**: Owner only
- **Action**: Updates an existing policy's requirements and status
- **Event**: Emits `PolicyUpdated`

#### `delete_policy`
```rust
pub fn delete_policy(&mut self, policy_id: u32) -> Result<()>
```

- **Permission**: Owner only
- **Action**: Permanently removes a policy
- **Event**: Emits `PolicyDeleted`

### Policy Queries

#### `get_policy`
```rust
pub fn get_policy(&self, policy_id: u32) -> Option<PolicyRule>
```

- **Permission**: Public (read-only)
- **Returns**: Policy details or `None` if not found

#### `evaluate_access`
```rust
pub fn evaluate_access(&self, account: AccountId, policy_id: u32) -> bool
```

- **Permission**: Public
- **Action**: Evaluates if an account satisfies the policy requirements
- **Events**: Emits `AccessGranted` or `AccessDenied`

**Current Implementation**: Simplified evaluation that checks policy existence and active status. Full implementation would:
1. Query Access Registry for entitlement level
2. Query Attribute Store for required attributes
3. Compare against policy requirements

#### `owner`
```rust
pub fn owner(&self) -> AccountId
```

Returns the contract owner's account ID.

#### `next_policy_id`
```rust
pub fn next_policy_id(&self) -> u32
```

Returns the next policy ID that will be assigned.

## Events

### PolicyCreated
```rust
pub struct PolicyCreated {
    #[ink(topic)]
    policy_id: u32,
    resource_id: String,
}
```

### PolicyUpdated
```rust
pub struct PolicyUpdated {
    #[ink(topic)]
    policy_id: u32,
}
```

### PolicyDeleted
```rust
pub struct PolicyDeleted {
    #[ink(topic)]
    policy_id: u32,
}
```

### AccessGranted
```rust
pub struct AccessGranted {
    #[ink(topic)]
    account: AccountId,
    #[ink(topic)]
    policy_id: u32,
    resource_id: String,
}
```

### AccessDenied
```rust
pub struct AccessDenied {
    #[ink(topic)]
    account: AccountId,
    #[ink(topic)]
    policy_id: u32,
    resource_id: String,
    reason: String,
}
```

## Errors

```rust
pub enum Error {
    NotOwner,                // Caller is not the contract owner
    PolicyNotFound,          // Policy ID does not exist
    ContractNotConfigured,   // Access Registry or Attribute Store not configured
}
```

## Building

```bash
cd contracts/policy_engine
cargo contract build --release
```

**Output**: `target/ink/policy_engine.{contract,wasm,json}`

## Testing

### Unit Tests

```bash
cargo test
```

**Test Coverage**:
- ✅ Constructor initialization
- ✅ Policy creation with ID assignment
- ✅ Policy updates (attributes, entitlement, active status)
- ✅ Policy deletion
- ✅ Access evaluation (simplified)

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
  --path contracts/policy_engine/target/ink/policy_engine.contract \
  --account alice
```

### Manual Deployment

```bash
cargo contract instantiate \
  --constructor new \
  --suri //Alice \
  --url ws://127.0.0.1:9944
```

### Post-Deployment Configuration

After deploying all contracts, configure the external dependencies:

```rust
// Configure Access Registry
policy_engine.set_access_registry(access_registry_address)?;

// Configure Attribute Store
policy_engine.set_attribute_store(attribute_store_address)?;
```

## Integration

### Full Contract Interaction Flow

```
1. Policy Creation (Owner)
   ↓
2. Access Request (User)
   ↓
3. Policy Engine.evaluate_access()
   ↓
4. → Access Registry.has_entitlement()
   ↓
5. → Attribute Store.get_attribute() (for each required attribute)
   ↓
6. Decision: Grant or Deny
   ↓
7. Emit Event (AccessGranted/AccessDenied)
```

### With OpenTDF (authnz-rs)

The authnz-rs service uses this contract as a policy decision point:

1. User requests access to protected resource
2. authnz-rs calls `evaluate_access(user_account, policy_id)`
3. Policy Engine queries Access Registry and Attribute Store
4. Returns access decision with audit trail event

### Policy Lifecycle Example

```rust
// 1. Create policy for sensitive document
let policy_id = policy_engine.create_policy(
    "sensitive-doc-123".to_string(),
    vec![
        ("opentdf.role".to_string(), "admin".to_string()),
        ("opentdf.clearance".to_string(), "secret".to_string()),
    ],
    2, // Premium entitlement required
)?;

// 2. Evaluate access for a user
let granted = policy_engine.evaluate_access(user_account, policy_id);

// 3. Update policy to require higher entitlement
policy_engine.update_policy(
    policy_id,
    vec![("opentdf.role".to_string(), "admin".to_string())],
    3, // VIP entitlement now required
    true,
)?;

// 4. Temporarily disable policy
policy_engine.update_policy(
    policy_id,
    vec![("opentdf.role".to_string(), "admin".to_string())],
    3,
    false, // Deactivated
)?;

// 5. Delete policy when no longer needed
policy_engine.delete_policy(policy_id)?;
```

## Security Considerations

- **Owner Control**: Only owner can create/modify/delete policies
- **Immutable Audit Trail**: All policy changes and access decisions emit events
- **Policy Activation**: Inactive policies automatically deny access
- **Attribute Format**: Use "namespace.key" format for attribute requirements
- **Cross-Contract Calls**: Future implementation requires careful gas management

## Storage Layout

```
policies: Mapping<u32, PolicyRule>
next_policy_id: u32
owner: AccountId
access_registry: Option<AccountId>
attribute_store: Option<AccountId>
```

**Gas Efficiency**:
- Single storage read for policy lookup
- Policy ID auto-increment prevents collisions
- Optional external contract addresses reduce deployment dependencies

## Future Enhancements

The current implementation provides a foundation for policy management. Full implementation would include:

1. **Cross-Contract Calls**:
   - Query Access Registry for `has_entitlement(account, min_entitlement)`
   - Query Attribute Store for each required attribute match

2. **Advanced Policy Logic**:
   - Boolean operators (AND/OR) for attribute requirements
   - Time-based policies (valid from/until)
   - Resource hierarchies (wildcard matching)

3. **Delegation**:
   - Allow users to create policies for their own resources
   - Policy inheritance and override mechanisms

## License

GPL-3.0
