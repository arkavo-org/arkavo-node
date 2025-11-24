# Payment Integration Contract

Ink! smart contract for managing payment processing and entitlement grants in the Arkavo blockchain.

## Overview

The Payment Integration contract bridges external payment providers (Apple Pay, Google Pay, etc.) with the on-chain Access Registry. It records payment transactions, manages payment status, and coordinates entitlement grants upon successful payment completion.

## Payment Model

### PaymentStatus
```rust
pub enum PaymentStatus {
    Pending,    // Payment initiated, awaiting confirmation
    Completed,  // Payment confirmed, entitlement granted
    Failed,     // Payment failed, no entitlement granted
    Refunded,   // Payment refunded, entitlement revoked
}
```

### Payment Record
```rust
pub struct Payment {
    pub account: AccountId,          // User receiving entitlement
    pub payment_provider: String,    // "apple", "google", "stripe", etc.
    pub transaction_id: String,      // Provider's transaction identifier
    pub amount: Balance,             // Payment amount
    pub entitlement_granted: u8,     // Entitlement level granted (0-3)
    pub status: PaymentStatus,       // Current payment status
    pub timestamp: u64,              // Block timestamp of payment record
}
```

## Contract Functions

### Constructor

```rust
pub fn new() -> Self
```

Initializes the contract with:
- Empty payment storage
- Payment ID counter at 0
- Deployer as owner
- Owner automatically authorized as payment processor

### Configuration

#### `set_access_registry`
```rust
pub fn set_access_registry(&mut self, address: AccountId) -> Result<()>
```

- **Permission**: Owner only
- **Action**: Configures the Access Registry contract address for entitlement grants

#### `authorize_processor`
```rust
pub fn authorize_processor(&mut self, processor: AccountId) -> Result<()>
```

- **Permission**: Owner only
- **Action**: Authorizes an account to process payments
- **Event**: Emits `ProcessorAuthorized`
- **Use Case**: Authorize backend services to record and complete payments

### Payment Processing

#### `record_payment`
```rust
pub fn record_payment(
    &mut self,
    account: AccountId,
    payment_provider: String,
    transaction_id: String,
    amount: Balance,
    entitlement_granted: u8,
) -> Result<u32>
```

- **Permission**: Authorized processors only
- **Action**: Records a new payment in `Pending` status
- **Returns**: Payment ID
- **Event**: Emits `PaymentRecorded`
- **Validation**: Prevents duplicate transaction IDs

**Example**:
```rust
let payment_id = payment_integration.record_payment(
    user_account,
    "apple".to_string(),
    "txn-abc123".to_string(),
    1000, // Amount in native token units
    2,    // Premium entitlement
)?;
```

#### `complete_payment`
```rust
pub fn complete_payment(&mut self, payment_id: u32) -> Result<()>
```

- **Permission**: Authorized processors only
- **Action**: Marks payment as completed
- **Side Effect**: In full implementation, calls Access Registry to grant entitlement
- **Event**: Emits `PaymentCompleted`
- **Validation**: Only pending payments can be completed

#### `fail_payment`
```rust
pub fn fail_payment(&mut self, payment_id: u32, reason: String) -> Result<()>
```

- **Permission**: Authorized processors only
- **Action**: Marks payment as failed with reason
- **Event**: Emits `PaymentFailed`

#### `refund_payment`
```rust
pub fn refund_payment(&mut self, payment_id: u32) -> Result<()>
```

- **Permission**: Authorized processors only
- **Action**: Marks payment as refunded
- **Side Effect**: In full implementation, calls Access Registry to revoke entitlement
- **Event**: Emits `PaymentRefunded`
- **Validation**: Only completed payments can be refunded

### Queries

#### `get_payment`
```rust
pub fn get_payment(&self, payment_id: u32) -> Option<Payment>
```

- **Permission**: Public (read-only)
- **Returns**: Payment details or `None` if not found

#### `get_payment_by_transaction`
```rust
pub fn get_payment_by_transaction(&self, transaction_id: String) -> Option<u32>
```

- **Permission**: Public (read-only)
- **Returns**: Payment ID for a transaction ID (for idempotency checks)

#### `is_authorized_processor`
```rust
pub fn is_authorized_processor(&self, account: AccountId) -> bool
```

- **Permission**: Public (read-only)
- **Returns**: `true` if account is authorized to process payments

#### `owner`
```rust
pub fn owner(&self) -> AccountId
```

Returns the contract owner's account ID.

#### `next_payment_id`
```rust
pub fn next_payment_id(&self) -> u32
```

Returns the next payment ID that will be assigned.

## Events

### PaymentRecorded
```rust
pub struct PaymentRecorded {
    #[ink(topic)]
    payment_id: u32,
    #[ink(topic)]
    account: AccountId,
    payment_provider: String,
    transaction_id: String,
    amount: Balance,
}
```

### PaymentCompleted
```rust
pub struct PaymentCompleted {
    #[ink(topic)]
    payment_id: u32,
    #[ink(topic)]
    account: AccountId,
    entitlement_granted: u8,
}
```

### PaymentFailed
```rust
pub struct PaymentFailed {
    #[ink(topic)]
    payment_id: u32,
    reason: String,
}
```

### PaymentRefunded
```rust
pub struct PaymentRefunded {
    #[ink(topic)]
    payment_id: u32,
}
```

### ProcessorAuthorized
```rust
pub struct ProcessorAuthorized {
    #[ink(topic)]
    processor: AccountId,
}
```

## Errors

```rust
pub enum Error {
    NotOwner,                  // Caller is not the contract owner
    NotAuthorizedProcessor,    // Caller is not an authorized processor
    PaymentNotFound,           // Payment ID does not exist
    PaymentAlreadyExists,      // Transaction ID already recorded
    InvalidStatus,             // Payment status transition not allowed
}
```

## Building

```bash
cd contracts/payment_integration
cargo contract build --release
```

**Output**: `target/ink/payment_integration.{contract,wasm,json}`

## Testing

### Unit Tests

```bash
cargo test
```

**Test Coverage**:
- ✅ Constructor initialization with owner as processor
- ✅ Payment recording with ID assignment
- ✅ Payment completion and status transition
- ✅ Payment refund flow
- ✅ Processor authorization

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
  --path contracts/payment_integration/target/ink/payment_integration.contract \
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

```rust
// Configure Access Registry address
payment_integration.set_access_registry(access_registry_address)?;

// Authorize payment processor service
payment_integration.authorize_processor(processor_service_account)?;
```

## Integration

### Payment Flow

```
1. User initiates purchase (external system)
   ↓
2. Payment provider processes payment
   ↓
3. Backend service calls record_payment()
   ↓ (Status: Pending)
4. Payment confirmed by provider
   ↓
5. Backend service calls complete_payment()
   ↓
6. → Access Registry.grant_entitlement()
   ↓
7. User receives entitlement
```

### Refund Flow

```
1. User requests refund (external system)
   ↓
2. Backend service calls refund_payment()
   ↓
3. → Access Registry.revoke_entitlement()
   ↓
4. User entitlement removed
   ↓
5. Payment provider processes refund
```

### With Access Registry

The Payment Integration contract coordinates with Access Registry:

**On Complete**:
```rust
// Full implementation would call:
access_registry.grant_entitlement(payment.account, payment.entitlement_granted)?;
```

**On Refund**:
```rust
// Full implementation would call:
access_registry.revoke_entitlement(payment.account)?;
```

### Example Integration Code

```rust
// 1. Authorize backend processor
payment_integration.authorize_processor(backend_service)?;

// 2. Backend records payment from Apple Pay
let payment_id = payment_integration.record_payment(
    user_account,
    "apple".to_string(),
    "apple-txn-xyz789".to_string(),
    999, // $9.99 in cents
    2,   // Premium entitlement
)?;

// 3. After Apple confirms payment
payment_integration.complete_payment(payment_id)?;
// → User now has Premium entitlement in Access Registry

// 4. User requests refund
payment_integration.refund_payment(payment_id)?;
// → User entitlement revoked
```

## Security Considerations

- **Processor Authorization**: Only authorized accounts can record/process payments
- **Idempotency**: Transaction ID uniqueness prevents duplicate payment records
- **Status Transitions**: Enforced state machine prevents invalid status changes
- **Immutable Audit Trail**: All payment events recorded on-chain
- **Owner Control**: Only owner can authorize processors and configure contracts
- **Amount Storage**: Payment amounts recorded for accounting and reconciliation

## Storage Layout

```
payments: Mapping<u32, Payment>
transaction_to_payment: Mapping<String, u32>
next_payment_id: u32
owner: AccountId
access_registry: Option<AccountId>
authorized_processors: Mapping<AccountId, bool>
```

**Gas Efficiency**:
- Dual indexing (by payment ID and transaction ID) for flexible queries
- Single storage write for payment state transitions
- Processor authorization cached in storage map

## Payment Provider Integration

### Supported Providers

The contract supports any payment provider with proper backend integration:

- **Apple Pay**: In-app purchases, subscriptions
- **Google Pay**: Android in-app purchases
- **Stripe**: Web payments, recurring billing
- **PayPal**: One-time and subscription payments
- **Crypto**: Native token payments, stablecoin transfers

### Backend Service Responsibilities

The authorized processor service must:

1. Listen to payment provider webhooks
2. Verify payment authenticity with provider APIs
3. Call `record_payment()` when payment initiated
4. Call `complete_payment()` when confirmed
5. Call `fail_payment()` on payment failure
6. Handle refund requests via `refund_payment()`

## Future Enhancements

1. **Subscription Management**:
   - Recurring payment tracking
   - Automatic entitlement renewal
   - Grace periods for failed payments

2. **Price Tiers**:
   - Mapping of amount ranges to entitlement levels
   - Dynamic pricing based on market conditions

3. **Multi-Currency Support**:
   - Currency conversion tracking
   - Stablecoin payment support

4. **Dispute Resolution**:
   - Chargeback handling
   - Dispute status tracking

## License

GPL-3.0
