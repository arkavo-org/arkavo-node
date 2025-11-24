#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod payment_integration {
    use ink::prelude::string::String;
    use ink::storage::Mapping;

    /// Payment status
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum PaymentStatus {
        Pending,
        Completed,
        Failed,
        Refunded,
    }

    /// Payment record
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Payment {
        pub account: AccountId,
        pub payment_provider: String, // "apple", "google", etc.
        pub transaction_id: String,
        pub amount: Balance,
        pub entitlement_granted: u8, // Entitlement level granted
        pub status: PaymentStatus,
        pub timestamp: u64,
    }

    /// Payment integration contract for managing payments and entitlements
    #[ink(storage)]
    pub struct PaymentIntegration {
        /// Mapping from payment ID to payment record
        payments: Mapping<u32, Payment>,
        /// Mapping from transaction ID to payment ID
        transaction_to_payment: Mapping<String, u32>,
        /// Next payment ID
        next_payment_id: u32,
        /// Contract owner
        owner: AccountId,
        /// Access registry contract address
        access_registry: Option<AccountId>,
        /// Authorized payment processors
        authorized_processors: Mapping<AccountId, bool>,
    }

    /// Events emitted by the contract
    #[ink(event)]
    pub struct PaymentRecorded {
        #[ink(topic)]
        payment_id: u32,
        #[ink(topic)]
        account: AccountId,
        payment_provider: String,
        transaction_id: String,
        amount: Balance,
    }

    #[ink(event)]
    pub struct PaymentCompleted {
        #[ink(topic)]
        payment_id: u32,
        #[ink(topic)]
        account: AccountId,
        entitlement_granted: u8,
    }

    #[ink(event)]
    pub struct PaymentFailed {
        #[ink(topic)]
        payment_id: u32,
        reason: String,
    }

    #[ink(event)]
    pub struct PaymentRefunded {
        #[ink(topic)]
        payment_id: u32,
    }

    #[ink(event)]
    pub struct ProcessorAuthorized {
        #[ink(topic)]
        processor: AccountId,
    }

    /// Errors that can occur during contract execution
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        /// Caller is not the owner
        NotOwner,
        /// Caller is not an authorized processor
        NotAuthorizedProcessor,
        /// Payment not found
        PaymentNotFound,
        /// Payment already exists
        PaymentAlreadyExists,
        /// Invalid payment status
        InvalidStatus,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl PaymentIntegration {
        /// Constructor that initializes the contract
        #[ink(constructor)]
        pub fn new() -> Self {
            let caller = Self::env().caller();
            let mut contract = Self {
                payments: Mapping::default(),
                transaction_to_payment: Mapping::default(),
                next_payment_id: 0,
                owner: caller,
                access_registry: None,
                authorized_processors: Mapping::default(),
            };
            // Owner is automatically an authorized processor
            contract.authorized_processors.insert(caller, &true);
            contract
        }

        /// Set the access registry contract address
        #[ink(message)]
        pub fn set_access_registry(&mut self, address: AccountId) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }
            self.access_registry = Some(address);
            Ok(())
        }

        /// Authorize a payment processor
        #[ink(message)]
        pub fn authorize_processor(&mut self, processor: AccountId) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            self.authorized_processors.insert(processor, &true);

            self.env().emit_event(ProcessorAuthorized { processor });

            Ok(())
        }

        /// Record a new payment (pending status)
        #[ink(message)]
        pub fn record_payment(
            &mut self,
            account: AccountId,
            payment_provider: String,
            transaction_id: String,
            amount: Balance,
            entitlement_granted: u8,
        ) -> Result<u32> {
            if !self.is_authorized_processor(self.env().caller()) {
                return Err(Error::NotAuthorizedProcessor);
            }

            // Check if transaction already exists
            if self.transaction_to_payment.contains(transaction_id.clone()) {
                return Err(Error::PaymentAlreadyExists);
            }

            let payment_id = self.next_payment_id;
            let timestamp = self.env().block_timestamp();

            let payment = Payment {
                account,
                payment_provider: payment_provider.clone(),
                transaction_id: transaction_id.clone(),
                amount,
                entitlement_granted,
                status: PaymentStatus::Pending,
                timestamp,
            };

            self.payments.insert(payment_id, &payment);
            self.transaction_to_payment.insert(transaction_id.clone(), &payment_id);
            self.next_payment_id += 1;

            self.env().emit_event(PaymentRecorded {
                payment_id,
                account,
                payment_provider,
                transaction_id,
                amount,
            });

            Ok(payment_id)
        }

        /// Complete a payment and grant entitlement
        /// In a real implementation, this would call the access_registry contract
        #[ink(message)]
        pub fn complete_payment(&mut self, payment_id: u32) -> Result<()> {
            if !self.is_authorized_processor(self.env().caller()) {
                return Err(Error::NotAuthorizedProcessor);
            }

            let mut payment = self.payments.get(payment_id).ok_or(Error::PaymentNotFound)?;

            if payment.status != PaymentStatus::Pending {
                return Err(Error::InvalidStatus);
            }

            payment.status = PaymentStatus::Completed;
            self.payments.insert(payment_id, &payment);

            // In a full implementation, this would call access_registry.grant_entitlement()
            // For now, we just emit an event

            self.env().emit_event(PaymentCompleted {
                payment_id,
                account: payment.account,
                entitlement_granted: payment.entitlement_granted,
            });

            Ok(())
        }

        /// Mark a payment as failed
        #[ink(message)]
        pub fn fail_payment(&mut self, payment_id: u32, reason: String) -> Result<()> {
            if !self.is_authorized_processor(self.env().caller()) {
                return Err(Error::NotAuthorizedProcessor);
            }

            let mut payment = self.payments.get(payment_id).ok_or(Error::PaymentNotFound)?;

            payment.status = PaymentStatus::Failed;
            self.payments.insert(payment_id, &payment);

            self.env().emit_event(PaymentFailed { payment_id, reason });

            Ok(())
        }

        /// Refund a payment
        #[ink(message)]
        pub fn refund_payment(&mut self, payment_id: u32) -> Result<()> {
            if !self.is_authorized_processor(self.env().caller()) {
                return Err(Error::NotAuthorizedProcessor);
            }

            let mut payment = self.payments.get(payment_id).ok_or(Error::PaymentNotFound)?;

            if payment.status != PaymentStatus::Completed {
                return Err(Error::InvalidStatus);
            }

            payment.status = PaymentStatus::Refunded;
            self.payments.insert(payment_id, &payment);

            // In a full implementation, this would call access_registry.revoke_entitlement()

            self.env().emit_event(PaymentRefunded { payment_id });

            Ok(())
        }

        /// Get payment details
        #[ink(message)]
        pub fn get_payment(&self, payment_id: u32) -> Option<Payment> {
            self.payments.get(payment_id)
        }

        /// Get payment ID by transaction ID
        #[ink(message)]
        pub fn get_payment_by_transaction(&self, transaction_id: String) -> Option<u32> {
            self.transaction_to_payment.get(transaction_id)
        }

        /// Check if an account is an authorized processor
        #[ink(message)]
        pub fn is_authorized_processor(&self, account: AccountId) -> bool {
            self.authorized_processors.get(account).unwrap_or(false)
        }

        /// Get the contract owner
        #[ink(message)]
        pub fn owner(&self) -> AccountId {
            self.owner
        }

        /// Get next payment ID
        #[ink(message)]
        pub fn next_payment_id(&self) -> u32 {
            self.next_payment_id
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn new_works() {
            let contract = PaymentIntegration::new();
            let owner = AccountId::from([0x01; 32]);
            assert_eq!(contract.owner(), owner);
            assert!(contract.is_authorized_processor(owner));
        }

        #[ink::test]
        fn record_payment_works() {
            let mut contract = PaymentIntegration::new();
            let account = AccountId::from([0x02; 32]);

            let payment_id = contract
                .record_payment(
                    account,
                    String::from("apple"),
                    String::from("txn-123"),
                    1000,
                    2,
                )
                .unwrap();

            assert_eq!(payment_id, 0);
            let payment = contract.get_payment(payment_id).unwrap();
            assert_eq!(payment.account, account);
            assert_eq!(payment.amount, 1000);
            assert_eq!(payment.status, PaymentStatus::Pending);
        }

        #[ink::test]
        fn complete_payment_works() {
            let mut contract = PaymentIntegration::new();
            let account = AccountId::from([0x02; 32]);

            let payment_id = contract
                .record_payment(
                    account,
                    String::from("apple"),
                    String::from("txn-123"),
                    1000,
                    2,
                )
                .unwrap();

            assert!(contract.complete_payment(payment_id).is_ok());

            let payment = contract.get_payment(payment_id).unwrap();
            assert_eq!(payment.status, PaymentStatus::Completed);
        }

        #[ink::test]
        fn refund_payment_works() {
            let mut contract = PaymentIntegration::new();
            let account = AccountId::from([0x02; 32]);

            let payment_id = contract
                .record_payment(
                    account,
                    String::from("apple"),
                    String::from("txn-123"),
                    1000,
                    2,
                )
                .unwrap();

            contract.complete_payment(payment_id).unwrap();
            assert!(contract.refund_payment(payment_id).is_ok());

            let payment = contract.get_payment(payment_id).unwrap();
            assert_eq!(payment.status, PaymentStatus::Refunded);
        }

        #[ink::test]
        fn authorize_processor_works() {
            let mut contract = PaymentIntegration::new();
            let processor = AccountId::from([0x03; 32]);

            assert!(contract.authorize_processor(processor).is_ok());
            assert!(contract.is_authorized_processor(processor));
        }
    }
}
