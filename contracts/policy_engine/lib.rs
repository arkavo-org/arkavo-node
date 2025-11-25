#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod policy_engine {
    use ink::prelude::string::String;
    use ink::prelude::vec::Vec;
    use ink::storage::Mapping;

    /// Maximum length for string inputs (`resource_id`, attribute keys/values)
    const MAX_STRING_LENGTH: usize = 256;
    /// Maximum number of required attributes in a policy
    const MAX_ATTRIBUTES: usize = 50;

    /// Policy rule for access control
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout))]
    pub struct PolicyRule {
        pub resource_id: String,
        pub required_attributes: Vec<(String, String)>, // (namespace.key, value)
        pub min_entitlement: u8,
        pub active: bool,
    }

    /// Policy engine contract for evaluating access policies
    #[ink(storage)]
    pub struct PolicyEngine {
        /// Mapping from policy ID to policy rule
        policies: Mapping<u32, PolicyRule>,
        /// Next policy ID
        next_policy_id: u32,
        /// Contract owner
        owner: Address,
        /// Access registry contract address
        access_registry: Option<Address>,
        /// Attribute store contract address
        attribute_store: Option<Address>,
    }

    /// Events emitted by the contract
    #[ink(event)]
    pub struct PolicyCreated {
        #[ink(topic)]
        policy_id: u32,
        resource_id: String,
    }

    #[ink(event)]
    pub struct PolicyUpdated {
        #[ink(topic)]
        policy_id: u32,
    }

    #[ink(event)]
    pub struct PolicyDeleted {
        #[ink(topic)]
        policy_id: u32,
    }

    #[ink(event)]
    pub struct AccessGranted {
        #[ink(topic)]
        account: Address,
        #[ink(topic)]
        policy_id: u32,
        resource_id: String,
    }

    #[ink(event)]
    pub struct AccessDenied {
        #[ink(topic)]
        account: Address,
        #[ink(topic)]
        policy_id: u32,
        resource_id: String,
        reason: String,
    }

    /// Errors that can occur during contract execution
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        /// Caller is not the owner
        NotOwner,
        /// Policy not found
        PolicyNotFound,
        /// External contract not configured
        ContractNotConfigured,
        /// Input string exceeds maximum length
        InputTooLong,
        /// Too many attributes in policy
        TooManyAttributes,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Default for PolicyEngine {
        fn default() -> Self {
            Self::new()
        }
    }

    impl PolicyEngine {
        /// Constructor that initializes the contract
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                policies: Mapping::default(),
                next_policy_id: 0,
                owner: Self::env().caller(),
                access_registry: None,
                attribute_store: None,
            }
        }

        /// Set the access registry contract address
        #[ink(message)]
        pub fn set_access_registry(&mut self, address: Address) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }
            self.access_registry = Some(address);
            Ok(())
        }

        /// Set the attribute store contract address
        #[ink(message)]
        pub fn set_attribute_store(&mut self, address: Address) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }
            self.attribute_store = Some(address);
            Ok(())
        }

        /// Create a new policy
        #[ink(message)]
        pub fn create_policy(
            &mut self,
            resource_id: String,
            required_attributes: Vec<(String, String)>,
            min_entitlement: u8,
        ) -> Result<u32> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            // Validate input lengths
            if resource_id.len() > MAX_STRING_LENGTH {
                return Err(Error::InputTooLong);
            }

            if required_attributes.len() > MAX_ATTRIBUTES {
                return Err(Error::TooManyAttributes);
            }

            // Validate each attribute tuple
            for (key, value) in &required_attributes {
                if key.len() > MAX_STRING_LENGTH || value.len() > MAX_STRING_LENGTH {
                    return Err(Error::InputTooLong);
                }
            }

            let policy_id = self.next_policy_id;
            let policy = PolicyRule {
                resource_id: resource_id.clone(),
                required_attributes,
                min_entitlement,
                active: true,
            };

            self.policies.insert(policy_id, &policy);
            self.next_policy_id += 1;

            self.env().emit_event(PolicyCreated {
                policy_id,
                resource_id,
            });

            Ok(policy_id)
        }

        /// Update an existing policy
        #[ink(message)]
        pub fn update_policy(
            &mut self,
            policy_id: u32,
            required_attributes: Vec<(String, String)>,
            min_entitlement: u8,
            active: bool,
        ) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            // Validate input lengths
            if required_attributes.len() > MAX_ATTRIBUTES {
                return Err(Error::TooManyAttributes);
            }

            // Validate each attribute tuple
            for (key, value) in &required_attributes {
                if key.len() > MAX_STRING_LENGTH || value.len() > MAX_STRING_LENGTH {
                    return Err(Error::InputTooLong);
                }
            }

            let mut policy = self.policies.get(policy_id).ok_or(Error::PolicyNotFound)?;
            policy.required_attributes = required_attributes;
            policy.min_entitlement = min_entitlement;
            policy.active = active;

            self.policies.insert(policy_id, &policy);

            self.env().emit_event(PolicyUpdated { policy_id });

            Ok(())
        }

        /// Delete a policy
        #[ink(message)]
        pub fn delete_policy(&mut self, policy_id: u32) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            self.policies.remove(policy_id);

            self.env().emit_event(PolicyDeleted { policy_id });

            Ok(())
        }

        /// Get a policy
        #[ink(message)]
        pub fn get_policy(&self, policy_id: u32) -> Option<PolicyRule> {
            self.policies.get(policy_id)
        }

        /// Evaluate access for an account against a policy
        /// Note: In a real implementation, this would call the `access_registry`
        /// and `attribute_store` contracts. For now, it's a simplified version.
        #[ink(message)]
        pub fn evaluate_access(&self, account: Address, policy_id: u32) -> bool {
            if let Some(policy) = self.policies.get(policy_id) {
                if !policy.active {
                    self.env().emit_event(AccessDenied {
                        account,
                        policy_id,
                        resource_id: policy.resource_id.clone(),
                        reason: String::from("Policy inactive"),
                    });
                    return false;
                }

                // In a full implementation, this would:
                // 1. Call access_registry to check entitlement level
                // 2. Call attribute_store to verify required attributes
                // For now, we just emit an event

                self.env().emit_event(AccessGranted {
                    account,
                    policy_id,
                    resource_id: policy.resource_id,
                });
                true
            } else {
                false
            }
        }

        /// Get the contract owner
        #[ink(message)]
        pub fn owner(&self) -> Address {
            self.owner
        }

        /// Get next policy ID
        #[ink(message)]
        pub fn next_policy_id(&self) -> u32 {
            self.next_policy_id
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn new_works() {
            let contract = PolicyEngine::new();
            // Owner should be the caller (default test caller)
            assert_eq!(contract.next_policy_id(), 0);
        }

        #[ink::test]
        fn create_policy_works() {
            let mut contract = PolicyEngine::new();
            let resource_id = String::from("resource-123");
            let required_attributes = ink::prelude::vec![
                (String::from("opentdf.role"), String::from("admin")),
            ];

            let policy_id = contract
                .create_policy(resource_id.clone(), required_attributes.clone(), 2)
                .unwrap();

            assert_eq!(policy_id, 0);
            let policy = contract.get_policy(policy_id).unwrap();
            assert_eq!(policy.resource_id, resource_id);
            assert_eq!(policy.min_entitlement, 2);
            assert!(policy.active);
        }

        #[ink::test]
        fn update_policy_works() {
            let mut contract = PolicyEngine::new();
            let policy_id = contract
                .create_policy(
                    String::from("resource-123"),
                    ink::prelude::vec![],
                    1,
                )
                .unwrap();

            let new_attributes = ink::prelude::vec![
                (String::from("opentdf.department"), String::from("engineering")),
            ];

            assert!(contract
                .update_policy(policy_id, new_attributes.clone(), 3, false)
                .is_ok());

            let policy = contract.get_policy(policy_id).unwrap();
            assert_eq!(policy.min_entitlement, 3);
            assert!(!policy.active);
        }

        #[ink::test]
        fn delete_policy_works() {
            let mut contract = PolicyEngine::new();
            let policy_id = contract
                .create_policy(
                    String::from("resource-123"),
                    ink::prelude::vec![],
                    1,
                )
                .unwrap();

            assert!(contract.delete_policy(policy_id).is_ok());
            assert!(contract.get_policy(policy_id).is_none());
        }

        #[ink::test]
        fn evaluate_access_works() {
            let mut contract = PolicyEngine::new();
            let account = Address::from([0x02; 20]);
            let policy_id = contract
                .create_policy(
                    String::from("resource-123"),
                    ink::prelude::vec![],
                    1,
                )
                .unwrap();

            assert!(contract.evaluate_access(account, policy_id));
        }
    }
}
