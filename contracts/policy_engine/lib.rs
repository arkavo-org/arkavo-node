#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod policy_engine {
    use ink::prelude::string::String;
    use ink::prelude::vec::Vec;
    use ink::storage::Mapping;
    use ink::U256;

    /// Maximum length for string inputs (`resource_id`, attribute keys/values)
    const MAX_STRING_LENGTH: usize = 256;
    /// Maximum number of required attributes in a policy
    const MAX_ATTRIBUTES: usize = 50;

    /// Ink! selector for `access_registry.has_entitlement(account, level)`
    /// Computed as blake2b_256(b"has_entitlement")[0..4]
    const SELECTOR_HAS_ENTITLEMENT: [u8; 4] = [0xc6, 0x39, 0x10, 0x1c];
    /// Ink! selector for `attribute_store.get_attribute(account, namespace, key)`
    /// Computed as blake2b_256(b"get_attribute")[0..4]
    const SELECTOR_GET_ATTRIBUTE: [u8; 4] = [0x97, 0xf8, 0x6d, 0xa4];

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
        /// Reverse index: resource_id → policy_id
        resource_to_policy: Mapping<String, u32>,
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
        /// A resource_id already has a policy bound to it
        ResourceAlreadyBound,
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
                resource_to_policy: Mapping::default(),
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

        /// Create a new policy bound to a resource_id
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

            if resource_id.len() > MAX_STRING_LENGTH {
                return Err(Error::InputTooLong);
            }

            if required_attributes.len() > MAX_ATTRIBUTES {
                return Err(Error::TooManyAttributes);
            }

            for (key, value) in &required_attributes {
                if key.len() > MAX_STRING_LENGTH || value.len() > MAX_STRING_LENGTH {
                    return Err(Error::InputTooLong);
                }
            }

            // Prevent duplicate resource bindings
            if self.resource_to_policy.get(&resource_id).is_some() {
                return Err(Error::ResourceAlreadyBound);
            }

            let policy_id = self.next_policy_id;
            let policy = PolicyRule {
                resource_id: resource_id.clone(),
                required_attributes,
                min_entitlement,
                active: true,
            };

            self.policies.insert(policy_id, &policy);
            self.resource_to_policy.insert(&resource_id, &policy_id);
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

            if required_attributes.len() > MAX_ATTRIBUTES {
                return Err(Error::TooManyAttributes);
            }

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

        /// Delete a policy and remove its resource binding
        #[ink(message)]
        pub fn delete_policy(&mut self, policy_id: u32) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            // Remove the reverse index entry
            if let Some(policy) = self.policies.get(policy_id) {
                self.resource_to_policy.remove(&policy.resource_id);
            }

            self.policies.remove(policy_id);

            self.env().emit_event(PolicyDeleted { policy_id });

            Ok(())
        }

        /// Get a policy by ID
        #[ink(message)]
        pub fn get_policy(&self, policy_id: u32) -> Option<PolicyRule> {
            self.policies.get(policy_id)
        }

        /// Look up a policy ID by resource_id
        #[ink(message)]
        pub fn get_policy_by_resource(&self, resource_id: String) -> Option<u32> {
            self.resource_to_policy.get(&resource_id)
        }

        /// Evaluate access for an account against a policy.
        ///
        /// Performs cross-contract calls to:
        /// - `access_registry.has_entitlement(account, min_level)` for entitlement check
        /// - `attribute_store.get_attribute(account, namespace, key)` for each required attribute
        #[ink(message)]
        pub fn evaluate_access(&self, account: Address, policy_id: u32) -> bool {
            let Some(policy) = self.policies.get(policy_id) else {
                return false;
            };

            if !policy.active {
                self.env().emit_event(AccessDenied {
                    account,
                    policy_id,
                    resource_id: policy.resource_id,
                    reason: String::from("Policy inactive"),
                });
                return false;
            }

            // Verify both contracts are configured
            if self.access_registry.is_none() || self.attribute_store.is_none() {
                self.env().emit_event(AccessDenied {
                    account,
                    policy_id,
                    resource_id: policy.resource_id,
                    reason: String::from("Contracts not configured"),
                });
                return false;
            }

            // Check entitlement level via access_registry
            if !self.check_entitlement(account, policy.min_entitlement) {
                self.env().emit_event(AccessDenied {
                    account,
                    policy_id,
                    resource_id: policy.resource_id,
                    reason: String::from("Insufficient entitlement"),
                });
                return false;
            }

            // Check each required attribute via attribute_store
            for (attr_key, attr_val) in &policy.required_attributes {
                if !self.check_attribute(account, attr_key, attr_val) {
                    self.env().emit_event(AccessDenied {
                        account,
                        policy_id,
                        resource_id: policy.resource_id.clone(),
                        reason: ink::prelude::format!("Missing attribute: {}", attr_key),
                    });
                    return false;
                }
            }

            self.env().emit_event(AccessGranted {
                account,
                policy_id,
                resource_id: policy.resource_id,
            });
            true
        }

        /// Evaluate access by resource_id instead of policy_id.
        /// This is the primary entry point for KAS/PDP checks.
        #[ink(message)]
        pub fn evaluate_access_by_resource(
            &self,
            account: Address,
            resource_id: String,
        ) -> bool {
            match self.resource_to_policy.get(&resource_id) {
                Some(policy_id) => self.evaluate_access(account, policy_id),
                None => false,
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

        // --- Cross-contract call helpers ---

        /// Call access_registry.has_entitlement(account, required_level) -> bool
        fn check_entitlement(&self, account: Address, min_level: u8) -> bool {
            let Some(registry_addr) = self.access_registry else {
                return false;
            };

            let result = ink::env::call::build_call::<ink::env::DefaultEnvironment>()
                .call(registry_addr)
                .transferred_value(U256::from(0))
                .exec_input(
                    ink::env::call::ExecutionInput::new(
                        ink::env::call::Selector::new(SELECTOR_HAS_ENTITLEMENT),
                    )
                    .push_arg(account)
                    .push_arg(min_level),
                )
                .returns::<bool>()
                .try_invoke();

            match result {
                Ok(Ok(val)) => val,
                _ => false,
            }
        }

        /// Call attribute_store.get_attribute(account, namespace, key) -> Option<String>
        /// and compare against expected_value.
        /// The attr_key format is "namespace.key" (e.g. "opentdf.role").
        fn check_attribute(
            &self,
            account: Address,
            attr_key: &str,
            expected_value: &str,
        ) -> bool {
            let Some(store_addr) = self.attribute_store else {
                return false;
            };

            // Split "namespace.key" into (namespace, key)
            let Some((namespace, key)) = attr_key.split_once('.') else {
                return false;
            };

            let result = ink::env::call::build_call::<ink::env::DefaultEnvironment>()
                .call(store_addr)
                .transferred_value(U256::from(0))
                .exec_input(
                    ink::env::call::ExecutionInput::new(
                        ink::env::call::Selector::new(SELECTOR_GET_ATTRIBUTE),
                    )
                    .push_arg(account)
                    .push_arg(String::from(namespace))
                    .push_arg(String::from(key)),
                )
                .returns::<Option<String>>()
                .try_invoke();

            match result {
                Ok(Ok(Some(val))) => val == expected_value,
                _ => false,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn new_works() {
            let contract = PolicyEngine::new();
            assert_eq!(contract.owner(), Address::default());
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
        fn create_policy_sets_resource_index() {
            let mut contract = PolicyEngine::new();
            let resource_id = String::from("letter-abc-123");

            let policy_id = contract
                .create_policy(resource_id.clone(), ink::prelude::vec![], 1)
                .unwrap();

            assert_eq!(contract.get_policy_by_resource(resource_id), Some(policy_id));
        }

        #[ink::test]
        fn create_policy_rejects_duplicate_resource() {
            let mut contract = PolicyEngine::new();
            let resource_id = String::from("letter-abc-123");

            contract
                .create_policy(resource_id.clone(), ink::prelude::vec![], 1)
                .unwrap();

            let result = contract.create_policy(resource_id, ink::prelude::vec![], 2);
            assert_eq!(result, Err(Error::ResourceAlreadyBound));
        }

        #[ink::test]
        fn delete_policy_removes_resource_index() {
            let mut contract = PolicyEngine::new();
            let resource_id = String::from("letter-abc-123");

            let policy_id = contract
                .create_policy(resource_id.clone(), ink::prelude::vec![], 1)
                .unwrap();

            contract.delete_policy(policy_id).unwrap();
            assert!(contract.get_policy_by_resource(resource_id).is_none());
            assert!(contract.get_policy(policy_id).is_none());
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
        fn evaluate_access_denies_when_contracts_not_configured() {
            let mut contract = PolicyEngine::new();
            let account = Address::from([0x02; 20]);
            let policy_id = contract
                .create_policy(
                    String::from("resource-123"),
                    ink::prelude::vec![],
                    1,
                )
                .unwrap();

            // Without access_registry and attribute_store configured, access is denied
            assert!(!contract.evaluate_access(account, policy_id));
        }

        #[ink::test]
        fn evaluate_access_denies_inactive_policy() {
            let mut contract = PolicyEngine::new();
            let account = Address::from([0x02; 20]);
            let policy_id = contract
                .create_policy(
                    String::from("resource-123"),
                    ink::prelude::vec![],
                    1,
                )
                .unwrap();

            contract
                .update_policy(policy_id, ink::prelude::vec![], 1, false)
                .unwrap();

            assert!(!contract.evaluate_access(account, policy_id));
        }

        #[ink::test]
        fn evaluate_access_by_resource_returns_false_for_unknown() {
            let contract = PolicyEngine::new();
            let account = Address::from([0x02; 20]);

            assert!(!contract.evaluate_access_by_resource(account, String::from("unknown")));
        }

        #[ink::test]
        fn selector_has_entitlement_is_correct() {
            let mut output = [0u8; 32];
            ink::env::hash_bytes::<ink::env::hash::Blake2x256>(
                b"has_entitlement",
                &mut output,
            );
            assert_eq!(
                &output[0..4],
                &SELECTOR_HAS_ENTITLEMENT,
                "has_entitlement selector mismatch"
            );
        }

        #[ink::test]
        fn selector_get_attribute_is_correct() {
            let mut output = [0u8; 32];
            ink::env::hash_bytes::<ink::env::hash::Blake2x256>(
                b"get_attribute",
                &mut output,
            );
            assert_eq!(
                &output[0..4],
                &SELECTOR_GET_ATTRIBUTE,
                "get_attribute selector mismatch"
            );
        }
    }
}
