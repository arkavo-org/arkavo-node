#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod access_registry {
    use ink::storage::Mapping;

    /// Defines entitlement levels for access control
    #[derive(Default, Debug, PartialEq, Eq, Clone, Copy, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub enum EntitlementLevel {
        #[default]
        None,
        Basic,
        Premium,
        Vip,
    }

    /// Session grant for chain-driven access control.
    ///
    /// Represents an access session issued by the blockchain. Agents must
    /// possess the ephemeral private key corresponding to `eph_pub_key`
    /// to prove ownership of the session.
    #[derive(Default, Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct SessionGrant {
        /// Ephemeral public key (33 bytes compressed EC point).
        /// The agent signs requests with the corresponding private key.
        pub eph_pub_key: ink::prelude::vec::Vec<u8>,
        /// Resource scope identifier (32 bytes hash).
        /// Defines what resources this session can access.
        pub scope_id: [u8; 32],
        /// Block number when this session expires.
        pub expires_at_block: u64,
        /// Whether this session has been revoked on-chain.
        pub is_revoked: bool,
        /// Block number when this session was created.
        pub created_at_block: u64,
    }

    /// Merkle proof for an attribute.
    ///
    /// Used to prove possession of an attribute without revealing all attributes.
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct AttributeProof {
        /// Attribute hash: H(namespace | name | value | salt)
        pub attribute_hash: [u8; 32],
        /// Merkle proof path (sibling hashes from leaf to root)
        pub proof_path: ink::prelude::vec::Vec<[u8; 32]>,
        /// Position indicators (0 = left, 1 = right) for each level
        pub proof_indices: ink::prelude::vec::Vec<u8>,
    }

    /// Scope requirement definition.
    ///
    /// Defines what attributes are required to access a particular scope.
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct ScopeRequirement {
        /// Required attribute hashes for this scope
        pub required_attributes: ink::prelude::vec::Vec<[u8; 32]>,
        /// Whether this scope is active
        pub active: bool,
    }

    /// Access registry contract for managing entitlements
    #[ink(storage)]
    pub struct AccessRegistry {
        /// Mapping from account to their entitlement level
        entitlements: Mapping<Address, EntitlementLevel>,
        /// Mapping from session ID to session grant
        sessions: Mapping<[u8; 32], SessionGrant>,
        /// Contract owner who can grant/revoke entitlements
        owner: Address,
        /// Reference to `attribute_store` contract for Merkle root lookups
        attribute_store: Option<Address>,
        /// Scope requirements: `scope_id` -> required attribute hashes
        scope_requirements: Mapping<[u8; 32], ScopeRequirement>,
    }

    /// Events emitted by the contract
    #[ink(event)]
    pub struct EntitlementGranted {
        #[ink(topic)]
        account: Address,
        level: EntitlementLevel,
    }

    #[ink(event)]
    pub struct EntitlementRevoked {
        #[ink(topic)]
        account: Address,
    }

    #[ink(event)]
    pub struct SessionCreated {
        #[ink(topic)]
        session_id: [u8; 32],
        expires_at_block: u64,
    }

    #[ink(event)]
    pub struct SessionRevoked {
        #[ink(topic)]
        session_id: [u8; 32],
    }

    #[ink(event)]
    pub struct SessionRequested {
        #[ink(topic)]
        session_id: [u8; 32],
        #[ink(topic)]
        requester: Address,
        scope_id: [u8; 32],
        expires_at_block: u64,
    }

    #[ink(event)]
    pub struct ScopeRequirementSet {
        #[ink(topic)]
        scope_id: [u8; 32],
    }

    /// Errors that can occur during contract execution
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        /// Caller is not the owner
        NotOwner,
        /// Entitlement not found
        EntitlementNotFound,
        /// Session not found
        SessionNotFound,
        /// Attribute store contract not configured
        AttributeStoreNotConfigured,
        /// Merkle root not found for account
        RootNotFound,
        /// Invalid Merkle proof
        InvalidProof,
        /// Missing required attribute proof
        MissingRequiredAttribute,
        /// Scope not found
        ScopeNotFound,
        /// Scope is inactive
        ScopeInactive,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Default for AccessRegistry {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AccessRegistry {
        /// Constructor that initializes the contract
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                entitlements: Mapping::default(),
                sessions: Mapping::default(),
                owner: Self::env().caller(),
                attribute_store: None,
                scope_requirements: Mapping::default(),
            }
        }

        /// Grant an entitlement to an account
        #[ink(message)]
        pub fn grant_entitlement(
            &mut self,
            account: Address,
            level: EntitlementLevel,
        ) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            self.entitlements.insert(account, &level);

            self.env().emit_event(EntitlementGranted { account, level });

            Ok(())
        }

        /// Revoke an entitlement from an account
        #[ink(message)]
        pub fn revoke_entitlement(&mut self, account: Address) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            self.entitlements.remove(account);

            self.env().emit_event(EntitlementRevoked { account });

            Ok(())
        }

        /// Check the entitlement level of an account
        #[ink(message)]
        pub fn get_entitlement(&self, account: Address) -> EntitlementLevel {
            self.entitlements.get(account).unwrap_or_default()
        }

        /// Check if an account has at least a specific entitlement level
        #[ink(message)]
        pub fn has_entitlement(&self, account: Address, required_level: EntitlementLevel) -> bool {
            let current_level = self.get_entitlement(account);
            Self::level_value(current_level) >= Self::level_value(required_level)
        }

        /// Get the contract owner
        #[ink(message)]
        pub fn owner(&self) -> Address {
            self.owner
        }

        /// Helper function to convert entitlement level to numeric value for comparison
        fn level_value(level: EntitlementLevel) -> u8 {
            match level {
                EntitlementLevel::None => 0,
                EntitlementLevel::Basic => 1,
                EntitlementLevel::Premium => 2,
                EntitlementLevel::Vip => 3,
            }
        }

        /// Create a new session grant.
        ///
        /// Only the contract owner can create sessions.
        #[ink(message)]
        pub fn create_session(
            &mut self,
            session_id: [u8; 32],
            eph_pub_key: ink::prelude::vec::Vec<u8>,
            scope_id: [u8; 32],
            expires_at_block: u64,
        ) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            let grant = SessionGrant {
                eph_pub_key,
                scope_id,
                expires_at_block,
                is_revoked: false,
                created_at_block: u64::from(self.env().block_number()),
            };

            self.sessions.insert(session_id, &grant);

            self.env().emit_event(SessionCreated {
                session_id,
                expires_at_block,
            });

            Ok(())
        }

        /// Get a session grant by session ID.
        #[ink(message)]
        pub fn get_session(&self, session_id: [u8; 32]) -> Option<SessionGrant> {
            self.sessions.get(session_id)
        }

        /// Revoke a session grant.
        ///
        /// Only the contract owner can revoke sessions.
        #[ink(message)]
        pub fn revoke_session(&mut self, session_id: [u8; 32]) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            if let Some(mut grant) = self.sessions.get(session_id) {
                grant.is_revoked = true;
                self.sessions.insert(session_id, &grant);

                self.env().emit_event(SessionRevoked { session_id });

                Ok(())
            } else {
                Err(Error::SessionNotFound)
            }
        }

        /// Set the `attribute_store` contract address.
        ///
        /// Only the contract owner can configure this.
        #[ink(message)]
        pub fn set_attribute_store(&mut self, address: Address) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }
            self.attribute_store = Some(address);
            Ok(())
        }

        /// Get the `attribute_store` contract address.
        #[ink(message)]
        pub fn get_attribute_store(&self) -> Option<Address> {
            self.attribute_store
        }

        /// Set scope requirements.
        ///
        /// Only the contract owner can define scope requirements.
        #[ink(message)]
        pub fn set_scope_requirement(
            &mut self,
            scope_id: [u8; 32],
            required_attributes: ink::prelude::vec::Vec<[u8; 32]>,
            active: bool,
        ) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            let requirement = ScopeRequirement {
                required_attributes,
                active,
            };
            self.scope_requirements.insert(scope_id, &requirement);

            self.env().emit_event(ScopeRequirementSet { scope_id });

            Ok(())
        }

        /// Get scope requirements.
        #[ink(message)]
        pub fn get_scope_requirement(&self, scope_id: [u8; 32]) -> Option<ScopeRequirement> {
            self.scope_requirements.get(scope_id)
        }

        /// Request a session by proving attributes via Merkle proofs.
        ///
        /// The caller provides their attribute root and proofs. The contract:
        /// 1. Verifies `attribute_store` is configured
        /// 2. Validates each proof against the provided root
        /// 3. Checks all required attributes for the scope are proven
        /// 4. Creates and returns the session
        ///
        /// Note: In a full implementation, the root would be fetched via
        /// cross-contract call to `attribute_store.get_root(caller)`.
        #[ink(message)]
        #[allow(clippy::needless_pass_by_value)]
        pub fn request_session(
            &mut self,
            eph_pub_key: ink::prelude::vec::Vec<u8>,
            scope_id: [u8; 32],
            duration_blocks: u64,
            proofs: ink::prelude::vec::Vec<AttributeProof>,
            root: [u8; 32],
        ) -> Result<[u8; 32]> {
            let caller = self.env().caller();

            // Verify attribute_store is configured
            let _attribute_store = self
                .attribute_store
                .ok_or(Error::AttributeStoreNotConfigured)?;

            // TODO: Cross-contract call to attribute_store.get_root(caller)
            // For now, we accept the root parameter
            // In production: verify root matches stored root

            // Get scope requirements
            let requirement = self
                .scope_requirements
                .get(scope_id)
                .ok_or(Error::ScopeNotFound)?;

            if !requirement.active {
                return Err(Error::ScopeInactive);
            }

            // Verify each required attribute has a valid proof
            for required_hash in &requirement.required_attributes {
                let proof = proofs
                    .iter()
                    .find(|p| &p.attribute_hash == required_hash)
                    .ok_or(Error::MissingRequiredAttribute)?;

                if !Self::verify_merkle_proof(
                    &proof.attribute_hash,
                    &proof.proof_path,
                    &proof.proof_indices,
                    &root,
                ) {
                    return Err(Error::InvalidProof);
                }
            }

            // Generate session ID from caller + scope + block
            let session_id = self.compute_session_id(&caller, &scope_id);

            let expires_at_block = u64::from(self.env().block_number()) + duration_blocks;

            let grant = SessionGrant {
                eph_pub_key,
                scope_id,
                expires_at_block,
                is_revoked: false,
                created_at_block: u64::from(self.env().block_number()),
            };

            self.sessions.insert(session_id, &grant);

            self.env().emit_event(SessionRequested {
                session_id,
                requester: caller,
                scope_id,
                expires_at_block,
            });

            Ok(session_id)
        }

        /// Verify a Merkle proof.
        ///
        /// Returns true if the proof path from leaf to root is valid.
        fn verify_merkle_proof(
            leaf: &[u8; 32],
            proof_path: &[[u8; 32]],
            proof_indices: &[u8],
            root: &[u8; 32],
        ) -> bool {
            use ink::env::hash::{Blake2x256, HashOutput};

            if proof_path.len() != proof_indices.len() {
                return false;
            }

            let mut current = *leaf;

            for (sibling, &index) in proof_path.iter().zip(proof_indices.iter()) {
                let mut input = [0u8; 64];
                if index == 0 {
                    // Current is on the left
                    input[..32].copy_from_slice(&current);
                    input[32..].copy_from_slice(sibling);
                } else {
                    // Current is on the right
                    input[..32].copy_from_slice(sibling);
                    input[32..].copy_from_slice(&current);
                }

                let mut output = <Blake2x256 as HashOutput>::Type::default();
                ink::env::hash_bytes::<Blake2x256>(&input, &mut output);
                current = output;
            }

            current == *root
        }

        /// Compute session ID from caller, scope, and block number.
        fn compute_session_id(&self, caller: &Address, scope_id: &[u8; 32]) -> [u8; 32] {
            use ink::env::hash::{Blake2x256, HashOutput};

            let mut input = ink::prelude::vec::Vec::new();
            input.extend_from_slice(caller.as_ref());
            input.extend_from_slice(scope_id);
            input.extend_from_slice(&self.env().block_number().to_le_bytes());

            let mut output = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_bytes::<Blake2x256>(&input, &mut output);
            output
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn new_works() {
            let contract = AccessRegistry::new();
            // Owner is set to the default caller (zero address in test env)
            assert_eq!(contract.owner(), Address::default());
        }

        #[ink::test]
        fn grant_entitlement_works() {
            let mut contract = AccessRegistry::new();
            let account = Address::from([0x02; 20]);

            assert!(
                contract
                    .grant_entitlement(account, EntitlementLevel::Vip)
                    .is_ok()
            );
            assert_eq!(contract.get_entitlement(account), EntitlementLevel::Vip);
        }

        #[ink::test]
        fn has_entitlement_works() {
            let mut contract = AccessRegistry::new();
            let account = Address::from([0x02; 20]);

            contract
                .grant_entitlement(account, EntitlementLevel::Premium)
                .unwrap();

            assert!(contract.has_entitlement(account, EntitlementLevel::Basic));
            assert!(contract.has_entitlement(account, EntitlementLevel::Premium));
            assert!(!contract.has_entitlement(account, EntitlementLevel::Vip));
        }

        #[ink::test]
        fn revoke_entitlement_works() {
            let mut contract = AccessRegistry::new();
            let account = Address::from([0x02; 20]);

            contract
                .grant_entitlement(account, EntitlementLevel::Vip)
                .unwrap();
            assert!(contract.revoke_entitlement(account).is_ok());
            assert_eq!(contract.get_entitlement(account), EntitlementLevel::None);
        }

        #[ink::test]
        fn create_session_works() {
            let mut contract = AccessRegistry::new();
            let session_id = [0x01u8; 32];
            let eph_pub_key = ink::prelude::vec![0x02u8; 33];
            let scope_id = [0x03u8; 32];
            let expires_at_block = 1000u64;

            assert!(
                contract
                    .create_session(session_id, eph_pub_key.clone(), scope_id, expires_at_block)
                    .is_ok()
            );

            let grant = contract.get_session(session_id);
            assert!(grant.is_some());
            let grant = grant.unwrap();
            assert_eq!(grant.eph_pub_key, eph_pub_key);
            assert_eq!(grant.scope_id, scope_id);
            assert_eq!(grant.expires_at_block, expires_at_block);
            assert!(!grant.is_revoked);
        }

        #[ink::test]
        fn get_session_returns_none_for_unknown() {
            let contract = AccessRegistry::new();
            let session_id = [0x99u8; 32];
            assert!(contract.get_session(session_id).is_none());
        }

        #[ink::test]
        fn revoke_session_works() {
            let mut contract = AccessRegistry::new();
            let session_id = [0x01u8; 32];
            let eph_pub_key = ink::prelude::vec![0x02u8; 33];
            let scope_id = [0x03u8; 32];
            let expires_at_block = 1000u64;

            contract
                .create_session(session_id, eph_pub_key, scope_id, expires_at_block)
                .unwrap();

            assert!(contract.revoke_session(session_id).is_ok());

            let grant = contract.get_session(session_id).unwrap();
            assert!(grant.is_revoked);
        }

        #[ink::test]
        fn revoke_session_fails_for_unknown() {
            let mut contract = AccessRegistry::new();
            let session_id = [0x99u8; 32];
            assert_eq!(
                contract.revoke_session(session_id),
                Err(Error::SessionNotFound)
            );
        }

        #[ink::test]
        fn set_attribute_store_works() {
            let mut contract = AccessRegistry::new();
            let address = Address::from([0x01; 20]);
            assert!(contract.set_attribute_store(address).is_ok());
            assert_eq!(contract.get_attribute_store(), Some(address));
        }

        #[ink::test]
        fn set_scope_requirement_works() {
            let mut contract = AccessRegistry::new();
            let scope_id = [0x01u8; 32];
            let required = ink::prelude::vec![[0xABu8; 32], [0xCDu8; 32]];

            assert!(
                contract
                    .set_scope_requirement(scope_id, required.clone(), true)
                    .is_ok()
            );

            let req = contract.get_scope_requirement(scope_id).unwrap();
            assert_eq!(req.required_attributes, required);
            assert!(req.active);
        }

        #[ink::test]
        fn verify_merkle_proof_works() {
            // Build a simple 2-leaf Merkle tree
            // Leaves: [A, B]
            // Root: H(A || B)
            use ink::env::hash::{Blake2x256, HashOutput};

            let leaf_a = [0x01u8; 32];
            let leaf_b = [0x02u8; 32];

            // Compute root = H(leaf_a || leaf_b)
            let mut root_input = [0u8; 64];
            root_input[..32].copy_from_slice(&leaf_a);
            root_input[32..].copy_from_slice(&leaf_b);
            let mut root = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_bytes::<Blake2x256>(&root_input, &mut root);

            // Proof for leaf_a: sibling is leaf_b, index 0 (left)
            let proof_path = ink::prelude::vec![leaf_b];
            let proof_indices = ink::prelude::vec![0u8];

            assert!(AccessRegistry::verify_merkle_proof(
                &leaf_a,
                &proof_path,
                &proof_indices,
                &root
            ));

            // Invalid proof should fail
            let wrong_leaf = [0x99u8; 32];
            assert!(!AccessRegistry::verify_merkle_proof(
                &wrong_leaf,
                &proof_path,
                &proof_indices,
                &root
            ));
        }

        #[ink::test]
        fn request_session_fails_without_attribute_store() {
            let mut contract = AccessRegistry::new();
            let scope_id = [0x01u8; 32];

            // Set up scope requirement
            contract
                .set_scope_requirement(scope_id, ink::prelude::vec![], true)
                .unwrap();

            let result = contract.request_session(
                ink::prelude::vec![0x02u8; 33],
                scope_id,
                100,
                ink::prelude::vec![],
                [0u8; 32],
            );

            assert_eq!(result, Err(Error::AttributeStoreNotConfigured));
        }

        #[ink::test]
        fn request_session_fails_for_unknown_scope() {
            let mut contract = AccessRegistry::new();
            let attribute_store = Address::from([0x99; 20]);
            let scope_id = [0x01u8; 32];

            contract.set_attribute_store(attribute_store).unwrap();

            let result = contract.request_session(
                ink::prelude::vec![0x02u8; 33],
                scope_id,
                100,
                ink::prelude::vec![],
                [0u8; 32],
            );

            assert_eq!(result, Err(Error::ScopeNotFound));
        }

        #[ink::test]
        fn request_session_fails_for_inactive_scope() {
            let mut contract = AccessRegistry::new();
            let attribute_store = Address::from([0x99; 20]);
            let scope_id = [0x01u8; 32];

            contract.set_attribute_store(attribute_store).unwrap();
            contract
                .set_scope_requirement(scope_id, ink::prelude::vec![], false)
                .unwrap();

            let result = contract.request_session(
                ink::prelude::vec![0x02u8; 33],
                scope_id,
                100,
                ink::prelude::vec![],
                [0u8; 32],
            );

            assert_eq!(result, Err(Error::ScopeInactive));
        }

        #[ink::test]
        fn request_session_works_with_no_requirements() {
            let mut contract = AccessRegistry::new();
            let attribute_store = Address::from([0x99; 20]);
            let scope_id = [0x01u8; 32];

            contract.set_attribute_store(attribute_store).unwrap();
            contract
                .set_scope_requirement(scope_id, ink::prelude::vec![], true)
                .unwrap();

            let result = contract.request_session(
                ink::prelude::vec![0x02u8; 33],
                scope_id,
                100,
                ink::prelude::vec![],
                [0u8; 32],
            );

            assert!(result.is_ok());
            let session_id = result.unwrap();
            let grant = contract.get_session(session_id).unwrap();
            assert_eq!(grant.scope_id, scope_id);
        }

        #[ink::test]
        fn request_session_works_with_valid_proofs() {
            let mut contract = AccessRegistry::new();
            let scope_id = [0x01u8; 32];
            let attribute_store = Address::from([0x99; 20]);

            contract.set_attribute_store(attribute_store).unwrap();

            // Build Merkle tree with one required attribute
            use ink::env::hash::{Blake2x256, HashOutput};

            let attr_hash = [0xABu8; 32];
            let sibling = [0xCDu8; 32];

            // Root = H(attr_hash || sibling)
            let mut root_input = [0u8; 64];
            root_input[..32].copy_from_slice(&attr_hash);
            root_input[32..].copy_from_slice(&sibling);
            let mut root = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_bytes::<Blake2x256>(&root_input, &mut root);

            // Set scope requirement
            contract
                .set_scope_requirement(scope_id, ink::prelude::vec![attr_hash], true)
                .unwrap();

            // Create proof
            let proof = AttributeProof {
                attribute_hash: attr_hash,
                proof_path: ink::prelude::vec![sibling],
                proof_indices: ink::prelude::vec![0],
            };

            let result = contract.request_session(
                ink::prelude::vec![0x02u8; 33],
                scope_id,
                100,
                ink::prelude::vec![proof],
                root,
            );

            assert!(result.is_ok());
            let session_id = result.unwrap();
            let grant = contract.get_session(session_id).unwrap();
            assert_eq!(grant.scope_id, scope_id);
        }

        #[ink::test]
        fn request_session_fails_with_invalid_proof() {
            let mut contract = AccessRegistry::new();
            let scope_id = [0x01u8; 32];
            let attribute_store = Address::from([0x99; 20]);

            contract.set_attribute_store(attribute_store).unwrap();

            let attr_hash = [0xABu8; 32];

            // Set scope requirement
            contract
                .set_scope_requirement(scope_id, ink::prelude::vec![attr_hash], true)
                .unwrap();

            // Create proof with wrong root
            let proof = AttributeProof {
                attribute_hash: attr_hash,
                proof_path: ink::prelude::vec![[0xCDu8; 32]],
                proof_indices: ink::prelude::vec![0],
            };

            let result = contract.request_session(
                ink::prelude::vec![0x02u8; 33],
                scope_id,
                100,
                ink::prelude::vec![proof],
                [0x99u8; 32], // Wrong root
            );

            assert_eq!(result, Err(Error::InvalidProof));
        }

        #[ink::test]
        fn request_session_fails_with_missing_attribute() {
            let mut contract = AccessRegistry::new();
            let scope_id = [0x01u8; 32];
            let attribute_store = Address::from([0x99; 20]);

            contract.set_attribute_store(attribute_store).unwrap();

            // Require an attribute but don't provide proof for it
            contract
                .set_scope_requirement(scope_id, ink::prelude::vec![[0xABu8; 32]], true)
                .unwrap();

            let result = contract.request_session(
                ink::prelude::vec![0x02u8; 33],
                scope_id,
                100,
                ink::prelude::vec![], // No proofs
                [0u8; 32],
            );

            assert_eq!(result, Err(Error::MissingRequiredAttribute));
        }
    }
}
