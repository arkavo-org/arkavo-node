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

    /// Status of a read request.
    #[derive(Default, Debug, PartialEq, Eq, Clone, Copy, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub enum RequestStatus {
        #[default]
        Pending,
        Approved,
        Denied,
    }

    /// A read request submitted by a user wanting access to a letter.
    #[derive(Default, Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct ReadRequestRecord {
        /// Hash of the letter being requested
        pub letter_id: [u8; 32],
        /// Hash of the requester's email (privacy-preserving)
        pub email_hash: [u8; 32],
        /// Account that submitted the request
        pub requester: Address,
        /// Current status of the request
        pub status: RequestStatus,
        /// Block when the request was submitted
        pub submitted_at_block: u64,
        /// Block when the request was resolved (approved/denied), 0 if pending
        pub resolved_at_block: u64,
        /// Admin who resolved the request (zero address if pending)
        pub resolved_by: Address,
    }

    /// A dissem list entry granting read access to a letter.
    #[derive(Default, Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct DissemEntry {
        /// Block when the entitlement was granted
        pub granted_at_block: u64,
        /// Block when the entitlement expires (0 = no expiry)
        pub expires_at_block: u64,
        /// Whether this entry has been revoked
        pub is_revoked: bool,
        /// Admin who granted this entry
        pub granted_by: Address,
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
        /// Admin accounts that can approve/deny read requests
        admins: Mapping<Address, bool>,
        /// Read requests: `request_id` -> `ReadRequestRecord`
        read_requests: Mapping<[u8; 32], ReadRequestRecord>,
        /// Dissem list: `dissem_key(letter_id, email_hash)` -> `DissemEntry`
        dissem_entries: Mapping<[u8; 32], DissemEntry>,
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

    #[ink(event)]
    pub struct AdminAdded {
        #[ink(topic)]
        admin: Address,
    }

    #[ink(event)]
    pub struct AdminRemoved {
        #[ink(topic)]
        admin: Address,
    }

    #[ink(event)]
    pub struct ReadRequestSubmitted {
        #[ink(topic)]
        request_id: [u8; 32],
        #[ink(topic)]
        requester: Address,
        letter_id: [u8; 32],
        email_hash: [u8; 32],
    }

    #[ink(event)]
    pub struct ReadRequestApproved {
        #[ink(topic)]
        request_id: [u8; 32],
        #[ink(topic)]
        admin: Address,
        letter_id: [u8; 32],
        email_hash: [u8; 32],
    }

    #[ink(event)]
    pub struct ReadRequestDenied {
        #[ink(topic)]
        request_id: [u8; 32],
        #[ink(topic)]
        admin: Address,
    }

    #[ink(event)]
    pub struct DissemEntryRevoked {
        #[ink(topic)]
        letter_id: [u8; 32],
        email_hash: [u8; 32],
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
        /// Caller is not an admin
        NotAdmin,
        /// Read request not found
        RequestNotFound,
        /// Read request has already been processed
        RequestAlreadyProcessed,
        /// A request for this letter+email already exists
        DuplicateRequest,
        /// Dissem entry not found
        DissemEntryNotFound,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Default for AccessRegistry {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AccessRegistry {
        /// Constructor that initializes the contract.
        /// The deployer becomes the owner and is automatically an admin.
        #[ink(constructor)]
        pub fn new() -> Self {
            let owner = Self::env().caller();
            let mut admins = Mapping::default();
            admins.insert(owner, &true);

            Self {
                entitlements: Mapping::default(),
                sessions: Mapping::default(),
                owner,
                attribute_store: None,
                scope_requirements: Mapping::default(),
                admins,
                read_requests: Mapping::default(),
                dissem_entries: Mapping::default(),
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

        // ──────────────────────────────────────────────────
        // Admin Management
        // ──────────────────────────────────────────────────

        /// Add an admin account. Only the owner can add admins.
        #[ink(message)]
        pub fn add_admin(&mut self, account: Address) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }
            self.admins.insert(account, &true);
            self.env().emit_event(AdminAdded { admin: account });
            Ok(())
        }

        /// Remove an admin account. Only the owner can remove admins.
        #[ink(message)]
        pub fn remove_admin(&mut self, account: Address) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }
            self.admins.remove(account);
            self.env().emit_event(AdminRemoved { admin: account });
            Ok(())
        }

        /// Check if an account is an admin.
        #[ink(message)]
        pub fn is_admin_account(&self, account: Address) -> bool {
            self.admins.get(account).unwrap_or(false)
        }

        /// Check if caller is owner or admin.
        fn caller_is_admin(&self) -> bool {
            let caller = self.env().caller();
            caller == self.owner || self.admins.get(caller).unwrap_or(false)
        }

        // ──────────────────────────────────────────────────
        // Read Request Workflow
        // ──────────────────────────────────────────────────

        /// Submit a read request for a letter.
        ///
        /// Anyone can submit a request. The `letter_id` and `email_hash` are
        /// 32-byte hashes to preserve privacy on-chain. The request ID is
        /// deterministic: `H(letter_id || email_hash)`, preventing duplicates.
        #[ink(message)]
        pub fn submit_read_request(
            &mut self,
            letter_id: [u8; 32],
            email_hash: [u8; 32],
        ) -> Result<[u8; 32]> {
            let caller = self.env().caller();
            let request_id = Self::compute_request_id(&letter_id, &email_hash);

            // Check for duplicate
            if self.read_requests.get(request_id).is_some() {
                return Err(Error::DuplicateRequest);
            }

            let record = ReadRequestRecord {
                letter_id,
                email_hash,
                requester: caller,
                status: RequestStatus::Pending,
                submitted_at_block: u64::from(self.env().block_number()),
                resolved_at_block: 0,
                resolved_by: Address::default(),
            };

            self.read_requests.insert(request_id, &record);

            self.env().emit_event(ReadRequestSubmitted {
                request_id,
                requester: caller,
                letter_id,
                email_hash,
            });

            Ok(request_id)
        }

        /// Approve a read request. Only admins can approve.
        ///
        /// Approving a request adds the email hash to the letter's dissem list,
        /// granting read access. An optional `expires_at_block` of 0 means no expiry.
        #[ink(message)]
        pub fn approve_read_request(
            &mut self,
            request_id: [u8; 32],
            expires_at_block: u64,
        ) -> Result<()> {
            if !self.caller_is_admin() {
                return Err(Error::NotAdmin);
            }

            let mut record = self
                .read_requests
                .get(request_id)
                .ok_or(Error::RequestNotFound)?;

            if record.status != RequestStatus::Pending {
                return Err(Error::RequestAlreadyProcessed);
            }

            let admin = self.env().caller();
            let current_block = u64::from(self.env().block_number());

            record.status = RequestStatus::Approved;
            record.resolved_at_block = current_block;
            record.resolved_by = admin;
            self.read_requests.insert(request_id, &record);

            // Add to dissem list
            let dissem_key = Self::compute_dissem_key(&record.letter_id, &record.email_hash);
            let entry = DissemEntry {
                granted_at_block: current_block,
                expires_at_block,
                is_revoked: false,
                granted_by: admin,
            };
            self.dissem_entries.insert(dissem_key, &entry);

            self.env().emit_event(ReadRequestApproved {
                request_id,
                admin,
                letter_id: record.letter_id,
                email_hash: record.email_hash,
            });

            Ok(())
        }

        /// Deny a read request. Only admins can deny.
        #[ink(message)]
        pub fn deny_read_request(&mut self, request_id: [u8; 32]) -> Result<()> {
            if !self.caller_is_admin() {
                return Err(Error::NotAdmin);
            }

            let mut record = self
                .read_requests
                .get(request_id)
                .ok_or(Error::RequestNotFound)?;

            if record.status != RequestStatus::Pending {
                return Err(Error::RequestAlreadyProcessed);
            }

            let admin = self.env().caller();

            record.status = RequestStatus::Denied;
            record.resolved_at_block = u64::from(self.env().block_number());
            record.resolved_by = admin;
            self.read_requests.insert(request_id, &record);

            self.env().emit_event(ReadRequestDenied {
                request_id,
                admin,
            });

            Ok(())
        }

        /// Get a read request by its ID.
        #[ink(message)]
        pub fn get_read_request(&self, request_id: [u8; 32]) -> Option<ReadRequestRecord> {
            self.read_requests.get(request_id)
        }

        // ──────────────────────────────────────────────────
        // Letter Dissem List / Entitlement Checks
        // ──────────────────────────────────────────────────

        /// Check if an email hash is entitled to read a letter.
        ///
        /// Returns true if a non-revoked, non-expired dissem entry exists.
        #[ink(message)]
        pub fn check_letter_entitlement(
            &self,
            letter_id: [u8; 32],
            email_hash: [u8; 32],
        ) -> bool {
            let dissem_key = Self::compute_dissem_key(&letter_id, &email_hash);
            if let Some(entry) = self.dissem_entries.get(dissem_key) {
                if entry.is_revoked {
                    return false;
                }
                if entry.expires_at_block > 0
                    && u64::from(self.env().block_number()) > entry.expires_at_block
                {
                    return false;
                }
                true
            } else {
                false
            }
        }

        /// Get the dissem entry for a letter+email pair.
        #[ink(message)]
        pub fn get_dissem_entry(
            &self,
            letter_id: [u8; 32],
            email_hash: [u8; 32],
        ) -> Option<DissemEntry> {
            let dissem_key = Self::compute_dissem_key(&letter_id, &email_hash);
            self.dissem_entries.get(dissem_key)
        }

        /// Revoke a dissem entry (remove read access). Only admins can revoke.
        #[ink(message)]
        pub fn revoke_letter_entitlement(
            &mut self,
            letter_id: [u8; 32],
            email_hash: [u8; 32],
        ) -> Result<()> {
            if !self.caller_is_admin() {
                return Err(Error::NotAdmin);
            }

            let dissem_key = Self::compute_dissem_key(&letter_id, &email_hash);
            let mut entry = self
                .dissem_entries
                .get(dissem_key)
                .ok_or(Error::DissemEntryNotFound)?;

            entry.is_revoked = true;
            self.dissem_entries.insert(dissem_key, &entry);

            self.env().emit_event(DissemEntryRevoked {
                letter_id,
                email_hash,
            });

            Ok(())
        }

        /// Manually add a dissem entry without a request. Only admins can do this.
        #[ink(message)]
        pub fn add_dissem_entry(
            &mut self,
            letter_id: [u8; 32],
            email_hash: [u8; 32],
            expires_at_block: u64,
        ) -> Result<()> {
            if !self.caller_is_admin() {
                return Err(Error::NotAdmin);
            }

            let admin = self.env().caller();
            let dissem_key = Self::compute_dissem_key(&letter_id, &email_hash);
            let entry = DissemEntry {
                granted_at_block: u64::from(self.env().block_number()),
                expires_at_block,
                is_revoked: false,
                granted_by: admin,
            };
            self.dissem_entries.insert(dissem_key, &entry);

            Ok(())
        }

        /// Compute a deterministic request ID from letter_id and email_hash.
        fn compute_request_id(letter_id: &[u8; 32], email_hash: &[u8; 32]) -> [u8; 32] {
            use ink::env::hash::{Blake2x256, HashOutput};

            let mut input = [0u8; 64];
            input[..32].copy_from_slice(letter_id);
            input[32..].copy_from_slice(email_hash);

            let mut output = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_bytes::<Blake2x256>(&input, &mut output);
            output
        }

        /// Compute the dissem storage key from letter_id and email_hash.
        fn compute_dissem_key(letter_id: &[u8; 32], email_hash: &[u8; 32]) -> [u8; 32] {
            use ink::env::hash::{Blake2x256, HashOutput};

            // Use a domain separator to avoid collision with request IDs
            let mut input = ink::prelude::vec::Vec::with_capacity(72);
            input.extend_from_slice(b"dissem::");
            input.extend_from_slice(letter_id);
            input.extend_from_slice(email_hash);

            let mut output = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_bytes::<Blake2x256>(&input, &mut output);
            output
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

        // ──────────────────────────────────────────────────
        // Admin Management Tests
        // ──────────────────────────────────────────────────

        #[ink::test]
        fn owner_is_admin_by_default() {
            let contract = AccessRegistry::new();
            let owner = contract.owner();
            assert!(contract.is_admin_account(owner));
        }

        #[ink::test]
        fn add_admin_works() {
            let mut contract = AccessRegistry::new();
            let admin = Address::from([0x02; 20]);

            assert!(!contract.is_admin_account(admin));
            assert!(contract.add_admin(admin).is_ok());
            assert!(contract.is_admin_account(admin));
        }

        #[ink::test]
        fn add_admin_fails_for_non_owner() {
            let mut contract = AccessRegistry::new();
            let admin = Address::from([0x02; 20]);

            // Change caller to non-owner
            ink::env::test::set_caller(admin);

            assert_eq!(
                contract.add_admin(Address::from([0x03; 20])),
                Err(Error::NotOwner)
            );
        }

        #[ink::test]
        fn remove_admin_works() {
            let mut contract = AccessRegistry::new();
            let admin = Address::from([0x02; 20]);

            contract.add_admin(admin).unwrap();
            assert!(contract.is_admin_account(admin));

            assert!(contract.remove_admin(admin).is_ok());
            assert!(!contract.is_admin_account(admin));
        }

        // ──────────────────────────────────────────────────
        // Read Request Tests
        // ──────────────────────────────────────────────────

        #[ink::test]
        fn submit_read_request_works() {
            let mut contract = AccessRegistry::new();
            let letter_id = [0x01u8; 32];
            let email_hash = [0x02u8; 32];

            let result = contract.submit_read_request(letter_id, email_hash);
            assert!(result.is_ok());

            let request_id = result.unwrap();
            let record = contract.get_read_request(request_id).unwrap();
            assert_eq!(record.letter_id, letter_id);
            assert_eq!(record.email_hash, email_hash);
            assert_eq!(record.status, RequestStatus::Pending);
            assert_eq!(record.resolved_at_block, 0);
        }

        #[ink::test]
        fn submit_duplicate_request_fails() {
            let mut contract = AccessRegistry::new();
            let letter_id = [0x01u8; 32];
            let email_hash = [0x02u8; 32];

            contract.submit_read_request(letter_id, email_hash).unwrap();
            let result = contract.submit_read_request(letter_id, email_hash);
            assert_eq!(result, Err(Error::DuplicateRequest));
        }

        #[ink::test]
        fn different_letter_email_pairs_get_different_ids() {
            let mut contract = AccessRegistry::new();

            let id1 = contract
                .submit_read_request([0x01u8; 32], [0x02u8; 32])
                .unwrap();
            let id2 = contract
                .submit_read_request([0x01u8; 32], [0x03u8; 32])
                .unwrap();
            let id3 = contract
                .submit_read_request([0x04u8; 32], [0x02u8; 32])
                .unwrap();

            assert_ne!(id1, id2);
            assert_ne!(id1, id3);
            assert_ne!(id2, id3);
        }

        #[ink::test]
        fn approve_read_request_works() {
            let mut contract = AccessRegistry::new();
            let letter_id = [0x01u8; 32];
            let email_hash = [0x02u8; 32];

            let request_id = contract
                .submit_read_request(letter_id, email_hash)
                .unwrap();

            // Owner is admin by default, so approve should work
            assert!(contract.approve_read_request(request_id, 0).is_ok());

            let record = contract.get_read_request(request_id).unwrap();
            assert_eq!(record.status, RequestStatus::Approved);
            assert_eq!(record.resolved_by, contract.owner());

            // Dissem entry should now exist
            assert!(contract.check_letter_entitlement(letter_id, email_hash));
        }

        #[ink::test]
        fn approve_request_fails_for_non_admin() {
            let mut contract = AccessRegistry::new();
            let letter_id = [0x01u8; 32];
            let email_hash = [0x02u8; 32];

            let request_id = contract
                .submit_read_request(letter_id, email_hash)
                .unwrap();

            // Switch to non-admin caller
            let non_admin = Address::from([0x99; 20]);
            ink::env::test::set_caller(non_admin);

            assert_eq!(
                contract.approve_read_request(request_id, 0),
                Err(Error::NotAdmin)
            );
        }

        #[ink::test]
        fn approve_nonexistent_request_fails() {
            let mut contract = AccessRegistry::new();
            assert_eq!(
                contract.approve_read_request([0x99u8; 32], 0),
                Err(Error::RequestNotFound)
            );
        }

        #[ink::test]
        fn approve_already_approved_request_fails() {
            let mut contract = AccessRegistry::new();
            let request_id = contract
                .submit_read_request([0x01u8; 32], [0x02u8; 32])
                .unwrap();

            contract.approve_read_request(request_id, 0).unwrap();
            assert_eq!(
                contract.approve_read_request(request_id, 0),
                Err(Error::RequestAlreadyProcessed)
            );
        }

        #[ink::test]
        fn deny_read_request_works() {
            let mut contract = AccessRegistry::new();
            let letter_id = [0x01u8; 32];
            let email_hash = [0x02u8; 32];

            let request_id = contract
                .submit_read_request(letter_id, email_hash)
                .unwrap();

            assert!(contract.deny_read_request(request_id).is_ok());

            let record = contract.get_read_request(request_id).unwrap();
            assert_eq!(record.status, RequestStatus::Denied);

            // Dissem entry should NOT exist
            assert!(!contract.check_letter_entitlement(letter_id, email_hash));
        }

        #[ink::test]
        fn deny_request_fails_for_non_admin() {
            let mut contract = AccessRegistry::new();
            let request_id = contract
                .submit_read_request([0x01u8; 32], [0x02u8; 32])
                .unwrap();

            let non_admin = Address::from([0x99; 20]);
            ink::env::test::set_caller(non_admin);

            assert_eq!(
                contract.deny_read_request(request_id),
                Err(Error::NotAdmin)
            );
        }

        #[ink::test]
        fn deny_already_denied_request_fails() {
            let mut contract = AccessRegistry::new();
            let request_id = contract
                .submit_read_request([0x01u8; 32], [0x02u8; 32])
                .unwrap();

            contract.deny_read_request(request_id).unwrap();
            assert_eq!(
                contract.deny_read_request(request_id),
                Err(Error::RequestAlreadyProcessed)
            );
        }

        #[ink::test]
        fn cannot_approve_denied_request() {
            let mut contract = AccessRegistry::new();
            let request_id = contract
                .submit_read_request([0x01u8; 32], [0x02u8; 32])
                .unwrap();

            contract.deny_read_request(request_id).unwrap();
            assert_eq!(
                contract.approve_read_request(request_id, 0),
                Err(Error::RequestAlreadyProcessed)
            );
        }

        // ──────────────────────────────────────────────────
        // Dissem List / Letter Entitlement Tests
        // ──────────────────────────────────────────────────

        #[ink::test]
        fn check_entitlement_returns_false_when_none() {
            let contract = AccessRegistry::new();
            assert!(!contract.check_letter_entitlement([0x01u8; 32], [0x02u8; 32]));
        }

        #[ink::test]
        fn revoke_letter_entitlement_works() {
            let mut contract = AccessRegistry::new();
            let letter_id = [0x01u8; 32];
            let email_hash = [0x02u8; 32];

            // Approve to create dissem entry
            let request_id = contract
                .submit_read_request(letter_id, email_hash)
                .unwrap();
            contract.approve_read_request(request_id, 0).unwrap();
            assert!(contract.check_letter_entitlement(letter_id, email_hash));

            // Revoke
            assert!(contract.revoke_letter_entitlement(letter_id, email_hash).is_ok());
            assert!(!contract.check_letter_entitlement(letter_id, email_hash));

            // Dissem entry still exists but is_revoked
            let entry = contract.get_dissem_entry(letter_id, email_hash).unwrap();
            assert!(entry.is_revoked);
        }

        #[ink::test]
        fn revoke_nonexistent_entitlement_fails() {
            let mut contract = AccessRegistry::new();
            assert_eq!(
                contract.revoke_letter_entitlement([0x01u8; 32], [0x02u8; 32]),
                Err(Error::DissemEntryNotFound)
            );
        }

        #[ink::test]
        fn revoke_entitlement_fails_for_non_admin() {
            let mut contract = AccessRegistry::new();
            let letter_id = [0x01u8; 32];
            let email_hash = [0x02u8; 32];

            let request_id = contract
                .submit_read_request(letter_id, email_hash)
                .unwrap();
            contract.approve_read_request(request_id, 0).unwrap();

            let non_admin = Address::from([0x99; 20]);
            ink::env::test::set_caller(non_admin);

            assert_eq!(
                contract.revoke_letter_entitlement(letter_id, email_hash),
                Err(Error::NotAdmin)
            );
        }

        #[ink::test]
        fn add_dissem_entry_works() {
            let mut contract = AccessRegistry::new();
            let letter_id = [0x01u8; 32];
            let email_hash = [0x02u8; 32];

            assert!(contract.add_dissem_entry(letter_id, email_hash, 0).is_ok());
            assert!(contract.check_letter_entitlement(letter_id, email_hash));
        }

        #[ink::test]
        fn add_dissem_entry_fails_for_non_admin() {
            let mut contract = AccessRegistry::new();
            let non_admin = Address::from([0x99; 20]);
            ink::env::test::set_caller(non_admin);

            assert_eq!(
                contract.add_dissem_entry([0x01u8; 32], [0x02u8; 32], 0),
                Err(Error::NotAdmin)
            );
        }

        #[ink::test]
        fn added_admin_can_approve_requests() {
            let mut contract = AccessRegistry::new();
            let admin2 = Address::from([0x02; 20]);
            contract.add_admin(admin2).unwrap();

            let request_id = contract
                .submit_read_request([0x01u8; 32], [0x02u8; 32])
                .unwrap();

            // Switch to admin2
            ink::env::test::set_caller(admin2);
            assert!(contract.approve_read_request(request_id, 0).is_ok());
        }

        #[ink::test]
        fn get_read_request_returns_none_for_unknown() {
            let contract = AccessRegistry::new();
            assert!(contract.get_read_request([0x99u8; 32]).is_none());
        }
    }
}
