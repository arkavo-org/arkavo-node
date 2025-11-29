#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod access_registry {
    use ink::storage::Mapping;

    /// Defines entitlement levels for access control
    #[derive(Default, Debug, PartialEq, Eq, Clone, Copy, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout))]
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
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout))]
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

    /// Access registry contract for managing entitlements
    #[ink(storage)]
    pub struct AccessRegistry {
        /// Mapping from account to their entitlement level
        entitlements: Mapping<Address, EntitlementLevel>,
        /// Mapping from session ID to session grant
        sessions: Mapping<[u8; 32], SessionGrant>,
        /// Contract owner who can grant/revoke entitlements
        owner: Address,
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

            self.env().emit_event(EntitlementGranted {
                account,
                level,
            });

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
        pub fn has_entitlement(
            &self,
            account: Address,
            required_level: EntitlementLevel,
        ) -> bool {
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

            assert!(contract
                .grant_entitlement(account, EntitlementLevel::Vip)
                .is_ok());
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

            assert!(contract
                .create_session(session_id, eph_pub_key.clone(), scope_id, expires_at_block)
                .is_ok());

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
    }
}
