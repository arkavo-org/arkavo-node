#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod attribute_store {
    use ink::prelude::string::String;
    use ink::storage::Mapping;

    /// Maximum length for string inputs (namespace, key, value)
    const MAX_STRING_LENGTH: usize = 256;

    /// Type alias for attribute key: (account, namespace, key)
    type AttributeKey = (Address, String, String);

    /// Attribute store contract for managing ABAC attributes
    #[ink(storage)]
    pub struct AttributeStore {
        /// Mapping from (account, namespace, key) to value
        attributes: Mapping<AttributeKey, String>,
        /// Mapping to track who can write attributes for an account
        /// (account, writer) -> bool
        authorized_writers: Mapping<(Address, Address), bool>,
        /// Contract owner
        owner: Address,
        /// Mapping from user account to their attribute Merkle root
        roots: Mapping<Address, [u8; 32]>,
        /// Authorized identity providers that can set Merkle roots
        authorized_anchors: Mapping<Address, bool>,
    }

    /// Events emitted by the contract
    #[ink(event)]
    pub struct AttributeSet {
        #[ink(topic)]
        account: Address,
        namespace: String,
        key: String,
        value: String,
    }

    #[ink(event)]
    pub struct AttributeRemoved {
        #[ink(topic)]
        account: Address,
        namespace: String,
        key: String,
    }

    #[ink(event)]
    pub struct WriterAuthorized {
        #[ink(topic)]
        account: Address,
        #[ink(topic)]
        writer: Address,
    }

    #[ink(event)]
    pub struct WriterRevoked {
        #[ink(topic)]
        account: Address,
        #[ink(topic)]
        writer: Address,
    }

    #[ink(event)]
    pub struct RootUpdated {
        #[ink(topic)]
        account: Address,
        root: [u8; 32],
    }

    #[ink(event)]
    pub struct AnchorAdded {
        #[ink(topic)]
        anchor: Address,
    }

    #[ink(event)]
    pub struct AnchorRemoved {
        #[ink(topic)]
        anchor: Address,
    }

    /// Errors that can occur during contract execution
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        /// Caller is not authorized
        NotAuthorized,
        /// Attribute not found
        AttributeNotFound,
        /// Input string exceeds maximum length
        InputTooLong,
        /// Caller is not the contract owner
        NotOwner,
        /// Caller is not an authorized anchor
        NotAuthorizedAnchor,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Default for AttributeStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AttributeStore {
        /// Constructor that initializes the contract
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                attributes: Mapping::default(),
                authorized_writers: Mapping::default(),
                owner: Self::env().caller(),
                roots: Mapping::default(),
                authorized_anchors: Mapping::default(),
            }
        }

        /// Set an attribute for an account
        /// Can be called by the account owner, authorized writers, or contract owner
        #[ink(message)]
        pub fn set_attribute(
            &mut self,
            account: Address,
            namespace: String,
            key: String,
            value: String,
        ) -> Result<()> {
            // Validate input lengths
            if namespace.len() > MAX_STRING_LENGTH
                || key.len() > MAX_STRING_LENGTH
                || value.len() > MAX_STRING_LENGTH
            {
                return Err(Error::InputTooLong);
            }

            let caller = self.env().caller();

            if !self.can_write(caller, account) {
                return Err(Error::NotAuthorized);
            }

            self.attributes
                .insert((account, namespace.clone(), key.clone()), &value);

            self.env().emit_event(AttributeSet {
                account,
                namespace,
                key,
                value,
            });

            Ok(())
        }

        /// Remove an attribute for an account
        #[ink(message)]
        pub fn remove_attribute(
            &mut self,
            account: Address,
            namespace: String,
            key: String,
        ) -> Result<()> {
            let caller = self.env().caller();

            if !self.can_write(caller, account) {
                return Err(Error::NotAuthorized);
            }

            self.attributes
                .remove((account, namespace.clone(), key.clone()));

            self.env().emit_event(AttributeRemoved {
                account,
                namespace,
                key,
            });

            Ok(())
        }

        /// Get an attribute value
        #[ink(message)]
        pub fn get_attribute(
            &self,
            account: Address,
            namespace: String,
            key: String,
        ) -> Option<String> {
            self.attributes.get((account, namespace, key))
        }

        /// Authorize a writer to set attributes for an account
        #[ink(message)]
        pub fn authorize_writer(&mut self, writer: Address) {
            let caller = self.env().caller();
            self.authorized_writers.insert((caller, writer), &true);

            self.env().emit_event(WriterAuthorized {
                account: caller,
                writer,
            });
        }

        /// Revoke a writer's authorization
        #[ink(message)]
        pub fn revoke_writer(&mut self, writer: Address) {
            let caller = self.env().caller();
            self.authorized_writers.remove((caller, writer));

            self.env().emit_event(WriterRevoked {
                account: caller,
                writer,
            });
        }

        /// Check if a caller can write attributes for an account
        #[ink(message)]
        pub fn can_write(&self, caller: Address, account: Address) -> bool {
            // Owner can write to any account
            if caller == self.owner {
                return true;
            }

            // Account owner can write to their own attributes
            if caller == account {
                return true;
            }

            // Check if caller is an authorized writer
            self.authorized_writers
                .get((account, caller))
                .unwrap_or(false)
        }

        /// Get the contract owner
        #[ink(message)]
        pub fn owner(&self) -> Address {
            self.owner
        }

        /// Set the Merkle root for a user's attributes.
        /// Can only be called by authorized anchors (identity providers).
        #[ink(message)]
        pub fn set_root(&mut self, account: Address, root: [u8; 32]) -> Result<()> {
            let caller = self.env().caller();
            if !self.is_authorized_anchor(caller) {
                return Err(Error::NotAuthorizedAnchor);
            }

            self.roots.insert(account, &root);

            self.env().emit_event(RootUpdated { account, root });

            Ok(())
        }

        /// Get the Merkle root for a user's attributes.
        #[ink(message)]
        pub fn get_root(&self, account: Address) -> Option<[u8; 32]> {
            self.roots.get(account)
        }

        /// Add an authorized anchor (identity provider).
        /// Only the contract owner can call this.
        #[ink(message)]
        pub fn add_anchor(&mut self, anchor: Address) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            self.authorized_anchors.insert(anchor, &true);

            self.env().emit_event(AnchorAdded { anchor });

            Ok(())
        }

        /// Remove an authorized anchor.
        /// Only the contract owner can call this.
        #[ink(message)]
        pub fn remove_anchor(&mut self, anchor: Address) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            self.authorized_anchors.remove(anchor);

            self.env().emit_event(AnchorRemoved { anchor });

            Ok(())
        }

        /// Check if an address is an authorized anchor.
        #[ink(message)]
        pub fn is_authorized_anchor(&self, anchor: Address) -> bool {
            // Owner is always an authorized anchor
            if anchor == self.owner {
                return true;
            }
            self.authorized_anchors.get(anchor).unwrap_or(false)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn new_works() {
            let contract = AttributeStore::new();
            // Owner is set to the default caller (zero address in test env)
            assert_eq!(contract.owner(), Address::default());
        }

        #[ink::test]
        fn set_and_get_attribute_works() {
            let mut contract = AttributeStore::new();
            let account = Address::from([0x01; 20]);

            assert!(
                contract
                    .set_attribute(
                        account,
                        String::from("opentdf"),
                        String::from("role"),
                        String::from("admin")
                    )
                    .is_ok()
            );

            assert_eq!(
                contract.get_attribute(account, String::from("opentdf"), String::from("role")),
                Some(String::from("admin"))
            );
        }

        #[ink::test]
        fn remove_attribute_works() {
            let mut contract = AttributeStore::new();
            let account = Address::from([0x01; 20]);

            contract
                .set_attribute(
                    account,
                    String::from("opentdf"),
                    String::from("role"),
                    String::from("admin"),
                )
                .unwrap();

            assert!(
                contract
                    .remove_attribute(account, String::from("opentdf"), String::from("role"))
                    .is_ok()
            );

            assert_eq!(
                contract.get_attribute(account, String::from("opentdf"), String::from("role")),
                None
            );
        }

        #[ink::test]
        fn authorize_writer_works() {
            let mut contract = AttributeStore::new();
            // The caller (default = zero address) authorizes a writer
            let caller = Address::default();
            let writer = Address::from([0x02; 20]);

            contract.authorize_writer(writer);
            // Writer should be able to write to the caller's account
            assert!(contract.can_write(writer, caller));
        }

        #[ink::test]
        fn set_root_works() {
            let mut contract = AttributeStore::new();
            let account = Address::from([0x01; 20]);
            let root = [0xAB; 32];

            // Owner is an authorized anchor by default
            assert!(contract.set_root(account, root).is_ok());
            assert_eq!(contract.get_root(account), Some(root));
        }

        #[ink::test]
        fn set_root_fails_for_unauthorized() {
            let mut contract = AttributeStore::new();
            let account = Address::from([0x01; 20]);
            let root = [0xAB; 32];

            // Change caller to non-owner
            ink::env::test::set_caller(Address::from([0x99; 20]));

            assert_eq!(
                contract.set_root(account, root),
                Err(Error::NotAuthorizedAnchor)
            );
        }

        #[ink::test]
        fn add_anchor_works() {
            let mut contract = AttributeStore::new();
            let anchor = Address::from([0x02; 20]);

            assert!(contract.add_anchor(anchor).is_ok());
            assert!(contract.is_authorized_anchor(anchor));
        }

        #[ink::test]
        fn authorized_anchor_can_set_root() {
            let mut contract = AttributeStore::new();
            let anchor = Address::from([0x02; 20]);
            let account = Address::from([0x01; 20]);
            let root = [0xCD; 32];

            // Owner adds anchor
            contract.add_anchor(anchor).unwrap();

            // Switch caller to anchor
            ink::env::test::set_caller(anchor);

            // Anchor can set root
            assert!(contract.set_root(account, root).is_ok());
            assert_eq!(contract.get_root(account), Some(root));
        }

        #[ink::test]
        fn remove_anchor_works() {
            let mut contract = AttributeStore::new();
            let anchor = Address::from([0x02; 20]);

            contract.add_anchor(anchor).unwrap();
            assert!(contract.is_authorized_anchor(anchor));

            contract.remove_anchor(anchor).unwrap();
            assert!(!contract.is_authorized_anchor(anchor));
        }

        #[ink::test]
        fn get_root_returns_none_for_unknown() {
            let contract = AttributeStore::new();
            let account = Address::from([0x99; 20]);
            assert!(contract.get_root(account).is_none());
        }

        #[ink::test]
        fn add_anchor_fails_for_non_owner() {
            let mut contract = AttributeStore::new();
            let anchor = Address::from([0x02; 20]);

            // Change caller to non-owner
            ink::env::test::set_caller(Address::from([0x99; 20]));

            assert_eq!(contract.add_anchor(anchor), Err(Error::NotOwner));
        }

        #[ink::test]
        fn remove_anchor_fails_for_non_owner() {
            let mut contract = AttributeStore::new();
            let anchor = Address::from([0x02; 20]);

            // Owner adds anchor first
            contract.add_anchor(anchor).unwrap();

            // Change caller to non-owner
            ink::env::test::set_caller(Address::from([0x99; 20]));

            assert_eq!(contract.remove_anchor(anchor), Err(Error::NotOwner));
        }
    }
}
