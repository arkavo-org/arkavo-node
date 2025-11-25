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

            self.attributes.remove((account, namespace.clone(), key.clone()));

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
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn new_works() {
            let _contract = AttributeStore::new();
            // Contract initializes successfully
        }

        #[ink::test]
        fn set_and_get_attribute_works() {
            let mut contract = AttributeStore::new();
            let account = Address::from([0x01; 20]);

            assert!(contract
                .set_attribute(
                    account,
                    String::from("opentdf"),
                    String::from("role"),
                    String::from("admin")
                )
                .is_ok());

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

            assert!(contract
                .remove_attribute(account, String::from("opentdf"), String::from("role"))
                .is_ok());

            assert_eq!(
                contract.get_attribute(account, String::from("opentdf"), String::from("role")),
                None
            );
        }

        #[ink::test]
        fn authorize_writer_works() {
            let mut contract = AttributeStore::new();
            let account = Address::from([0x01; 20]);
            let writer = Address::from([0x02; 20]);

            contract.authorize_writer(writer);
            assert!(contract.can_write(writer, account));
        }
    }
}
