#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod attribute_store {
    use ink::prelude::string::String;
    use ink::prelude::vec::Vec;
    use ink::storage::Mapping;

    /// Attribute definition for ABAC
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Attribute {
        pub namespace: String,
        pub key: String,
        pub value: String,
    }

    /// Attribute store contract for managing ABAC attributes
    #[ink(storage)]
    pub struct AttributeStore {
        /// Mapping from (account, namespace, key) to value
        attributes: Mapping<(AccountId, String, String), String>,
        /// Mapping to track who can write attributes for an account
        /// (account, writer) -> bool
        authorized_writers: Mapping<(AccountId, AccountId), bool>,
        /// Contract owner
        owner: AccountId,
    }

    /// Events emitted by the contract
    #[ink(event)]
    pub struct AttributeSet {
        #[ink(topic)]
        account: AccountId,
        namespace: String,
        key: String,
        value: String,
    }

    #[ink(event)]
    pub struct AttributeRemoved {
        #[ink(topic)]
        account: AccountId,
        namespace: String,
        key: String,
    }

    #[ink(event)]
    pub struct WriterAuthorized {
        #[ink(topic)]
        account: AccountId,
        #[ink(topic)]
        writer: AccountId,
    }

    #[ink(event)]
    pub struct WriterRevoked {
        #[ink(topic)]
        account: AccountId,
        #[ink(topic)]
        writer: AccountId,
    }

    /// Errors that can occur during contract execution
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        /// Caller is not authorized
        NotAuthorized,
        /// Attribute not found
        AttributeNotFound,
    }

    pub type Result<T> = core::result::Result<T, Error>;

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
            account: AccountId,
            namespace: String,
            key: String,
            value: String,
        ) -> Result<()> {
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
            account: AccountId,
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
            account: AccountId,
            namespace: String,
            key: String,
        ) -> Option<String> {
            self.attributes.get((account, namespace, key))
        }

        /// Authorize a writer to set attributes for an account
        #[ink(message)]
        pub fn authorize_writer(&mut self, writer: AccountId) -> Result<()> {
            let caller = self.env().caller();
            self.authorized_writers.insert((caller, writer), &true);

            self.env().emit_event(WriterAuthorized {
                account: caller,
                writer,
            });

            Ok(())
        }

        /// Revoke a writer's authorization
        #[ink(message)]
        pub fn revoke_writer(&mut self, writer: AccountId) -> Result<()> {
            let caller = self.env().caller();
            self.authorized_writers.remove((caller, writer));

            self.env().emit_event(WriterRevoked {
                account: caller,
                writer,
            });

            Ok(())
        }

        /// Check if a caller can write attributes for an account
        #[ink(message)]
        pub fn can_write(&self, caller: AccountId, account: AccountId) -> bool {
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
        pub fn owner(&self) -> AccountId {
            self.owner
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn new_works() {
            let contract = AttributeStore::new();
            assert_eq!(contract.owner(), AccountId::from([0x01; 32]));
        }

        #[ink::test]
        fn set_and_get_attribute_works() {
            let mut contract = AttributeStore::new();
            let account = AccountId::from([0x01; 32]);

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
            let account = AccountId::from([0x01; 32]);

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
            let account = AccountId::from([0x01; 32]);
            let writer = AccountId::from([0x02; 32]);

            assert!(contract.authorize_writer(writer).is_ok());
            assert!(contract.can_write(writer, account));
        }
    }
}
