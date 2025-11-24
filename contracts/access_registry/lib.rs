#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod access_registry {
    use ink::storage::Mapping;

    /// Defines entitlement levels for access control
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout))]
    pub enum EntitlementLevel {
        None,
        Basic,
        Premium,
        VIP,
    }

    impl Default for EntitlementLevel {
        fn default() -> Self {
            Self::None
        }
    }

    /// Access registry contract for managing entitlements
    #[ink(storage)]
    pub struct AccessRegistry {
        /// Mapping from account to their entitlement level
        entitlements: Mapping<AccountId, EntitlementLevel>,
        /// Contract owner who can grant/revoke entitlements
        owner: AccountId,
    }

    /// Events emitted by the contract
    #[ink(event)]
    pub struct EntitlementGranted {
        #[ink(topic)]
        account: AccountId,
        level: EntitlementLevel,
    }

    #[ink(event)]
    pub struct EntitlementRevoked {
        #[ink(topic)]
        account: AccountId,
    }

    /// Errors that can occur during contract execution
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        /// Caller is not the owner
        NotOwner,
        /// Entitlement not found
        EntitlementNotFound,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl AccessRegistry {
        /// Constructor that initializes the contract
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                entitlements: Mapping::default(),
                owner: Self::env().caller(),
            }
        }

        /// Grant an entitlement to an account
        #[ink(message)]
        pub fn grant_entitlement(
            &mut self,
            account: AccountId,
            level: EntitlementLevel,
        ) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            self.entitlements.insert(account, &level);

            self.env().emit_event(EntitlementGranted {
                account,
                level: level.clone(),
            });

            Ok(())
        }

        /// Revoke an entitlement from an account
        #[ink(message)]
        pub fn revoke_entitlement(&mut self, account: AccountId) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }

            self.entitlements.remove(account);

            self.env().emit_event(EntitlementRevoked { account });

            Ok(())
        }

        /// Check the entitlement level of an account
        #[ink(message)]
        pub fn get_entitlement(&self, account: AccountId) -> EntitlementLevel {
            self.entitlements.get(account).unwrap_or_default()
        }

        /// Check if an account has at least a specific entitlement level
        #[ink(message)]
        pub fn has_entitlement(
            &self,
            account: AccountId,
            required_level: EntitlementLevel,
        ) -> bool {
            let current_level = self.get_entitlement(account);
            Self::level_value(&current_level) >= Self::level_value(&required_level)
        }

        /// Get the contract owner
        #[ink(message)]
        pub fn owner(&self) -> AccountId {
            self.owner
        }

        /// Helper function to convert entitlement level to numeric value for comparison
        fn level_value(level: &EntitlementLevel) -> u8 {
            match level {
                EntitlementLevel::None => 0,
                EntitlementLevel::Basic => 1,
                EntitlementLevel::Premium => 2,
                EntitlementLevel::VIP => 3,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn new_works() {
            let contract = AccessRegistry::new();
            assert_eq!(contract.owner(), AccountId::from([0x01; 32]));
        }

        #[ink::test]
        fn grant_entitlement_works() {
            let mut contract = AccessRegistry::new();
            let account = AccountId::from([0x02; 32]);

            assert!(contract
                .grant_entitlement(account, EntitlementLevel::VIP)
                .is_ok());
            assert_eq!(contract.get_entitlement(account), EntitlementLevel::VIP);
        }

        #[ink::test]
        fn has_entitlement_works() {
            let mut contract = AccessRegistry::new();
            let account = AccountId::from([0x02; 32]);

            contract
                .grant_entitlement(account, EntitlementLevel::Premium)
                .unwrap();

            assert!(contract.has_entitlement(account, EntitlementLevel::Basic));
            assert!(contract.has_entitlement(account, EntitlementLevel::Premium));
            assert!(!contract.has_entitlement(account, EntitlementLevel::VIP));
        }

        #[ink::test]
        fn revoke_entitlement_works() {
            let mut contract = AccessRegistry::new();
            let account = AccountId::from([0x02; 32]);

            contract
                .grant_entitlement(account, EntitlementLevel::VIP)
                .unwrap();
            assert!(contract.revoke_entitlement(account).is_ok());
            assert_eq!(contract.get_entitlement(account), EntitlementLevel::None);
        }
    }
}
