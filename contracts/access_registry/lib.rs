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

    /// Access registry contract for managing entitlements
    #[ink(storage)]
    pub struct AccessRegistry {
        /// Mapping from account to their entitlement level
        entitlements: Mapping<Address, EntitlementLevel>,
        /// Contract owner who can grant/revoke entitlements
        owner: Address,
        /// Addresses authorized to call grant/revoke (e.g. payment_integration contract)
        authorized_grantors: Mapping<Address, bool>,
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
    pub struct GrantorAuthorized {
        #[ink(topic)]
        grantor: Address,
    }

    #[ink(event)]
    pub struct GrantorRevoked {
        #[ink(topic)]
        grantor: Address,
    }

    /// Errors that can occur during contract execution
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        /// Caller is not the owner
        NotOwner,
        /// Caller is not authorized (not owner and not an authorized grantor)
        NotAuthorized,
        /// Entitlement not found
        EntitlementNotFound,
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
                owner: Self::env().caller(),
                authorized_grantors: Mapping::default(),
            }
        }

        /// Grant an entitlement to an account (owner or authorized grantor)
        #[ink(message)]
        pub fn grant_entitlement(
            &mut self,
            account: Address,
            level: EntitlementLevel,
        ) -> Result<()> {
            if !self.is_authorized_caller() {
                return Err(Error::NotAuthorized);
            }

            self.entitlements.insert(account, &level);

            self.env().emit_event(EntitlementGranted {
                account,
                level,
            });

            Ok(())
        }

        /// Revoke an entitlement from an account (owner or authorized grantor)
        #[ink(message)]
        pub fn revoke_entitlement(&mut self, account: Address) -> Result<()> {
            if !self.is_authorized_caller() {
                return Err(Error::NotAuthorized);
            }

            self.entitlements.remove(account);

            self.env().emit_event(EntitlementRevoked { account });

            Ok(())
        }

        /// Authorize an address to call grant/revoke (owner only)
        #[ink(message)]
        pub fn authorize_grantor(&mut self, grantor: Address) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }
            self.authorized_grantors.insert(grantor, &true);
            self.env().emit_event(GrantorAuthorized { grantor });
            Ok(())
        }

        /// Revoke an authorized grantor (owner only)
        #[ink(message)]
        pub fn revoke_grantor(&mut self, grantor: Address) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::NotOwner);
            }
            self.authorized_grantors.remove(grantor);
            self.env().emit_event(GrantorRevoked { grantor });
            Ok(())
        }

        /// Check if an address is an authorized grantor
        #[ink(message)]
        pub fn is_authorized_grantor(&self, account: Address) -> bool {
            self.authorized_grantors.get(account).unwrap_or(false)
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

        /// Check if the caller is the owner or an authorized grantor
        fn is_authorized_caller(&self) -> bool {
            let caller = self.env().caller();
            caller == self.owner || self.authorized_grantors.get(caller).unwrap_or(false)
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
        fn authorize_grantor_works() {
            let mut contract = AccessRegistry::new();
            let grantor = Address::from([0x03; 20]);

            assert!(!contract.is_authorized_grantor(grantor));
            assert!(contract.authorize_grantor(grantor).is_ok());
            assert!(contract.is_authorized_grantor(grantor));
        }

        #[ink::test]
        fn revoke_grantor_works() {
            let mut contract = AccessRegistry::new();
            let grantor = Address::from([0x03; 20]);

            contract.authorize_grantor(grantor).unwrap();
            assert!(contract.revoke_grantor(grantor).is_ok());
            assert!(!contract.is_authorized_grantor(grantor));
        }
    }
}
