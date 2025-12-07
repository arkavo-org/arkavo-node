#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod user_registry {
    use ink::prelude::string::String;
    use ink::storage::Mapping;

    /// User registry contract for linking DIDs to on-chain accounts.
    ///
    /// This contract provides a minimal, permanent binding between
    /// decentralized identifiers (DIDs) and EVM addresses (H160).
    /// Once linked, the binding cannot be changed or removed.
    ///
    /// Supports two linking modes:
    /// 1. Self-linking: User calls `link_account(did)` to link their own address
    /// 2. Owner-linking: Contract owner calls `link_account_for(did, address)` for RPC backchannel
    #[ink(storage)]
    pub struct UserRegistry {
        /// DID -> Address mapping (one-to-one, permanent)
        did_to_account: Mapping<String, Address>,
        /// Address -> DID mapping (reverse lookup)
        account_to_did: Mapping<Address, String>,
        /// Contract owner (can link on behalf of users via backchannel)
        owner: Address,
        /// Total number of linked accounts
        total_linked: u32,
    }

    /// Event emitted when an account is linked to a DID
    #[ink(event)]
    pub struct AccountLinked {
        #[ink(topic)]
        account: Address,
        did: String,
        /// Whether this was linked by owner on behalf of user
        by_owner: bool,
    }

    /// Maximum length for a DID (prevents DoS via excessive storage)
    const MAX_DID_LENGTH: usize = 256;

    /// Errors that can occur during contract execution
    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        /// DID is already linked to another account
        DidAlreadyLinked,
        /// Account is already linked to a DID
        AccountAlreadyLinked,
        /// Invalid DID format (must start with "did:key:")
        InvalidDidFormat,
        /// DID cannot be empty
        EmptyDid,
        /// Only the contract owner can perform this action
        NotOwner,
        /// DID exceeds maximum length
        DidTooLong,
    }

    impl core::fmt::Display for Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Error::DidAlreadyLinked => write!(f, "DID is already linked to another account"),
                Error::AccountAlreadyLinked => write!(f, "Account is already linked to a DID"),
                Error::InvalidDidFormat => {
                    write!(f, "Invalid DID format (must start with 'did:key:')")
                }
                Error::EmptyDid => write!(f, "DID cannot be empty"),
                Error::NotOwner => write!(f, "Only the contract owner can perform this action"),
                Error::DidTooLong => write!(f, "DID exceeds maximum length of 256 bytes"),
            }
        }
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Default for UserRegistry {
        fn default() -> Self {
            Self::new()
        }
    }

    impl UserRegistry {
        /// Constructor that initializes the contract
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                did_to_account: Mapping::default(),
                account_to_did: Mapping::default(),
                owner: Self::env().caller(),
                total_linked: 0,
            }
        }

        /// Validate DID format and length
        fn validate_did(&self, did: &str) -> Result<()> {
            if did.is_empty() {
                return Err(Error::EmptyDid);
            }
            if did.len() > MAX_DID_LENGTH {
                return Err(Error::DidTooLong);
            }
            if !did.starts_with("did:key:") {
                return Err(Error::InvalidDidFormat);
            }
            Ok(())
        }

        /// Internal method to perform the actual linking
        fn do_link(&mut self, did: String, account: Address, by_owner: bool) -> Result<()> {
            // Validate DID format
            self.validate_did(&did)?;

            // Check if DID is already linked
            if self.did_to_account.contains(&did) {
                return Err(Error::DidAlreadyLinked);
            }

            // Check if account is already linked
            if self.account_to_did.contains(account) {
                return Err(Error::AccountAlreadyLinked);
            }

            // Create permanent binding
            self.did_to_account.insert(&did, &account);
            self.account_to_did.insert(account, &did);
            self.total_linked = self.total_linked.saturating_add(1);

            // Emit event
            self.env().emit_event(AccountLinked {
                account,
                did,
                by_owner,
            });

            Ok(())
        }

        /// Link the caller's account to a DID.
        ///
        /// This is a one-time, permanent operation. Once linked:
        /// - The DID cannot be linked to any other account
        /// - The account cannot be linked to any other DID
        ///
        /// # Arguments
        /// * `did` - The decentralized identifier to link (must start with "did:key:")
        ///
        /// # Errors
        /// * `EmptyDid` - If the DID is empty
        /// * `InvalidDidFormat` - If the DID doesn't start with "did:key:"
        /// * `DidAlreadyLinked` - If the DID is already linked to another account
        /// * `AccountAlreadyLinked` - If the caller's account is already linked to a DID
        #[ink(message)]
        pub fn link_account(&mut self, did: String) -> Result<()> {
            let caller = self.env().caller();
            self.do_link(did, caller, false)
        }

        /// Link a DID to a specific address (owner-only, for RPC backchannel).
        ///
        /// This allows the contract owner (typically the node's RPC service account)
        /// to link accounts on behalf of users after successful WebAuthn registration.
        ///
        /// # Arguments
        /// * `did` - The decentralized identifier to link (must start with "did:key:")
        /// * `account` - The EVM address to link the DID to
        ///
        /// # Errors
        /// * `NotOwner` - If caller is not the contract owner
        /// * `EmptyDid` - If the DID is empty
        /// * `InvalidDidFormat` - If the DID doesn't start with "did:key:"
        /// * `DidAlreadyLinked` - If the DID is already linked to another account
        /// * `AccountAlreadyLinked` - If the account is already linked to a DID
        #[ink(message)]
        pub fn link_account_for(&mut self, did: String, account: Address) -> Result<()> {
            let caller = self.env().caller();
            if caller != self.owner {
                return Err(Error::NotOwner);
            }
            self.do_link(did, account, true)
        }

        /// Get the account linked to a DID
        #[ink(message)]
        pub fn get_account_by_did(&self, did: String) -> Option<Address> {
            self.did_to_account.get(&did)
        }

        /// Get the DID linked to an account
        #[ink(message)]
        pub fn get_did_by_account(&self, account: Address) -> Option<String> {
            self.account_to_did.get(account)
        }

        /// Check if an account has a linked DID
        #[ink(message)]
        pub fn is_linked(&self, account: Address) -> bool {
            self.account_to_did.contains(account)
        }

        /// Check if a DID is already linked to an account
        #[ink(message)]
        pub fn is_did_linked(&self, did: String) -> bool {
            self.did_to_account.contains(&did)
        }

        /// Get the total number of linked accounts
        #[ink(message)]
        pub fn total_linked(&self) -> u32 {
            self.total_linked
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

        fn set_caller(caller: Address) {
            ink::env::test::set_caller(caller);
        }

        #[ink::test]
        fn new_works() {
            let contract = UserRegistry::new();
            assert_eq!(contract.total_linked(), 0);
            assert_eq!(contract.owner(), Address::default());
        }

        #[ink::test]
        fn link_account_works() {
            let alice = Address::from([0x01; 20]);
            set_caller(alice);

            let mut contract = UserRegistry::new();
            let did = String::from("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

            assert!(contract.link_account(did.clone()).is_ok());
            assert_eq!(contract.get_account_by_did(did.clone()), Some(alice));
            assert_eq!(contract.get_did_by_account(alice), Some(did));
            assert!(contract.is_linked(alice));
            assert_eq!(contract.total_linked(), 1);
        }

        #[ink::test]
        fn link_account_for_works() {
            let owner = Address::from([0x01; 20]);
            let user = Address::from([0x02; 20]);
            set_caller(owner);

            let mut contract = UserRegistry::new();
            let did = String::from("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

            // Owner can link on behalf of user
            assert!(contract.link_account_for(did.clone(), user).is_ok());
            assert_eq!(contract.get_account_by_did(did.clone()), Some(user));
            assert_eq!(contract.get_did_by_account(user), Some(did));
            assert!(contract.is_linked(user));
            assert_eq!(contract.total_linked(), 1);
        }

        #[ink::test]
        fn link_account_for_rejects_non_owner() {
            let owner = Address::from([0x01; 20]);
            let non_owner = Address::from([0x02; 20]);
            let user = Address::from([0x03; 20]);
            set_caller(owner);

            let mut contract = UserRegistry::new();

            // Switch to non-owner
            set_caller(non_owner);
            let did = String::from("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

            assert_eq!(
                contract.link_account_for(did, user),
                Err(Error::NotOwner)
            );
        }

        #[ink::test]
        fn link_account_rejects_empty_did() {
            let mut contract = UserRegistry::new();

            assert_eq!(contract.link_account(String::new()), Err(Error::EmptyDid));
        }

        #[ink::test]
        fn link_account_rejects_invalid_did_format() {
            let mut contract = UserRegistry::new();

            // Missing "did:key:" prefix
            assert_eq!(
                contract.link_account(String::from(
                    "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                )),
                Err(Error::InvalidDidFormat)
            );

            // Wrong DID method
            assert_eq!(
                contract.link_account(String::from("did:web:example.com")),
                Err(Error::InvalidDidFormat)
            );
        }

        #[ink::test]
        fn link_account_rejects_did_too_long() {
            let mut contract = UserRegistry::new();

            // Create a DID that exceeds MAX_DID_LENGTH (256 bytes)
            let long_suffix = "a".repeat(300);
            let long_did = ink::prelude::format!("did:key:{}", long_suffix);

            assert_eq!(contract.link_account(long_did), Err(Error::DidTooLong));
        }

        #[ink::test]
        fn link_account_rejects_duplicate_did() {
            let alice = Address::from([0x01; 20]);
            let bob = Address::from([0x02; 20]);
            let mut contract = UserRegistry::new();
            let did = String::from("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");

            // First link succeeds
            set_caller(alice);
            assert!(contract.link_account(did.clone()).is_ok());

            // Second link with same DID fails
            set_caller(bob);
            assert_eq!(contract.link_account(did), Err(Error::DidAlreadyLinked));
        }

        #[ink::test]
        fn link_account_rejects_duplicate_account() {
            let alice = Address::from([0x01; 20]);
            set_caller(alice);

            let mut contract = UserRegistry::new();
            let did1 = String::from("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
            let did2 = String::from("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH");

            // First link succeeds
            assert!(contract.link_account(did1).is_ok());

            // Second link with different DID fails (account already linked)
            assert_eq!(contract.link_account(did2), Err(Error::AccountAlreadyLinked));
        }

        #[ink::test]
        fn multiple_accounts_can_link() {
            let alice = Address::from([0x01; 20]);
            let bob = Address::from([0x02; 20]);
            let mut contract = UserRegistry::new();

            let did1 = String::from("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
            let did2 = String::from("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH");

            // Alice links
            set_caller(alice);
            assert!(contract.link_account(did1.clone()).is_ok());

            // Bob links with different DID
            set_caller(bob);
            assert!(contract.link_account(did2.clone()).is_ok());

            // Verify both are linked correctly
            assert_eq!(contract.get_account_by_did(did1), Some(alice));
            assert_eq!(contract.get_account_by_did(did2), Some(bob));
            assert_eq!(contract.total_linked(), 2);
        }

        #[ink::test]
        fn is_did_linked_works() {
            let alice = Address::from([0x01; 20]);
            set_caller(alice);

            let mut contract = UserRegistry::new();
            let did = String::from("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
            let unlinked_did =
                String::from("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH");

            assert!(!contract.is_did_linked(did.clone()));

            contract.link_account(did.clone()).unwrap();

            assert!(contract.is_did_linked(did));
            assert!(!contract.is_did_linked(unlinked_did));
        }

        #[ink::test]
        fn get_returns_none_for_unlinked() {
            let alice = Address::from([0x01; 20]);
            let contract = UserRegistry::new();

            assert_eq!(
                contract.get_account_by_did(String::from(
                    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                )),
                None
            );
            assert_eq!(contract.get_did_by_account(alice), None);
            assert!(!contract.is_linked(alice));
        }
    }
}
