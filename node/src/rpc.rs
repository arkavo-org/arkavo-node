//! A collection of node-specific RPC methods.
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]

use std::sync::Arc;

use arkavo_runtime::{AccountId, Balance, Nonce, opaque::Block};
use jsonrpsee::RpcModule;
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};

pub use auth_api::AuthApiServer;

/// Authentication API module for DID-to-account linking
/// Note: This is a secured backchannel RPC - no token verification needed
mod auth_api {
    use super::*;
    use jsonrpsee::{core::RpcResult, proc_macros::rpc};
    use pallet_revive::{H160, ReviveApi};
    use serde::{Deserialize, Serialize};
    use sp_core::crypto::Ss58Codec;

    /// Result of linking a DID to a blockchain address
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LinkAccountResult {
        /// Whether the linking was successful
        pub success: bool,
        /// The linked DID
        pub did: Option<String>,
        /// The linked address
        pub address: Option<String>,
        /// The user ID from authnz-rs
        pub user_id: Option<String>,
        /// Error message (if failed)
        pub error: Option<String>,
    }

    /// Configuration for user registry contract
    #[derive(Clone)]
    pub struct UserRegistryConfig {
        /// The deployed user_registry contract address (H160)
        pub contract_address: H160,
        /// The account that owns the contract (can call link_account_for)
        pub owner_account: AccountId,
    }

    /// AuthnZ RPC API for DID account linking (secured backchannel)
    #[rpc(server, client, namespace = "arkavo")]
    pub trait AuthApi {
        /// Link a DID to a blockchain address
        ///
        /// This is a secured backchannel RPC called by authnz-rs after successful
        /// WebAuthn registration. No token verification is performed as the
        /// channel is already secured.
        ///
        /// # Arguments
        /// * `user_id` - User UUID from authnz-rs
        /// * `did` - Decentralized Identifier (must start with "did:key:")
        /// * `address` - EVM-compatible blockchain address (0x-prefixed, 20 bytes hex)
        #[method(name = "linkAccountWithProof")]
        fn link_account_with_proof(
            &self,
            user_id: String,
            did: String,
            address: String,
        ) -> RpcResult<LinkAccountResult>;
    }

    /// Implementation of the AuthApi (secured backchannel - no token verification)
    pub struct AuthApiImpl<C> {
        /// Substrate client for runtime API calls
        client: Arc<C>,
        /// Optional user registry configuration
        config: Option<UserRegistryConfig>,
    }

    impl<C> AuthApiImpl<C> {
        /// Create a new AuthApi instance with client and optional contract config
        pub fn new(client: Arc<C>, config: Option<UserRegistryConfig>) -> Self {
            Self { client, config }
        }
    }

    /// Encode ink! contract call for `link_account_for(did: String, account: Address)`
    ///
    /// Ink! message encoding format:
    /// - 4 bytes: selector (blake2b hash of "link_account_for" truncated to 4 bytes)
    /// - SCALE-encoded arguments
    fn encode_link_account_for(did: &str, account: H160) -> Vec<u8> {
        use parity_scale_codec::Encode;

        // Ink! selector for "link_account_for" - computed as blake2b("link_account_for")[0..4]
        // Using ink!'s selector computation: blake2b_256("link_account_for")[0..4]
        let selector: [u8; 4] = {
            use sp_core::hashing::blake2_256;
            let hash = blake2_256(b"link_account_for");
            [hash[0], hash[1], hash[2], hash[3]]
        };

        let mut encoded = selector.to_vec();
        // Encode the DID string (SCALE: length-prefixed bytes)
        encoded.extend(did.encode());
        // Encode the H160 address (SCALE: 20 bytes, fixed size)
        encoded.extend(account.encode());

        encoded
    }

    /// Parse H160 address from hex string (0x-prefixed)
    fn parse_h160(address: &str) -> Result<H160, String> {
        if !address.starts_with("0x") || address.len() != 42 {
            return Err("Invalid address format: must be 0x-prefixed 20-byte hex".to_string());
        }

        let bytes =
            hex::decode(&address[2..]).map_err(|e| format!("Invalid hex in address: {}", e))?;

        if bytes.len() != 20 {
            return Err("Address must be exactly 20 bytes".to_string());
        }

        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(H160::from(arr))
    }

    impl<C> AuthApiServer for AuthApiImpl<C>
    where
        C: ProvideRuntimeApi<Block>,
        C: HeaderBackend<Block> + 'static,
        C: Send + Sync + 'static,
        C::Api: pallet_revive::ReviveApi<Block, AccountId, Balance, Nonce, u32>,
    {
        fn link_account_with_proof(
            &self,
            user_id: String,
            did: String,
            address: String,
        ) -> RpcResult<LinkAccountResult> {
            // Validate user_id is a valid UUID
            if uuid::Uuid::parse_str(&user_id).is_err() {
                return Ok(LinkAccountResult {
                    success: false,
                    did: None,
                    address: None,
                    user_id: None,
                    error: Some("Invalid user_id: must be a valid UUID".to_string()),
                });
            }

            // Validate and parse address
            let target_address = match parse_h160(&address) {
                Ok(addr) => addr,
                Err(e) => {
                    return Ok(LinkAccountResult {
                        success: false,
                        did: None,
                        address: None,
                        user_id: None,
                        error: Some(e),
                    });
                }
            };

            // Validate DID format
            if !did.starts_with("did:key:") {
                return Ok(LinkAccountResult {
                    success: false,
                    did: None,
                    address: None,
                    user_id: None,
                    error: Some("Invalid DID format: must start with 'did:key:'".to_string()),
                });
            }

            // Check if contract is configured
            let Some(config) = &self.config else {
                log::warn!(
                    "Account linking requested but USER_REGISTRY_ADDRESS not configured. \
                     user_id={}, did={}, address={}",
                    user_id,
                    did,
                    address
                );
                return Ok(LinkAccountResult {
                    success: false,
                    did: Some(did),
                    address: Some(address),
                    user_id: Some(user_id),
                    error: Some(
                        "User registry contract not configured. Set USER_REGISTRY_ADDRESS and USER_REGISTRY_OWNER environment variables.".to_string()
                    ),
                });
            };

            // Encode the contract call
            let input_data = encode_link_account_for(&did, target_address);

            // Get the best block hash for the runtime API call
            let at = self.client.info().best_hash;

            // Call the contract via runtime API
            let result = self.client.runtime_api().call(
                at,
                config.owner_account.clone(),
                config.contract_address,
                0,    // No value transfer
                None, // Default gas limit
                None, // Default storage deposit limit
                input_data,
            );

            match result {
                Ok(contract_result) => {
                    // Check if the contract call succeeded
                    match contract_result.result {
                        Ok(exec_result) => {
                            // Check the return flags - empty means success
                            if exec_result.flags.is_empty() {
                                log::info!(
                                    "Account linked on-chain: user_id={}, did={}, address={}",
                                    user_id,
                                    did,
                                    address
                                );
                                Ok(LinkAccountResult {
                                    success: true,
                                    did: Some(did),
                                    address: Some(address),
                                    user_id: Some(user_id),
                                    error: None,
                                })
                            } else {
                                // Contract returned an error
                                let error_msg = decode_contract_error(&exec_result.data);
                                log::error!(
                                    "Contract call failed: user_id={}, did={}, address={}, error={}",
                                    user_id,
                                    did,
                                    address,
                                    error_msg
                                );
                                Ok(LinkAccountResult {
                                    success: false,
                                    did: Some(did),
                                    address: Some(address),
                                    user_id: Some(user_id),
                                    error: Some(error_msg),
                                })
                            }
                        }
                        Err(error) => {
                            log::error!(
                                "Contract execution failed: user_id={}, did={}, address={}, error={:?}",
                                user_id,
                                did,
                                address,
                                error
                            );
                            Ok(LinkAccountResult {
                                success: false,
                                did: Some(did),
                                address: Some(address),
                                user_id: Some(user_id),
                                error: Some(format!("Contract execution failed: {:?}", error)),
                            })
                        }
                    }
                }
                Err(e) => {
                    log::error!(
                        "Runtime API call failed: user_id={}, did={}, address={}, error={}",
                        user_id,
                        did,
                        address,
                        e
                    );
                    Ok(LinkAccountResult {
                        success: false,
                        did: Some(did),
                        address: Some(address),
                        user_id: Some(user_id),
                        error: Some(format!("Runtime API error: {}", e)),
                    })
                }
            }
        }
    }

    /// Decode contract error from return data
    /// The user_registry contract returns SCALE-encoded Error enum
    fn decode_contract_error(data: &[u8]) -> String {
        // Try to decode as our Error enum variant index
        if data.is_empty() {
            return "Unknown contract error (empty data)".to_string();
        }

        // The first byte is the enum variant index
        match data[0] {
            0 => "DID is already linked to another account".to_string(),
            1 => "Account is already linked to a DID".to_string(),
            2 => "Invalid DID format".to_string(),
            3 => "Empty DID".to_string(),
            4 => "Not the contract owner".to_string(),
            _ => format!("Unknown contract error (code: {})", data[0]),
        }
    }

    /// Load user registry configuration from environment
    pub fn load_config_from_env() -> Option<UserRegistryConfig> {
        let contract_address_str = std::env::var("USER_REGISTRY_ADDRESS").ok()?;
        let owner_account_str = std::env::var("USER_REGISTRY_OWNER").ok()?;

        // Parse contract address (0x-prefixed H160)
        let contract_address = match parse_h160(&contract_address_str) {
            Ok(addr) => addr,
            Err(e) => {
                log::error!("Invalid USER_REGISTRY_ADDRESS: {}", e);
                return None;
            }
        };

        // Parse owner account (SS58 format)
        let owner_account = match AccountId::from_ss58check(&owner_account_str) {
            Ok(account) => account,
            Err(e) => {
                log::error!(
                    "Invalid USER_REGISTRY_OWNER (expected SS58 format): {:?}",
                    e
                );
                return None;
            }
        };

        log::info!(
            "User registry configured: contract={}, owner={}",
            contract_address_str,
            owner_account_str
        );

        Some(UserRegistryConfig {
            contract_address,
            owner_account,
        })
    }
}

/// Full client dependencies.
pub struct FullDeps<C, P> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
}

/// Instantiate all full RPC extensions.
pub fn create_full<C, P>(
    deps: FullDeps<C, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    C: ProvideRuntimeApi<Block>,
    C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + 'static,
    C: Send + Sync + 'static,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
    C::Api: pallet_revive::ReviveApi<Block, AccountId, Balance, Nonce, u32>,
    C::Api: BlockBuilder<Block>,
    P: TransactionPool + 'static,
{
    use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
    use substrate_frame_rpc_system::{System, SystemApiServer};

    let mut module = RpcModule::new(());
    let FullDeps { client, pool } = deps;

    module.merge(System::new(client.clone(), pool).into_rpc())?;
    module.merge(TransactionPayment::new(client.clone()).into_rpc())?;

    // Load user registry config from environment
    let user_registry_config = auth_api::load_config_from_env();

    // Add AuthnZ API for DID account linking (secured backchannel)
    let auth_api = auth_api::AuthApiImpl::new(client, user_registry_config);
    module.merge(auth_api.into_rpc())?;

    Ok(module)
}
