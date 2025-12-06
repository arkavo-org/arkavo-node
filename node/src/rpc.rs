//! A collection of node-specific RPC methods.
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]

use std::sync::Arc;

use arkavo_runtime::{opaque::Block, AccountId, Balance, Nonce};
use jsonrpsee::RpcModule;
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};

pub use auth_api::AuthApiServer;

/// Authentication API module for JWT verification
mod auth_api {
    use jsonrpsee::{core::RpcResult, proc_macros::rpc};
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    /// JWT Claims for registration tokens (includes passkey data)
    #[derive(Debug, Serialize, Deserialize)]
    pub struct AccountTokenClaims {
        /// User unique ID (UUID)
        pub user_unique_id: Option<String>,
        /// Subject (user_id as string)
        pub sub: String,
        /// Expiration timestamp
        pub exp: usize,
    }

    /// Authentication token verification result
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthTokenInfo {
        /// Whether the token signature is valid
        pub valid: bool,
        /// User ID extracted from token (if valid)
        pub user_id: Option<String>,
        /// Error message (if invalid)
        pub error: Option<String>,
        /// Token expiration timestamp (if valid)
        pub expires_at: Option<u64>,
    }

    /// AuthnZ RPC API for JWT verification and DID account lookups
    #[rpc(server, client, namespace = "arkavo")]
    pub trait AuthApi {
        /// Verify a JWT token from authnz-rs
        ///
        /// Returns token validity and extracted claims if valid.
        /// Note: authnz-rs intentionally disables exp/nbf validation
        /// as security relies on WebAuthn ceremony, not token expiration.
        #[method(name = "verifyAuthToken")]
        fn verify_auth_token(&self, jwt: String) -> RpcResult<AuthTokenInfo>;
    }

    /// Implementation of the AuthApi
    pub struct AuthApiImpl {
        /// Optional decoding key for JWT verification
        /// If None, JWT verification will fail with configuration error
        decoding_key: Option<Arc<DecodingKey>>,
    }

    impl AuthApiImpl {
        /// Create a new AuthApi instance without a decoding key
        /// JWT verification will return an error until a key is configured
        pub fn new() -> Self {
            Self { decoding_key: None }
        }

        /// Create a new AuthApi instance with a PEM-encoded public key
        ///
        /// # Arguments
        /// * `pem_key` - PEM-encoded EC public key for ES256 verification
        pub fn with_pem_key(pem_key: &[u8]) -> Result<Self, String> {
            let decoding_key = DecodingKey::from_ec_pem(pem_key)
                .map_err(|e| format!("Failed to parse EC public key: {e}"))?;
            Ok(Self {
                decoding_key: Some(Arc::new(decoding_key)),
            })
        }
    }

    impl Default for AuthApiImpl {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AuthApiServer for AuthApiImpl {
        fn verify_auth_token(&self, jwt: String) -> RpcResult<AuthTokenInfo> {
            let Some(decoding_key) = &self.decoding_key else {
                return Ok(AuthTokenInfo {
                    valid: false,
                    user_id: None,
                    error: Some(
                        "JWT verification not configured. Set AUTHNZ_PUBLIC_KEY_PATH environment variable.".to_string(),
                    ),
                    expires_at: None,
                });
            };

            // Configure validation for ES256 (ECDSA with P-256)
            // Note: authnz-rs intentionally disables exp/nbf validation
            // Security relies on WebAuthn ceremony, not token expiration
            let mut validation = Validation::new(Algorithm::ES256);
            validation.validate_exp = false;
            validation.validate_nbf = false;

            match decode::<AccountTokenClaims>(&jwt, decoding_key, &validation) {
                Ok(token_data) => {
                    let claims = token_data.claims;
                    Ok(AuthTokenInfo {
                        valid: true,
                        user_id: Some(claims.sub.clone()),
                        error: None,
                        expires_at: Some(claims.exp as u64),
                    })
                }
                Err(e) => Ok(AuthTokenInfo {
                    valid: false,
                    user_id: None,
                    error: Some(format!("Token verification failed: {e}")),
                    expires_at: None,
                }),
            }
        }
    }
}

/// Full client dependencies.
pub struct FullDeps<C, P> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
    /// Optional path to authnz-rs public key for JWT verification
    pub authnz_public_key: Option<Vec<u8>>,
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
    C::Api: BlockBuilder<Block>,
    P: TransactionPool + 'static,
{
    use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
    use substrate_frame_rpc_system::{System, SystemApiServer};

    let mut module = RpcModule::new(());
    let FullDeps {
        client,
        pool,
        authnz_public_key,
    } = deps;

    module.merge(System::new(client.clone(), pool).into_rpc())?;
    module.merge(TransactionPayment::new(client).into_rpc())?;

    // Add AuthnZ API for JWT verification
    let auth_api = if let Some(key_bytes) = authnz_public_key {
        auth_api::AuthApiImpl::with_pem_key(&key_bytes).unwrap_or_else(|e| {
            log::warn!("Failed to initialize AuthApi with public key: {e}");
            auth_api::AuthApiImpl::new()
        })
    } else {
        log::info!(
            "AuthnZ public key not configured. Set AUTHNZ_PUBLIC_KEY_PATH to enable JWT verification."
        );
        auth_api::AuthApiImpl::new()
    };
    module.merge(auth_api.into_rpc())?;

    Ok(module)
}
