//! TLS-enabled RPC server for secure WebSocket connections (wss://)

use std::{fs::File, io::BufReader, net::SocketAddr, path::Path, sync::Arc};

use jsonrpsee::{
    Methods,
    server::{serve_with_graceful_shutdown, stop_channel},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sc_rpc_api::DenyUnsafe;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;

/// Error type for TLS RPC server operations
#[derive(Debug)]
pub enum TlsRpcError {
    /// Failed to load TLS certificate
    CertificateLoad(String),
    /// Failed to load TLS private key
    KeyLoad(String),
    /// TLS configuration error
    TlsConfig(String),
    /// IO error
    Io(std::io::Error),
}

impl std::fmt::Display for TlsRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertificateLoad(e) => write!(f, "Failed to load certificate: {e}"),
            Self::KeyLoad(e) => write!(f, "Failed to load private key: {e}"),
            Self::TlsConfig(e) => write!(f, "TLS configuration error: {e}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for TlsRpcError {}

/// Configuration for the TLS RPC server
pub struct TlsRpcConfig {
    /// Path to the TLS certificate file (PEM format)
    pub cert_path: std::path::PathBuf,
    /// Path to the TLS private key file (PEM format)
    pub key_path: std::path::PathBuf,
    /// Port to listen on
    pub port: u16,
    /// Bind address (default: 0.0.0.0)
    pub bind_addr: String,
}

/// Load certificates from a PEM file
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsRpcError> {
    let file = File::open(path)
        .map_err(|e| TlsRpcError::CertificateLoad(format!("{}: {e}", path.display())))?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsRpcError::CertificateLoad(format!("PEM parse error: {e}")))
}

/// Load private key from a PEM file
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsRpcError> {
    let file =
        File::open(path).map_err(|e| TlsRpcError::KeyLoad(format!("{}: {e}", path.display())))?;
    let mut reader = BufReader::new(file);

    // Try to read any type of private key (RSA, PKCS8, EC)
    loop {
        match rustls_pemfile::read_one(&mut reader) {
            Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Ok(Some(rustls_pemfile::Item::Sec1Key(key))) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            Ok(Some(_)) => continue, // Skip other items (certs, etc.)
            Ok(None) => {
                return Err(TlsRpcError::KeyLoad("No private key found in file".into()));
            }
            Err(e) => {
                return Err(TlsRpcError::KeyLoad(format!("PEM parse error: {e}")));
            }
        }
    }
}

/// Create a TLS acceptor from certificate and key paths
fn create_tls_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, TlsRpcError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    // Use the ring crypto provider (aws-lc-rs requires additional build deps)
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| TlsRpcError::TlsConfig(format!("Protocol version error: {e}")))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| TlsRpcError::TlsConfig(format!("ServerConfig error: {e}")))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Start the TLS RPC server
///
/// This spawns a new server that listens for TLS-encrypted WebSocket
/// connections and serves the provided RPC methods.
pub async fn start_tls_rpc_server(
    config: TlsRpcConfig,
    methods: Methods,
) -> Result<(), TlsRpcError> {
    let tls_acceptor = create_tls_acceptor(&config.cert_path, &config.key_path)?;

    let addr: SocketAddr = format!("{}:{}", config.bind_addr, config.port)
        .parse()
        .map_err(|e| TlsRpcError::TlsConfig(format!("Invalid address: {e}")))?;

    let listener = TcpListener::bind(addr).await.map_err(TlsRpcError::Io)?;

    log::info!(
        "TLS RPC server listening on wss://{}:{}",
        config.bind_addr,
        config.port
    );

    let (stop_handle, server_handle) = stop_channel();

    // For TLS connections (public-facing), always deny unsafe methods
    let deny_unsafe = DenyUnsafe::Yes;

    // Accept connections loop
    loop {
        let tcp_stream = tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, peer_addr)) => {
                        log::debug!("TLS RPC: Accepted TCP connection from {peer_addr}");
                        stream
                    }
                    Err(e) => {
                        log::error!("TLS RPC: Failed to accept connection: {e}");
                        continue;
                    }
                }
            }
            _ = stop_handle.clone().shutdown() => {
                log::info!("TLS RPC server shutting down");
                break;
            }
        };

        // Clone everything needed for this connection
        let tls_acceptor = tls_acceptor.clone();
        let methods = methods.clone();
        let stop_handle = stop_handle.clone();

        // Spawn TLS handshake task
        tokio::spawn(async move {
            // Perform TLS handshake
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    log::warn!("TLS RPC: TLS handshake failed: {e}");
                    return;
                }
            };

            log::debug!("TLS RPC: TLS handshake successful");

            // Build the service builder fresh for this connection
            let svc_builder = jsonrpsee::server::Server::builder()
                .max_connections(100)
                .to_service_builder();

            // Create service with DenyUnsafe extension injected per request
            // Following substrate's pattern exactly
            let svc = tower::service_fn(move |mut req: http::Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(deny_unsafe);

                let methods = methods.clone();
                let svc_builder = svc_builder.clone();
                let stop_handle = stop_handle.clone();

                async move {
                    let mut svc = svc_builder.build(methods, stop_handle);
                    // https://github.com/rust-lang/rust/issues/102211 the error type can't be inferred
                    // to be `Box<dyn std::error::Error + Send + Sync>` so we need to
                    // convert it to a concrete type as workaround.
                    svc.call(req)
                        .await
                        .map_err(|e| jsonrpsee::core::BoxError::from(e))
                }
            });

            // Spawn the serve task directly - this avoids the lifetime issue
            // by not nesting it inside another async block
            tokio::spawn(serve_with_graceful_shutdown(
                tls_stream,
                svc,
                std::future::pending::<()>(),
            ));
        });
    }

    // Wait for in-flight connections to complete
    server_handle.stopped().await;
    log::info!("TLS RPC server stopped");

    Ok(())
}
