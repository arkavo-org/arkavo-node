use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: Option<Subcommand>,

    #[clap(flatten)]
    pub run: sc_cli::RunCmd,

    /// Path to TLS certificate file (PEM format) for secure RPC
    #[arg(long, value_name = "PATH")]
    pub rpc_tls_cert: Option<PathBuf>,

    /// Path to TLS private key file (PEM format) for secure RPC
    #[arg(long, value_name = "PATH")]
    pub rpc_tls_key: Option<PathBuf>,

    /// Port for TLS-enabled RPC server (default: 9945)
    #[arg(long, value_name = "PORT", default_value = "9945")]
    pub rpc_tls_port: u16,

    /// Bind address for TLS RPC server (default: 0.0.0.0)
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0")]
    pub rpc_tls_addr: String,
}

/// TLS configuration extracted from CLI args
#[derive(Clone)]
pub struct TlsConfig {
    /// Path to TLS certificate
    pub cert_path: PathBuf,
    /// Path to TLS private key
    pub key_path: PathBuf,
    /// Port for TLS server
    pub port: u16,
    /// Bind address for TLS server
    pub bind_addr: String,
}

impl Cli {
    /// Extract TLS configuration if both cert and key are provided
    pub fn tls_config(&self) -> Option<TlsConfig> {
        match (&self.rpc_tls_cert, &self.rpc_tls_key) {
            (Some(cert), Some(key)) => Some(TlsConfig {
                cert_path: cert.clone(),
                key_path: key.clone(),
                port: self.rpc_tls_port,
                bind_addr: self.rpc_tls_addr.clone(),
            }),
            _ => None,
        }
    }
}

#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Subcommand {
    /// Key management cli utilities
    #[command(subcommand)]
    Key(sc_cli::KeySubcommand),

    /// Build a chain specification.
    /// DEPRECATED: `build-spec` command will be removed after 1/04/2026. Use `export-chain-spec`
    /// command instead.
    #[deprecated(
        note = "build-spec command will be removed after 1/04/2026. Use export-chain-spec command instead"
    )]
    BuildSpec(sc_cli::BuildSpecCmd),

    /// Export the chain specification.
    ExportChainSpec(sc_cli::ExportChainSpecCmd),

    /// Validate blocks.
    CheckBlock(sc_cli::CheckBlockCmd),

    /// Export blocks.
    ExportBlocks(sc_cli::ExportBlocksCmd),

    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Import blocks.
    ImportBlocks(sc_cli::ImportBlocksCmd),

    /// Remove the whole chain.
    PurgeChain(sc_cli::PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Sub-commands concerned with benchmarking.
    #[command(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),

    /// Db meta columns information.
    ChainInfo(sc_cli::ChainInfoCmd),
}
