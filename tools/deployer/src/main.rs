use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sp_core::sr25519::Pair;
use sp_keyring::AccountKeyring;
use std::path::PathBuf;
use subxt::{OnlineClient, PolkadotConfig};
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "deployer")]
#[command(about = "Deploy and manage Ink! smart contracts on Arkavo Node", long_about = None)]
struct Cli {
    /// WebSocket endpoint URL
    #[arg(short, long, default_value = "ws://127.0.0.1:9944")]
    endpoint: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Upload a contract's code to the chain
    Upload {
        /// Path to the contract .wasm file
        #[arg(short, long)]
        wasm: PathBuf,

        /// Account to use for upload (Alice, Bob, etc.)
        #[arg(short, long, default_value = "alice")]
        account: String,
    },

    /// Instantiate a contract
    Instantiate {
        /// Code hash of the uploaded contract
        #[arg(short, long)]
        code_hash: String,

        /// Constructor selector (hex)
        #[arg(short = 's', long, default_value = "0x9bae9d5e")]
        selector: String,

        /// Constructor arguments (hex)
        #[arg(short, long, default_value = "")]
        args: String,

        /// Initial balance to transfer to the contract
        #[arg(short, long, default_value = "0")]
        value: u128,

        /// Gas limit
        #[arg(short, long, default_value = "500000000000")]
        gas_limit: u64,

        /// Account to use for instantiation
        #[arg(short = 'a', long, default_value = "alice")]
        account: String,
    },

    /// Deploy all contracts (upload and instantiate)
    DeployAll {
        /// Directory containing contract .wasm and .json files
        #[arg(short, long, default_value = "./target/ink")]
        contracts_dir: PathBuf,

        /// Account to use for deployment
        #[arg(short, long, default_value = "alice")]
        account: String,
    },

    /// Query contract information
    Query {
        /// Contract address
        #[arg(short, long)]
        address: String,

        /// Message selector (hex)
        #[arg(short, long)]
        selector: String,

        /// Message arguments (hex)
        #[arg(short = 'r', long, default_value = "")]
        args: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    info!("Connecting to {}", cli.endpoint);
    let api = OnlineClient::<PolkadotConfig>::from_url(&cli.endpoint)
        .await
        .context("Failed to connect to node")?;

    info!("Connected successfully!");

    match cli.command {
        Commands::Upload { wasm, account } => {
            upload_contract(&api, wasm, &account).await?;
        }
        Commands::Instantiate {
            code_hash,
            selector,
            args,
            value,
            gas_limit,
            account,
        } => {
            instantiate_contract(
                &api, &code_hash, &selector, &args, value, gas_limit, &account,
            )
            .await?;
        }
        Commands::DeployAll {
            contracts_dir,
            account,
        } => {
            deploy_all_contracts(&api, contracts_dir, &account).await?;
        }
        Commands::Query {
            address,
            selector,
            args,
        } => {
            query_contract(&api, &address, &selector, &args).await?;
        }
    }

    Ok(())
}

async fn upload_contract(
    api: &OnlineClient<PolkadotConfig>,
    wasm_path: PathBuf,
    account_name: &str,
) -> Result<()> {
    info!("Uploading contract from {:?}", wasm_path);

    let _signer = get_signer(account_name)?;
    let _wasm = std::fs::read(&wasm_path).context("Failed to read WASM file")?;

    // Note: Full implementation requires subxt-based contract pallet integration
    // The contracts pallet extrinsic needs to be constructed using the runtime metadata
    // For production, use cargo-contract CLI which provides complete upload functionality
    // Example: cargo contract upload --suri //Alice target/ink/contract.wasm
    warn!("Contract upload not yet implemented - use cargo-contract CLI for deployment");
    info!("To upload contract: cargo contract upload --suri //{} {:?}",
        account_name.to_uppercase(), wasm_path);

    Ok(())
}

async fn instantiate_contract(
    api: &OnlineClient<PolkadotConfig>,
    _code_hash: &str,
    _selector: &str,
    _args: &str,
    _value: u128,
    _gas_limit: u64,
    account_name: &str,
) -> Result<()> {
    info!("Instantiating contract with account {}", account_name);

    let _signer = get_signer(account_name)?;

    // Note: Full implementation requires constructing contracts::instantiate extrinsic
    // This needs runtime metadata and proper gas weight estimation
    // For production, use cargo-contract CLI which handles all contract operations
    // Example: cargo contract instantiate --suri //Alice --constructor new
    warn!("Contract instantiation not yet implemented - use cargo-contract CLI");
    info!("To instantiate contract: cargo contract instantiate --suri //{} --constructor new",
        account_name.to_uppercase());

    Ok(())
}

async fn deploy_all_contracts(
    api: &OnlineClient<PolkadotConfig>,
    contracts_dir: PathBuf,
    account_name: &str,
) -> Result<()> {
    info!("Deploying all contracts from {:?}", contracts_dir);

    let contract_names = vec![
        "access_registry",
        "attribute_store",
        "policy_engine",
        "payment_integration",
    ];

    for contract_name in contract_names {
        let wasm_path = contracts_dir.join(format!("{}.wasm", contract_name));

        if wasm_path.exists() {
            info!("Deploying {}", contract_name);
            upload_contract(api, wasm_path, account_name).await?;
        } else {
            warn!(
                "Contract {} not found at {:?}",
                contract_name, wasm_path
            );
        }
    }

    Ok(())
}

async fn query_contract(
    api: &OnlineClient<PolkadotConfig>,
    _address: &str,
    _selector: &str,
    _args: &str,
) -> Result<()> {
    info!("Querying contract");

    // Note: Contract queries require constructing contract call RPC requests
    // The implementation needs contract ABI metadata and proper encoding
    // For production, use cargo-contract CLI or Polkadot.js for contract interaction
    // Example: cargo contract call --contract <addr> --message <selector>
    warn!("Contract query not yet implemented - use cargo-contract CLI or Polkadot.js");
    info!("To query contract: cargo contract call --contract {} --message {}",
        _address, _selector);

    Ok(())
}

fn get_signer(account_name: &str) -> Result<Pair> {
    let keyring = match account_name.to_lowercase().as_str() {
        "alice" => AccountKeyring::Alice,
        "bob" => AccountKeyring::Bob,
        "charlie" => AccountKeyring::Charlie,
        "dave" => AccountKeyring::Dave,
        "eve" => AccountKeyring::Eve,
        "ferdie" => AccountKeyring::Ferdie,
        _ => anyhow::bail!("Unknown account: {}", account_name),
    };

    Ok(keyring.pair())
}
