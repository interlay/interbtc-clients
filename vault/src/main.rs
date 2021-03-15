use bitcoin::{BitcoinCore, BitcoinCoreApi};
use clap::Clap;
use log::*;
use runtime::substrate_subxt::PairSigner;
use runtime::{ConnectionManager, ConnectionManagerConfig, PolkaBtcRuntime, RestartPolicy};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use vault::Error;
use vault::{VaultService, VaultServiceConfig};

#[derive(Debug, Copy, Clone)]
pub struct BitcoinNetwork(pub bitcoin::Network);

impl FromStr for BitcoinNetwork {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "mainnet" => Ok(BitcoinNetwork(bitcoin::Network::Bitcoin)),
            "testnet" => Ok(BitcoinNetwork(bitcoin::Network::Testnet)),
            "regtest" => Ok(BitcoinNetwork(bitcoin::Network::Regtest)),
            _ => Err(Error::InvalidBitcoinNetwork),
        }
    }
}

/// The Vault client intermediates between Bitcoin Core
/// and the PolkaBTC Parachain.
#[derive(Clap, Debug, Clone)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
pub struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    pub polka_btc_url: String,

    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::0]:3031")]
    pub http_addr: String,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    pub rpc_cors_domain: String,

    /// Automatically register the vault with the given amount of collateral and a newly generated address.
    #[clap(long)]
    pub auto_register_with_collateral: Option<u128>,

    /// Automatically register the vault with the collateral received from the faucet and a newly generated address.
    /// The parameter is the URL of the faucet
    #[clap(long, conflicts_with("auto-register-with-collateral"))]
    pub auto_register_with_faucet_url: Option<String>,

    /// Opt out of auctioning under-collateralized vaults.
    #[clap(long)]
    pub no_auto_auction: bool,

    /// Opt out of participation in replace requests.
    #[clap(long)]
    pub no_auto_replace: bool,

    /// Don't check the collateralization rate at startup.
    #[clap(long)]
    pub no_startup_collateral_increase: bool,

    /// Don't try to execute issues.
    #[clap(long)]
    pub no_issue_execution: bool,

    /// Don't run the RPC API.
    #[clap(long)]
    pub no_api: bool,

    /// Maximum total collateral to keep the vault securely collateralized.
    #[clap(long, default_value = "1000000")]
    pub max_collateral: u128,

    /// Timeout in milliseconds to repeat collateralization checks.
    #[clap(long, default_value = "5000")]
    pub collateral_timeout_ms: u64,

    /// How many bitcoin confirmations to wait for. If not specified, the
    /// parachain settings will be used (recommended).
    #[clap(long)]
    pub btc_confirmations: Option<u32>,

    /// keyring / keyfile options.
    #[clap(flatten)]
    pub account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    pub bitcoin: bitcoin::cli::BitcoinOpts,

    /// Bitcoin network type for address encoding.
    #[clap(long, default_value = "regtest")]
    pub network: BitcoinNetwork,

    /// Timeout in milliseconds to poll Bitcoin.
    #[clap(long, default_value = "6000")]
    pub bitcoin_timeout_ms: u64,

    /// Timeout in milliseconds to wait for connection to btc-parachain.
    #[clap(long, default_value = "60000")]
    pub connection_timeout_ms: u64,

    /// What to do if the connection to the btc-parachain drops.
    #[clap(long, default_value = "always")]
    pub restart_policy: RestartPolicy,
}

async fn start() -> Result<(), Error> {
    env_logger::init_from_env(env_logger::Env::default().filter_or(
        env_logger::DEFAULT_FILTER_ENV,
        log::LevelFilter::Info.as_str(),
    ));
    let opts: Opts = Opts::parse();

    info!("Command line arguments: {:?}", opts.clone());

    let (pair, wallet) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(pair);

    let bitcoin_core = BitcoinCore::new_with_retry(
        Arc::new(opts.bitcoin.new_client(Some(&wallet))?),
        opts.network.0,
        Duration::from_millis(opts.connection_timeout_ms),
    )
    .await?;

    // load wallet. Exit on failure, since without wallet we can't do a lot
    bitcoin_core
        .create_wallet(&wallet)
        .await
        .map_err(|e| Error::WalletInitializationFailure(e))?;

    // only open connection to parachain after bitcoind sync to prevent timeout
    ConnectionManager::<_, _, VaultService>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        VaultServiceConfig {
            bitcoin_core,
            auto_register_with_collateral: opts.auto_register_with_collateral,
            auto_register_with_faucet_url: opts.auto_register_with_faucet_url,
            no_startup_collateral_increase: opts.no_startup_collateral_increase,
            btc_confirmations: opts.btc_confirmations,
            max_collateral: opts.max_collateral,
            no_auto_replace: opts.no_auto_replace,
            no_auto_auction: opts.no_auto_auction,
            no_issue_execution: opts.no_issue_execution,
            collateral_timeout: Duration::from_millis(opts.collateral_timeout_ms),

            http_addr: opts.http_addr.parse()?,
            rpc_cors_domain: opts.rpc_cors_domain,
        },
        ConnectionManagerConfig {
            retry_timeout: Duration::from_millis(opts.connection_timeout_ms),
            restart_policy: opts.restart_policy,
        },
        tokio::runtime::Handle::current(),
    )
    .start()
    .await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    let exit_code = if let Err(err) = start().await {
        eprintln!("Error: {}", err);
        1
    } else {
        0
    };
    std::process::exit(exit_code);
}
