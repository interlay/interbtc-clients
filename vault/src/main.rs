use clap::Clap;
use runtime::{substrate_subxt::PairSigner, ConnectionManager, PolkaBtcRuntime};
use std::time::Duration;

use vault::{Error, VaultService, VaultServiceConfig};

/// The Vault client intermediates between Bitcoin Core
/// and the PolkaBTC Parachain.
#[derive(Clap, Debug, Clone)]
#[clap(version = "0.2", author = "Interlay <contact@interlay.io>")]
pub struct Opts {
    /// Keyring / keyfile options.
    #[clap(flatten)]
    pub account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for the BTC-Parachain.
    #[clap(flatten)]
    pub parachain: runtime::cli::ConnectionOpts,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    pub bitcoin: bitcoin::cli::BitcoinOpts,

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
}

async fn start() -> Result<(), Error> {
    vault::init_subscriber();
    let opts: Opts = Opts::parse();

    tracing::info!("Command line arguments: {:?}", opts.clone());

    let (pair, wallet_name) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(pair);

    let bitcoin_core = opts.bitcoin.new_client(Some(wallet_name.to_string()))?;

    ConnectionManager::<_, _, VaultService>::new(
        opts.parachain.polka_btc_url.clone(),
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
            rpc_cors_domain: opts.rpc_cors_domain,
        },
        opts.parachain.into(),
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
