use staked_relayer::{system::*, Error};

use clap::Clap;
use runtime::{substrate_subxt::PairSigner, ConnectionManager, PolkaBtcRuntime};
use std::time::Duration;

/// The Staked Relayer client intermediates between Bitcoin Core
/// and the PolkaBTC Parachain.
#[derive(Clap)]
#[clap(version = "0.2", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Keyring / keyfile options.
    #[clap(flatten)]
    account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for the BTC-Parachain.
    #[clap(flatten)]
    parachain: runtime::cli::ConnectionOpts,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    bitcoin: bitcoin::cli::BitcoinOpts,

    /// Starting height for vault theft checks, if not defined
    /// automatically start from the chain tip.
    #[clap(long)]
    bitcoin_theft_start_height: Option<u32>,

    /// Timeout in milliseconds to poll Bitcoin.
    #[clap(long, default_value = "6000")]
    bitcoin_poll_timeout_ms: u64,

    /// Starting height to relay block headers, if not defined
    /// use the best height as reported by the relay module.
    #[clap(long)]
    bitcoin_relay_start_height: Option<u32>,

    /// Max batch size for combined block header submission.
    #[clap(long, default_value = "16")]
    max_batch_size: u32,

    /// Timeout in milliseconds to repeat oracle liveness check.
    #[clap(long, default_value = "5000")]
    oracle_timeout_ms: u64,

    /// Default deposit for all automated status proposals.
    #[clap(long, default_value = "100")]
    status_update_deposit: u128,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    rpc_cors_domain: String,

    /// Automatically register the relayer with the given stake (in Planck).
    #[clap(long)]
    auto_register_with_stake: Option<u128>,

    /// Automatically register the staked relayer with collateral received from the faucet and a newly generated
    /// address. The parameter is the URL of the faucet
    #[clap(long, conflicts_with("auto-register-with-stake"))]
    auto_register_with_faucet_url: Option<String>,

    /// Number of confirmations a block needs to have before it is submitted.
    #[clap(long, default_value = "0")]
    required_btc_confirmations: u32,
}

async fn start() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);

    let bitcoin_core = opts.bitcoin.new_client(None)?;

    ConnectionManager::<_, _, RelayerService>::new(
        opts.parachain.polka_btc_url.clone(),
        signer.clone(),
        RelayerServiceConfig {
            bitcoin_core,
            auto_register_with_stake: opts.auto_register_with_stake,
            auto_register_with_faucet_url: opts.auto_register_with_faucet_url,
            bitcoin_theft_start_height: opts.bitcoin_theft_start_height,
            bitcoin_relay_start_height: opts.bitcoin_relay_start_height,
            max_batch_size: opts.max_batch_size,
            bitcoin_timeout: Duration::from_millis(opts.bitcoin_poll_timeout_ms),
            oracle_timeout: Duration::from_millis(opts.oracle_timeout_ms),
            required_btc_confirmations: opts.required_btc_confirmations,
            status_update_deposit: opts.status_update_deposit,
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
