mod error;
mod http;
mod system;

use clap::Clap;
use error::Error;
use runtime::substrate_subxt::PairSigner;
use runtime::{ConnectionManager, ConnectionManagerConfig, PolkaBtcRuntime, RestartPolicy};
use std::time::Duration;
use system::{FaucetService, FaucetServiceConfig};

/// DOT faucet for enabling users to test PolkaBTC
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::0]:3033")]
    http_addr: String,

    /// keyring / keyfile options.
    #[clap(flatten)]
    account_info: runtime::cli::ProviderUserOpts,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    rpc_cors_domain: String,

    /// DOT allowance per request for regular users.
    #[clap(long, default_value = "1")]
    user_allowance: u128,

    /// DOT allowance per request for vaults.
    #[clap(long, default_value = "500")]
    vault_allowance: u128,

    /// DOT allowance per request for vaults.
    #[clap(long, default_value = "500")]
    staked_relayer_allowance: u128,

    /// Timeout in milliseconds to wait for connection to btc-parachain.
    #[clap(long, default_value = "60000")]
    connection_timeout_ms: u64,

    /// What to do if the connection to the btc-parachain drops.
    #[clap(long, default_value = "always")]
    restart_policy: RestartPolicy,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(env_logger::Env::default().filter_or(
        env_logger::DEFAULT_FILTER_ENV,
        log::LevelFilter::Info.as_str(),
    ));
    let opts: Opts = Opts::parse();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);

    ConnectionManager::<_, _, FaucetService>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        FaucetServiceConfig {
            http_addr: opts.http_addr.parse()?,
            rpc_cors_domain: opts.rpc_cors_domain,
            user_allowance: opts.user_allowance,
            vault_allowance: opts.vault_allowance,
            staked_relayer_allowance: opts.staked_relayer_allowance,
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
