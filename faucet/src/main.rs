mod error;
mod http;
mod system;

use clap::Clap;
use error::Error;
use runtime::substrate_subxt::PairSigner;
use runtime::{ConnectionManager, PolkaBtcRuntime};
use system::{FaucetService, FaucetServiceConfig};

/// DOT faucet for enabling users to test PolkaBTC
#[derive(Clap)]
#[clap(version = "0.2", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Keyring / keyfile options.
    #[clap(flatten)]
    account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for the BTC-Parachain.
    #[clap(flatten)]
    parachain: runtime::cli::ConnectionOpts,

    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::0]:3033")]
    http_addr: String,

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
        opts.parachain.polka_btc_url.clone(),
        signer.clone(),
        FaucetServiceConfig {
            http_addr: opts.http_addr.parse()?,
            rpc_cors_domain: opts.rpc_cors_domain,
            user_allowance: opts.user_allowance,
            vault_allowance: opts.vault_allowance,
            staked_relayer_allowance: opts.staked_relayer_allowance,
        },
        opts.parachain.into(),
        tokio::runtime::Handle::current(),
    )
    .start()
    .await?;

    Ok(())
}
