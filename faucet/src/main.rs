mod error;
mod http;

use clap::Clap;
use error::Error;
use runtime::substrate_subxt::PairSigner;
use runtime::{PolkaBtcProvider, PolkaBtcRuntime};
use std::sync::Arc;

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
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);
    let provider = Arc::new(PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?);

    let http_addr = opts.http_addr.parse()?;
    http::start(
        provider.clone(),
        http_addr,
        opts.rpc_cors_domain,
        opts.user_allowance,
        opts.vault_allowance,
        opts.staked_relayer_allowance,
    )
    .await;

    Ok(())
}
