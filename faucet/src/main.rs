mod error;
mod http;

use clap::Clap;
use error::Error;
use git_version::git_version;
use runtime::InterBtcSigner;
use service::{on_shutdown, wait_or_shutdown};
use std::net::SocketAddr;

const VERSION: &str = git_version!(args = ["--tags"]);
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const NAME: &str = env!("CARGO_PKG_NAME");
const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

#[derive(Clap)]
#[clap(name = NAME, version = VERSION, author = AUTHORS, about = ABOUT)]
struct Opts {
    /// Keyring / keyfile options.
    #[clap(flatten)]
    account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for the BTC Parachain.
    #[clap(flatten)]
    parachain: runtime::cli::ConnectionOpts,

    /// Settings specific to the faucet client.
    #[clap(flatten)]
    faucet: FaucetConfig,
}

#[derive(Clap, Clone)]
pub struct FaucetConfig {
    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::0]:3033")]
    http_addr: SocketAddr,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    rpc_cors_domain: String,

    /// Allowance per request for regular users.
    #[clap(long, default_value = "1")]
    user_allowance: u128,

    /// Allowance per request for vaults.
    #[clap(long, default_value = "500")]
    vault_allowance: u128,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = InterBtcSigner::new(key_pair);

    let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);

    let parachain_config = opts.parachain;
    let faucet_config = opts.faucet;

    loop {
        let btc_parachain = parachain_config.try_connect(signer.clone()).await?;

        let close_handle = http::start_http(
            btc_parachain.clone(),
            faucet_config.http_addr,
            faucet_config.rpc_cors_domain.clone(),
            faucet_config.user_allowance,
            faucet_config.vault_allowance,
        )
        .await;

        // run block listener to restart faucet on disconnect
        let block_listener = wait_or_shutdown("Faucet Block Listener", shutdown_tx.clone(), async move {
            btc_parachain
                .on_block(move |header| async move {
                    log::debug!("Got block {:?}", header);
                    Ok(())
                })
                .await?;
            Ok(())
        });

        let http_server = on_shutdown(shutdown_tx.clone(), async move {
            close_handle.close();
        });

        let _ = futures::future::join(block_listener, http_server).await;
    }
}
