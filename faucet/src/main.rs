mod error;
mod http;

use clap::Parser;
use error::Error;
use git_version::git_version;
use runtime::{InterBtcSigner, ShutdownSender};
use serde::Deserialize;
use service::{on_shutdown, wait_or_shutdown};
use shared::{Allowance, AllowanceAmount};
use std::{net::SocketAddr, path::PathBuf};
const VERSION: &str = git_version!(args = ["--tags"]);
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const NAME: &str = env!("CARGO_PKG_NAME");
const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

#[derive(Parser)]
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

    /// Allowance config
    #[clap(long, default_value = "./faucet-allowance-config.json")]
    allowance_config: PathBuf,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AllowanceConfig {
    pub max_fundable_client_balance: u128,
    pub faucet_cooldown_hours: i64,
    pub user_allowances: Allowance,
    pub vault_allowances: Allowance,
    pub auth_url: Option<String>,
}

impl AllowanceConfig {
    pub fn new(
        max_fundable_client_balance: u128,
        faucet_cooldown_hours: i64,
        user_allowances: Allowance,
        vault_allowances: Allowance,
    ) -> Self {
        Self {
            max_fundable_client_balance,
            faucet_cooldown_hours,
            user_allowances,
            vault_allowances,
            auth_url: None,
        }
    }
}

#[derive(Parser, Clone)]
pub struct FaucetConfig {
    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::0]:3033")]
    http_addr: SocketAddr,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    rpc_cors_domain: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = InterBtcSigner::new(key_pair);

    let shutdown_tx = ShutdownSender::new();

    let parachain_config = opts.parachain;
    let faucet_config = opts.faucet;

    let data = std::fs::read_to_string(opts.allowance_config)?;
    let allowance_config = serde_json::from_str::<AllowanceConfig>(&data)?;

    loop {
        let btc_parachain = parachain_config
            .try_connect(signer.clone(), shutdown_tx.clone())
            .await?;

        let close_handle = http::start_http(
            btc_parachain.clone(),
            faucet_config.http_addr,
            faucet_config.rpc_cors_domain.clone(),
            allowance_config.clone(),
        )
        .await;

        // run block listener to restart faucet on disconnect
        let block_listener = wait_or_shutdown(shutdown_tx.clone(), async move {
            btc_parachain
                .on_block(move |header| async move {
                    log::debug!("Got block {:?}", header);
                    Ok(())
                })
                .await?;
            Ok::<_, Error>(())
        });

        let http_server = on_shutdown(shutdown_tx.clone(), async move {
            close_handle.close();
        });

        let _ = futures::future::join(block_listener, http_server).await;
    }
}
