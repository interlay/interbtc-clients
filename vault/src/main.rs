mod api;
mod error;
mod issue;
mod redeem;
mod replace;
mod scheduler;
mod util;

use bitcoin::BitcoinCore;
use clap::Clap;
use error::Error;
use futures::channel::mpsc;
use issue::*;
use redeem::*;
use replace::*;
use runtime::{substrate_subxt::PairSigner, PolkaBtcProvider, PolkaBtcRuntime};
use scheduler::{CancelationScheduler, IssueEvent};
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use std::time::Duration;

/// The Vault client intermediates between Bitcoin Core
/// and the PolkaBTC Parachain.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// Keyring for vault.
    #[clap(long, default_value = "bob")]
    keyring: AccountKeyring,

    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::1]:3031")]
    http_addr: String,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    rpc_cors_domain: String,

    #[clap(long)]
    dev: bool,

    /// Timeout in milliseconds to repeat collateralization checks.
    #[clap(long, default_value = "5000")]
    collateral_timeout_ms: u64,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let btc_rpc = Arc::new(BitcoinCore::new(bitcoin::bitcoin_rpc_from_env()?));
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(opts.keyring.pair());
    let provider = PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?;
    let arc_provider = Arc::new(provider.clone());
    let auction_provider = arc_provider.clone();

    let num_confirmations = if opts.dev { 1 } else { 6 };
    let vault_id = opts.keyring.to_account_id();
    let collateral_timeout_ms = opts.collateral_timeout_ms;

    let (issue_event_tx, issue_event_rx) = mpsc::channel::<IssueEvent>(16);

    let mut cancelation_scheduler =
        CancelationScheduler::new(arc_provider.clone(), vault_id.clone());
    let issue_request_listener = listen_for_issue_requests(
        arc_provider.clone(),
        vault_id.clone(),
        issue_event_tx.clone(),
    );
    let issue_execute_listener = listen_for_issue_executes(
        arc_provider.clone(),
        vault_id.clone(),
        issue_event_tx.clone(),
    );
    let request_replace_listener =
        listen_for_replace_requests(arc_provider.clone(), vault_id.clone());
    let redeem_listener = listen_for_redeem_requests(
        arc_provider.clone(),
        btc_rpc.clone(),
        vault_id.clone(),
        num_confirmations,
    );
    let accept_replace_listener = listen_for_accept_replace(
        arc_provider.clone(),
        btc_rpc.clone(),
        vault_id.clone(),
        num_confirmations,
    );

    let api_listener = api::start(
        arc_provider.clone(),
        opts.http_addr.parse()?,
        opts.rpc_cors_domain,
    );

    let result = tokio::try_join!(
        tokio::spawn(async move {
            api_listener.await;
        }),
        tokio::spawn(async move {
            issue_request_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            issue_execute_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            cancelation_scheduler.issue_canceler(issue_event_rx).await;
        }),
        tokio::spawn(async move {
            redeem_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            request_replace_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            accept_replace_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            // we could automatically check vault collateralization rates on events
            // that affect this (e.g. `SetExchangeRate`, `WithdrawCollateral`) but
            // polling is easier for now
            util::check_every(Duration::from_secs(collateral_timeout_ms), || async {
                monitor_collateral_of_vaults(&auction_provider).await
            })
            .await;
        }),
    );
    match result {
        Ok(res) => {
            println!("{:?}", res);
        }
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    };

    Ok(())
}
