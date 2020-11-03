#![recursion_limit = "256"]

mod api;
mod collateral;
mod error;
mod issue;
mod redeem;
mod replace;
mod scheduler;
mod util;

use bitcoin::BitcoinCore;
use clap::Clap;
use collateral::*;
use error::Error;
use futures::channel::mpsc;
use issue::*;
use log::*;
use redeem::*;
use replace::*;
use runtime::{substrate_subxt::PairSigner, PolkaBtcProvider, PolkaBtcRuntime};
use scheduler::{CancelationScheduler, ProcessEvent};
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

    // lock more collateral if required; this might be required if the vault
    // restarted. TODO: don't hardcode the amount
    if let Err(e) =
        lock_required_collateral(arc_provider.clone(), vault_id.clone(), 100_000_000 as u128).await
    {
        error!("Failed to lock the required additional collateral: {}", e);
    }
    let collateral_maintainer = maintain_collateralization_rate(
        arc_provider.clone(),
        vault_id.clone(),
        100_000_000 as u128,
    );

    // Issue handling
    let (issue_event_tx, issue_event_rx) = mpsc::channel::<ProcessEvent>(16);
    let mut issue_cancelation_scheduler =
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

    // replace handling
    let (replace_event_tx, replace_event_rx) = mpsc::channel::<ProcessEvent>(16);
    let mut replace_cancelation_scheduler =
        CancelationScheduler::new(arc_provider.clone(), vault_id.clone());
    let request_replace_listener = listen_for_replace_requests(
        arc_provider.clone(),
        vault_id.clone(),
        replace_event_tx.clone(),
    );
    let accept_replace_listener = listen_for_accept_replace(
        arc_provider.clone(),
        btc_rpc.clone(),
        vault_id.clone(),
        num_confirmations,
    );
    let execute_replace_listener =
        listen_for_execute_replace(arc_provider.clone(), vault_id.clone(), replace_event_tx);

    // redeem handling
    let redeem_listener = listen_for_redeem_requests(
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
            collateral_maintainer.await.unwrap();
        }),
        tokio::spawn(async move {
            issue_request_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            issue_execute_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            issue_cancelation_scheduler
                .handle_cancelation::<scheduler::IssueCanceler>(issue_event_rx)
                .await;
        }),
        // redeem handling
        tokio::spawn(async move {
            redeem_listener.await.unwrap();
        }),
        // replace handling
        tokio::spawn(async move {
            request_replace_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            accept_replace_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            execute_replace_listener.await.unwrap();
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
        tokio::spawn(async move {
            replace_cancelation_scheduler
                .handle_cancelation::<scheduler::ReplaceCanceler>(replace_event_rx)
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
