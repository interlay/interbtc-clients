#![recursion_limit = "256"]

mod api;
mod cancellation;
mod collateral;
mod constants;
mod error;
mod execution;
mod issue;
mod redeem;
mod replace;

use crate::constants::*;
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use cancellation::{CancellationScheduler, IssueCanceller, ProcessEvent, ReplaceCanceller};
use clap::Clap;
use collateral::*;
use core::str::FromStr;
use error::Error;
use execution::{execute_open_issue_requests, execute_open_requests};
use futures::channel::mpsc;
use issue::*;
use log::*;
use redeem::*;
use replace::*;
use runtime::{
    substrate_subxt::PairSigner, BtcRelayPallet, Error as RuntimeError, PolkaBtcProvider,
    PolkaBtcRuntime, UtilFuncs, VaultRegistryPallet,
};
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::delay_for;

#[derive(Debug, Copy, Clone)]
struct BitcoinNetwork(bitcoin::Network);

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
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// Keyring for vault.
    #[clap(long, default_value = "bob")]
    keyring: AccountKeyring,

    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::0]:3031")]
    http_addr: String,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    rpc_cors_domain: String,

    /// Automatically register the vault with the given amount of collateral and a newly generated address.
    #[clap(long)]
    auto_register_with_collateral: Option<u128>,

    /// Opt out of auctioning under-collateralized vaults.
    #[clap(long)]
    no_auto_auction: bool,

    /// Opt out of participation in replace requests.
    #[clap(long)]
    no_auto_replace: bool,

    /// Don't check the collateralization rate at startup.
    #[clap(long)]
    no_startup_collateral_increase: bool,

    /// Maximum total collateral to keep the vault securely collateralized.
    #[clap(long, default_value = "1000000")]
    max_collateral: u128,

    /// Timeout in milliseconds to repeat collateralization checks.
    #[clap(long, default_value = "5000")]
    collateral_timeout_ms: u64,

    /// How many bitcoin confirmations to wait for. If not specified, the
    /// parachain settings will be used (recommended).
    #[clap(long)]
    btc_confirmations: Option<u32>,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    bitcoin: bitcoin::cli::BitcoinOpts,

    /// Bitcoin network type for address encoding.
    #[clap(long, default_value = "regtest")]
    network: BitcoinNetwork,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();

    info!("Command line arguments: {:?}", opts.clone());

    let btc_rpc = Arc::new(BitcoinCore::new(
        opts.bitcoin
            .new_client(Some(&format!("{}", opts.keyring)))?,
    ));
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(opts.keyring.pair());
    let provider = PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?;
    let arc_provider = Arc::new(provider.clone());
    let auction_provider = arc_provider.clone();
    let vault_id = opts.keyring.to_account_id();
    let collateral_timeout_ms = opts.collateral_timeout_ms;

    let num_confirmations = match opts.btc_confirmations {
        Some(x) => x,
        None => arc_provider.clone().get_bitcoin_confirmations().await?,
    };
    info!("Using {} bitcoin confirmations", num_confirmations);

    if let Some(collateral) = opts.auto_register_with_collateral {
        match provider.get_vault(vault_id.clone()).await {
            Ok(_) => info!("Not registering vault -- already registered"),
            Err(RuntimeError::VaultNotFound) => {
                let btc_address = btc_rpc.get_new_address()?;
                provider.register_vault(collateral, btc_address).await?;
                info!("Automatically registered vault");
            }
            Err(err) => return Err(err.into()),
        }
    }

    let open_request_executor = execute_open_requests(
        arc_provider.clone(),
        btc_rpc.clone(),
        vault_id.clone(),
        num_confirmations,
        opts.network.0,
    );
    tokio::spawn(async move {
        info!("Checking for open replace/redeem requests..");
        match open_request_executor.await {
            Ok(_) => info!("Done processing open replace/redeem requests"),
            Err(e) => error!("Failed to process open replace/redeem requests: {}", e),
        }
    });

    if !opts.no_startup_collateral_increase {
        // check if the vault is registered
        match lock_required_collateral(arc_provider.clone(), vault_id.clone(), opts.max_collateral)
            .await
        {
            Err(Error::RuntimeError(runtime::Error::VaultNotFound)) => {} // not registered
            Err(e) => error!("Failed to lock required additional collateral: {}", e),
            _ => {} // collateral level now OK
        };
    }

    let collateral_maintainer = maintain_collateralization_rate(
        arc_provider.clone(),
        vault_id.clone(),
        opts.max_collateral,
    );

    // wait for a new block to arrive, to prevent processing an event that potentially
    // has been processed already prior to restarting
    info!("Waiting for new block..");
    let startup_height = arc_provider.get_current_chain_height().await?;
    while startup_height == arc_provider.get_current_chain_height().await? {
        delay_for(CHAIN_HEIGHT_POLLING_INTERVAL).await;
    }
    info!("Starting to listen for events..");

    // Issue handling
    let issue_set = Arc::new(IssueIds::new());
    let (issue_event_tx, issue_event_rx) = mpsc::channel::<ProcessEvent>(16);
    let mut issue_cancellation_scheduler =
        CancellationScheduler::new(arc_provider.clone(), vault_id.clone());
    let issue_request_listener = listen_for_issue_requests(
        arc_provider.clone(),
        vault_id.clone(),
        issue_event_tx.clone(),
        issue_set.clone(),
    );
    let issue_execute_listener = listen_for_issue_executes(
        arc_provider.clone(),
        vault_id.clone(),
        issue_event_tx.clone(),
        issue_set.clone(),
    );
    let issue_cancel_listener = listen_for_issue_cancels(arc_provider.clone(), issue_set.clone());
    let issue_executor = execute_open_issue_requests(
        arc_provider.clone(),
        btc_rpc.clone(),
        issue_set.clone(),
        num_confirmations,
    );

    // replace handling
    let (replace_event_tx, replace_event_rx) = mpsc::channel::<ProcessEvent>(16);
    let mut replace_cancellation_scheduler =
        CancellationScheduler::new(arc_provider.clone(), vault_id.clone());
    let request_replace_listener = listen_for_replace_requests(
        arc_provider.clone(),
        vault_id.clone(),
        replace_event_tx.clone(),
        !opts.no_auto_replace,
    );
    let accept_replace_listener = listen_for_accept_replace(
        arc_provider.clone(),
        btc_rpc.clone(),
        vault_id.clone(),
        opts.network.0,
        num_confirmations,
    );
    let execute_replace_listener =
        listen_for_execute_replace(arc_provider.clone(), vault_id.clone(), replace_event_tx);

    // redeem handling
    let redeem_listener = listen_for_redeem_requests(
        arc_provider.clone(),
        btc_rpc.clone(),
        vault_id.clone(),
        opts.network.0,
        num_confirmations,
    );

    let api_listener = api::start(
        arc_provider.clone(),
        opts.http_addr.parse()?,
        opts.rpc_cors_domain,
    );

    let no_auto_auction = opts.no_auto_auction;

    let result = tokio::try_join!(
        tokio::spawn(async move {
            api_listener.await;
        }),
        tokio::spawn(async move {
            arc_provider
                .on_event_error(|e| error!("Received error event: {}", e))
                .await
                .unwrap();
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
            issue_cancellation_scheduler
                .handle_cancellation::<IssueCanceller>(issue_event_rx)
                .await
                .unwrap();
        }),
        tokio::spawn(async move {
            issue_cancel_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            issue_executor.await.unwrap();
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
            if !no_auto_auction {
                // we could automatically check vault collateralization rates on events
                // that affect this (e.g. `SetExchangeRate`, `WithdrawCollateral`) but
                // polling is easier for now
                loop {
                    if let Err(e) = monitor_collateral_of_vaults(&auction_provider).await {
                        error!(
                            "Error while monitoring collateral of vaults: {}",
                            e.to_string()
                        );
                    }
                    delay_for(Duration::from_secs(collateral_timeout_ms)).await
                }
            }
        }),
        tokio::spawn(async move {
            replace_cancellation_scheduler
                .handle_cancellation::<ReplaceCanceller>(replace_event_rx)
                .await
                .unwrap();
        }),
    );
    match result {
        Ok(_) => {
            println!("Done");
        }
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    };

    Ok(())
}
