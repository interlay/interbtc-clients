#![recursion_limit = "256"]

mod api;
mod cancellation;
mod collateral;
mod constants;
mod error;
mod execution;
mod faucet;
mod issue;
mod redeem;
mod refund;
mod replace;

use crate::collateral::lock_required_collateral;
use crate::{constants::*, faucet::*, refund::*};
use bitcoin::BitcoinCoreApi;
use clap::Clap;
use core::str::FromStr;
use futures::channel::mpsc;
use futures::SinkExt;
use jsonrpc_core_client::{transports::http as jsonrpc_http, TypedClient};
use log::*;
use runtime::{
    pallets::sla::UpdateVaultSLAEvent, AccountId, BtcRelayPallet, Error as RuntimeError,
    PolkaBtcHeader, PolkaBtcProvider, PolkaBtcRuntime, UtilFuncs, VaultRegistryPallet,
    PLANCK_PER_DOT, TX_FEES,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::delay_for;

pub use crate::error::Error;

pub mod service {
    pub use crate::cancellation::CancellationScheduler;
    pub use crate::cancellation::IssueCanceller;
    pub use crate::cancellation::ReplaceCanceller;
    pub use crate::collateral::maintain_collateralization_rate;
    pub use crate::execution::execute_open_issue_requests;
    pub use crate::execution::execute_open_requests;
    pub use crate::issue::listen_for_issue_cancels;
    pub use crate::issue::listen_for_issue_executes;
    pub use crate::issue::listen_for_issue_requests;
    pub use crate::redeem::listen_for_redeem_requests;
    pub use crate::refund::listen_for_refund_requests;
    pub use crate::replace::listen_for_accept_replace;
    pub use crate::replace::listen_for_auction_replace;
    pub use crate::replace::listen_for_execute_replace;
    pub use crate::replace::listen_for_replace_requests;
    pub use crate::replace::monitor_collateral_of_vaults;
}
pub use crate::cancellation::RequestEvent;
pub use crate::issue::IssueRequests;
use service::*;

#[derive(Debug, Copy, Clone)]
pub struct BitcoinNetwork(pub bitcoin::Network);

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
pub struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    pub polka_btc_url: String,

    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::0]:3031")]
    pub http_addr: String,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    pub rpc_cors_domain: String,

    /// Automatically register the vault with the given amount of collateral and a newly generated address.
    #[clap(long)]
    pub auto_register_with_collateral: Option<u128>,

    /// Automatically register the vault with the collateral received from the faucet and a newly generated address.
    /// The parameter is the URL of the faucet
    #[clap(long)]
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

    /// keyring / keyfile options.
    #[clap(flatten)]
    pub account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    pub bitcoin: bitcoin::cli::BitcoinOpts,

    /// Bitcoin network type for address encoding.
    #[clap(long, default_value = "regtest")]
    pub network: BitcoinNetwork,
}

async fn generate_btc_key_and_register<B: BitcoinCoreApi + Send + Sync + 'static>(
    vault_id: AccountId,
    collateral: u128,
    arc_provider: Arc<PolkaBtcProvider>,
    btc_rpc: Arc<B>,
) -> Result<(), Error> {
    match arc_provider.clone().get_vault(vault_id.clone()).await {
        Ok(_) => info!("Not registering vault -- already registered"),
        Err(RuntimeError::VaultNotFound) => {
            let public_key = btc_rpc.get_new_public_key().await?;
            arc_provider
                .clone()
                .register_vault(collateral, public_key)
                .await?;
            info!("Automatically registered vault");
        }
        Err(err) => return Err(err.into()),
    };
    Ok(())
}

async fn lock_additional_collateral(
    api: &Arc<PolkaBtcProvider>,
    amount: u128,
) -> Result<(), Error> {
    let result = api.lock_additional_collateral(amount).await;
    info!(
        "Locking additional collateral; amount {}: {:?}",
        amount, result
    );
    Ok(result?)
}

pub async fn start<B: BitcoinCoreApi + Send + Sync + 'static>(
    opts: Opts,
    arc_provider: Arc<PolkaBtcProvider>,
    btc_rpc: Arc<B>,
) -> Result<(), Error> {
    let vault_id = arc_provider.clone().get_account_id().clone();

    let num_confirmations = match opts.btc_confirmations {
        Some(x) => x,
        None => {
            arc_provider
                .clone()
                .clone()
                .get_bitcoin_confirmations()
                .await?
        }
    };
    info!("Using {} bitcoin confirmations", num_confirmations);

    if let Some(collateral) = opts.auto_register_with_collateral {
        generate_btc_key_and_register(
            vault_id.clone(),
            collateral,
            arc_provider.clone(),
            btc_rpc.clone(),
        )
        .await?
    }

    if let Some(faucet_url) = opts.auto_register_with_faucet_url {
        let connection = jsonrpc_http::connect::<TypedClient>(&faucet_url).await?;

        // Receive user allowance from faucet
        match get_funding(connection.clone(), vault_id.clone()).await {
            Ok(_) => {
                let user_allowance_in_dot: u128 =
                    get_faucet_allowance(connection.clone(), "user_allowance").await?;
                let registration_collateral = user_allowance_in_dot
                    .checked_mul(PLANCK_PER_DOT)
                    .ok_or(Error::MathError)?
                    .checked_sub(TX_FEES)
                    .ok_or(Error::MathError)?;
                generate_btc_key_and_register(
                    vault_id.clone(),
                    registration_collateral,
                    arc_provider.clone(),
                    btc_rpc.clone(),
                )
                .await?;
            }
            Err(e) => error!("Faucet error: {}", e.to_string()),
        }

        // Receive vault allowance from faucet
        match get_funding(connection.clone(), vault_id.clone()).await {
            Ok(_) => {
                let vault_allowance_in_dot: u128 =
                    get_faucet_allowance(connection.clone(), "vault_allowance").await?;
                let operational_collateral = vault_allowance_in_dot
                    .checked_mul(PLANCK_PER_DOT)
                    .ok_or(Error::MathError)?
                    .checked_sub(TX_FEES)
                    .ok_or(Error::MathError)?;
                lock_additional_collateral(&arc_provider.clone(), operational_collateral).await?;
            }
            Err(e) => error!("Faucet error: {}", e.to_string()),
        }
    }

    if let Ok(vault) = arc_provider.clone().get_vault(vault_id.clone()).await {
        if !btc_rpc
            .wallet_has_public_key(vault.wallet.public_key)
            .await?
        {
            return Err(bitcoin::Error::MissingPublicKey.into());
        }
    }

    let open_request_executor =
        execute_open_requests(arc_provider.clone(), btc_rpc.clone(), num_confirmations);
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

    let collateral_maintainer =
        maintain_collateralization_rate(arc_provider.clone(), opts.max_collateral);

    // wait for a new block to arrive, to prevent processing an event that potentially
    // has been processed already prior to restarting
    info!("Waiting for new block..");
    let startup_height = arc_provider.get_current_chain_height().await?;
    while startup_height == arc_provider.get_current_chain_height().await? {
        delay_for(CHAIN_HEIGHT_POLLING_INTERVAL).await;
    }
    info!("Starting to listen for events..");

    let (issue_block_tx, issue_block_rx) = mpsc::channel::<PolkaBtcHeader>(16);
    let (replace_block_tx, replace_block_rx) = mpsc::channel::<PolkaBtcHeader>(16);
    let block_listener = arc_provider.clone();

    // Issue handling
    let issue_set = Arc::new(IssueRequests::new());
    let (issue_event_tx, issue_event_rx) = mpsc::channel::<RequestEvent>(16);
    let mut issue_cancellation_scheduler =
        CancellationScheduler::new(arc_provider.clone(), vault_id.clone());
    let issue_request_listener = listen_for_issue_requests(
        arc_provider.clone(),
        btc_rpc.clone(),
        issue_event_tx.clone(),
        issue_set.clone(),
    );
    let issue_execute_listener = listen_for_issue_executes(
        arc_provider.clone(),
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
    let (replace_event_tx, replace_event_rx) = mpsc::channel::<RequestEvent>(16);
    let mut replace_cancellation_scheduler =
        CancellationScheduler::new(arc_provider.clone(), vault_id.clone());
    let request_replace_listener = listen_for_replace_requests(
        arc_provider.clone(),
        btc_rpc.clone(),
        replace_event_tx.clone(),
        !opts.no_auto_replace,
    );
    let accept_replace_listener =
        listen_for_accept_replace(arc_provider.clone(), btc_rpc.clone(), num_confirmations);
    let execute_replace_listener =
        listen_for_execute_replace(arc_provider.clone(), replace_event_tx.clone());
    let auction_replace_listener =
        listen_for_auction_replace(arc_provider.clone(), btc_rpc.clone(), num_confirmations);
    let third_party_collateral_listener = monitor_collateral_of_vaults(
        arc_provider.clone(),
        btc_rpc.clone(),
        replace_event_tx.clone(),
        Duration::from_millis(opts.collateral_timeout_ms),
    );

    // redeem handling
    let redeem_listener =
        listen_for_redeem_requests(arc_provider.clone(), btc_rpc.clone(), num_confirmations);

    // refund handling
    let refund_listener =
        listen_for_refund_requests(arc_provider.clone(), btc_rpc.clone(), num_confirmations);

    let api_listener = if opts.no_api {
        None
    } else {
        Some(api::start(
            arc_provider.clone(),
            btc_rpc.clone(),
            opts.http_addr.parse()?,
            opts.rpc_cors_domain,
        ))
    };

    // misc copies of variables to move into spawn closures
    let no_auto_auction = opts.no_auto_auction;
    let no_issue_execution = opts.no_issue_execution;
    let sla_event_provider = arc_provider.clone();

    // starts all the tasks
    let result = tokio::try_join!(
        tokio::spawn(async move {
            if let Some(api_listener) = api_listener {
                api_listener.await;
            }
        }),
        tokio::spawn(async move {
            arc_provider
                .on_event_error(|e| error!("Received error event: {}", e))
                .await
                .unwrap();
        }),
        tokio::spawn(async move {
            let vault_id = sla_event_provider.get_account_id();
            sla_event_provider
                .on_event::<UpdateVaultSLAEvent<PolkaBtcRuntime>, _, _, _>(
                    |event| async move {
                        if &event.vault_id == vault_id {
                            info!("Received event: new total SLA score = {:?}", event.new_sla);
                        }
                    },
                    |err| error!("Error (UpdateVaultSLAEvent): {}", err.to_string()),
                )
                .await
                .unwrap();
        }),
        tokio::spawn(async move {
            collateral_maintainer.await.unwrap();
        }),
        tokio::spawn(async move {
            let issue_block_tx = &issue_block_tx;
            let replace_block_tx = &replace_block_tx;

            block_listener
                .clone()
                .on_block(move |header| async move {
                    issue_block_tx
                        .clone()
                        .send(header.clone())
                        .await
                        .map_err(|_| RuntimeError::ChannelClosed)?;
                    replace_block_tx
                        .clone()
                        .send(header.clone())
                        .await
                        .map_err(|_| RuntimeError::ChannelClosed)?;
                    Ok(())
                })
                .await
                .unwrap();
        }),
        tokio::spawn(async move {
            issue_request_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            issue_execute_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            issue_cancellation_scheduler
                .handle_cancellation::<IssueCanceller>(issue_block_rx, issue_event_rx)
                .await
                .unwrap();
        }),
        tokio::spawn(async move {
            issue_cancel_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            if !no_issue_execution {
                issue_executor.await.unwrap();
            }
        }),
        // redeem handling
        tokio::spawn(async move {
            redeem_listener.await.unwrap();
        }),
        // refund handling
        tokio::spawn(async move {
            refund_listener.await.unwrap();
        }),
        // replace handling
        tokio::spawn(async move {
            request_replace_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            accept_replace_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            auction_replace_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            execute_replace_listener.await.unwrap();
        }),
        tokio::spawn(async move {
            if !no_auto_auction {
                third_party_collateral_listener.await.unwrap();
            }
        }),
        tokio::spawn(async move {
            replace_cancellation_scheduler
                .handle_cancellation::<ReplaceCanceller>(replace_block_rx, replace_event_rx)
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
