#![recursion_limit = "256"]

mod cancellor;
// mod collateral;
mod constants;
mod error;
mod execution;
mod faucet;
mod http;
// mod issue;
// mod redeem;
// mod refund;
// mod replace;
mod types;

mod services;

use bitcoin::BitcoinCoreApi;
use clap::Clap;
use core::str::FromStr;
use log::*;
use runtime::{
    AccountId, BtcRelayPallet, ConnectionManager, Error as RuntimeError, PolkaBtcProvider,
    PolkaBtcSigner, UtilFuncs, VaultRegistryPallet,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::delay_for;

use crate::constants::*;
use crate::services::*;

pub use crate::cancellor::RequestEvent;
pub use crate::error::Error;
pub use crate::types::IssueRequests;

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
    #[clap(long, conflicts_with("auto-register-with-collateral"))]
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

    /// Timeout in milliseconds to poll Bitcoin.
    #[clap(long, default_value = "6000")]
    pub bitcoin_timeout_ms: u64,

    /// Timeout in milliseconds to wait for connection to btc-parachain.
    #[clap(long, default_value = "60000")]
    pub connection_timeout_ms: u64,
}

pub(crate) async fn is_registered(
    provider: &PolkaBtcProvider,
    vault_id: AccountId,
) -> Result<bool, Error> {
    match provider.get_vault(vault_id).await {
        Ok(_) => Ok(true),
        Err(RuntimeError::VaultNotFound) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

pub(crate) async fn lock_additional_collateral(
    btc_parachain: &PolkaBtcProvider,
    amount: u128,
) -> Result<(), Error> {
    let result = btc_parachain.lock_additional_collateral(amount).await;
    info!(
        "Locking additional collateral; amount {}: {:?}",
        amount, result
    );
    Ok(result?)
}

pub async fn start<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    btc_parachain: PolkaBtcProvider,
    bitcoin_core: B,
    signer: Arc<PolkaBtcSigner>,
    opts: Opts,
) -> Result<(), Error> {
    let vault_id = btc_parachain.clone().get_account_id().clone();

    let num_confirmations = match opts.btc_confirmations {
        Some(x) => x,
        None => {
            btc_parachain
                .clone()
                .clone()
                .get_bitcoin_confirmations()
                .await?
        }
    };
    info!("Using {} bitcoin confirmations", num_confirmations);

    if let Some(collateral) = opts.auto_register_with_collateral {
        if !is_registered(&btc_parachain, vault_id.clone()).await? {
            let public_key = bitcoin_core.get_new_public_key().await?;
            btc_parachain.register_vault(collateral, public_key).await?;
            info!("Automatically registered vault");
        } else {
            info!("Not registering vault -- already registered");
        }
    } else if let Some(faucet_url) = opts.auto_register_with_faucet_url {
        if !is_registered(&btc_parachain, vault_id.clone()).await? {
            faucet::fund_and_register::<B>(
                &btc_parachain,
                &bitcoin_core,
                faucet_url,
                vault_id.clone(),
            )
            .await?;
            info!("Automatically registered vault");
        } else {
            info!("Not registering vault -- already registered");
        }
    }

    if let Ok(vault) = btc_parachain.clone().get_vault(vault_id.clone()).await {
        if !bitcoin_core
            .wallet_has_public_key(vault.wallet.public_key)
            .await?
        {
            return Err(bitcoin::Error::MissingPublicKey.into());
        }

        if !opts.no_startup_collateral_increase {
            // check if the vault is registered
            match lock_required_collateral(
                btc_parachain.clone(),
                vault_id.clone(),
                opts.max_collateral,
            )
            .await
            {
                Err(Error::RuntimeError(runtime::Error::VaultNotFound)) => {} // not registered
                Err(e) => error!("Failed to lock required additional collateral: {}", e),
                _ => {} // collateral level now OK
            };
        }
    }

    // wait for a new block to arrive, to prevent processing an event that potentially
    // has been processed already prior to restarting
    info!("Waiting for new block...");
    let startup_height = btc_parachain.get_current_chain_height().await?;
    while startup_height == btc_parachain.get_current_chain_height().await? {
        delay_for(CHAIN_HEIGHT_POLLING_INTERVAL).await;
    }

    let http_server = if opts.no_api {
        None
    } else {
        Some(http::start_http(
            btc_parachain,
            bitcoin_core.clone(),
            opts.http_addr.parse()?,
            opts.rpc_cors_domain,
        ))
    };

    // Collateral handling
    let collateral_listener = ConnectionManager::<_, _, CollateralService>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        CollateralServiceConfig {
            maximum_collateral: opts.max_collateral,
        },
    );

    // Issue handling
    let issue_listener = ConnectionManager::<_, _, IssueService<_>>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        IssueServiceConfig {
            bitcoin_core: bitcoin_core.clone(),
        },
    );

    let issue_execution_listener = if opts.no_issue_execution {
        None
    } else {
        Some(ConnectionManager::<_, _, IssueExecutionService<_>>::new(
            opts.polka_btc_url.clone(),
            signer.clone(),
            IssueExecutionServiceConfig {
                bitcoin_core: bitcoin_core.clone(),
                num_confirmations,
            },
        ))
    };

    // Refund handling
    let refund_listener = ConnectionManager::<_, _, RefundService<_>>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        RefundServiceConfig {
            bitcoin_core: bitcoin_core.clone(),
            num_confirmations,
        },
    );

    // Redeem handling
    let redeem_listener = ConnectionManager::<_, _, RedeemService<_>>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        RedeemServiceConfig {
            bitcoin_core: bitcoin_core.clone(),
            num_confirmations,
        },
    );

    // Replace handling
    let replace_listener = ConnectionManager::<_, _, ReplaceService<_>>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        ReplaceServiceConfig {
            bitcoin_core: bitcoin_core.clone(),
            num_confirmations,
            accept_replace_requests: !opts.no_auto_replace,
        },
    );

    let auction_listener = if opts.no_auto_auction {
        None
    } else {
        Some(ConnectionManager::<_, _, AuctionService<_>>::new(
            opts.polka_btc_url.clone(),
            signer.clone(),
            AuctionServiceConfig {
                bitcoin_core: bitcoin_core.clone(),
                timeout: Duration::from_millis(opts.collateral_timeout_ms),
            },
        ))
    };

    let system_listener = ConnectionManager::<_, _, SystemService<_>>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        SystemServiceConfig {
            bitcoin_core: bitcoin_core.clone(),
            num_confirmations,
        },
    );

    let sla_update_listener =
        ConnectionManager::<_, _, SlaUpdateService>::new(opts.polka_btc_url, signer, ());

    // starts all the tasks
    info!("Starting services...");
    let result = tokio::try_join!(
        tokio::spawn(async move {
            if let Some(http_server) = http_server {
                http_server.await;
            }
        }),
        // listen and update the vault's collateral
        tokio::spawn(async move { collateral_listener.start().await.unwrap() }),
        // listen for and report sla updates
        tokio::spawn(async move { sla_update_listener.start().await.unwrap() }),
        // listen for all issue events
        tokio::spawn(async move { issue_listener.start().await.unwrap() }),
        // find and execute issue requests
        tokio::spawn(async move {
            if let Some(issue_execution_listener) = issue_execution_listener {
                issue_execution_listener.start().await.unwrap();
            }
        }),
        // listen for all refund events
        tokio::spawn(async move { refund_listener.start().await.unwrap() }),
        // listen for all redeem events
        tokio::spawn(async move { redeem_listener.start().await.unwrap() }),
        // listen for all replace events
        tokio::spawn(async move { replace_listener.start().await.unwrap() }),
        // monitor vaults for insufficient collateral and auction
        tokio::spawn(async move {
            if let Some(auction_listener) = auction_listener {
                auction_listener.start().await.unwrap();
            }
        }),
        tokio::spawn(async move { system_listener.start().await.unwrap() }),
    );
    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            error!("{:?}", err);
            Err(Error::InternalError)
        }
    }
}
