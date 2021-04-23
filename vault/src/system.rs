use crate::{
    collateral::lock_required_collateral, faucet, issue, service::*, Error, IssueRequests, RequestEvent,
    CHAIN_HEIGHT_POLLING_INTERVAL,
};
use async_trait::async_trait;
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use clap::Clap;
use futures::{channel::mpsc, SinkExt};
use git_version::git_version;
use runtime::{
    cli::parse_duration_ms, pallets::sla::UpdateVaultSLAEvent, AccountId, BtcRelayPallet, Error as RuntimeError,
    PolkaBtcHeader, PolkaBtcProvider, PolkaBtcRuntime, UtilFuncs, VaultRegistryPallet,
};
use service::{wait_or_shutdown, Error as ServiceError, Service, ShutdownSender};
use std::{sync::Arc, time::Duration};
use tokio::time::delay_for;

pub const VERSION: &str = git_version!(args = ["--tags"]);
pub const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

#[derive(Clap, Clone, Debug)]
pub struct VaultServiceConfig {
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
    #[clap(long, parse(try_from_str = parse_duration_ms), default_value = "5000")]
    pub collateral_timeout_ms: Duration,

    /// How many bitcoin confirmations to wait for. If not specified, the
    /// parachain settings will be used (recommended).
    #[clap(long)]
    pub btc_confirmations: Option<u32>,
}

pub struct VaultService {
    btc_parachain: PolkaBtcProvider,
    bitcoin_core: BitcoinCore,
    config: VaultServiceConfig,
    shutdown: ShutdownSender,
}

#[async_trait]
impl Service<VaultServiceConfig> for VaultService {
    const NAME: &'static str = NAME;
    const VERSION: &'static str = VERSION;

    fn new_service(
        btc_parachain: PolkaBtcProvider,
        bitcoin_core: BitcoinCore,
        config: VaultServiceConfig,
        shutdown: ShutdownSender,
    ) -> Self {
        VaultService::new(btc_parachain, bitcoin_core, config, shutdown)
    }

    async fn start(&self) -> Result<(), ServiceError> {
        match self.run_service().await {
            Ok(_) => Ok(()),
            Err(Error::RuntimeError(err)) => Err(ServiceError::RuntimeError(err)),
            Err(Error::BitcoinError(err)) => Err(ServiceError::BitcoinError(err)),
            Err(err) => Err(ServiceError::Other(err.to_string())),
        }
    }
}

impl VaultService {
    fn new(
        btc_parachain: PolkaBtcProvider,
        bitcoin_core: BitcoinCore,
        config: VaultServiceConfig,
        shutdown: ShutdownSender,
    ) -> Self {
        Self {
            btc_parachain,
            bitcoin_core,
            config,
            shutdown,
        }
    }

    async fn run_service(&self) -> Result<(), Error> {
        let bitcoin_core = self.bitcoin_core.clone();

        // load wallet. Exit on failure, since without wallet we can't do a lot
        bitcoin_core
            .create_or_load_wallet()
            .await
            .map_err(Error::WalletInitializationFailure)?;

        let vault_id = self.btc_parachain.get_account_id().clone();

        let num_confirmations = match self.config.btc_confirmations {
            Some(x) => x,
            None => self.btc_parachain.get_bitcoin_confirmations().await?,
        };
        tracing::info!("Using {} bitcoin confirmations", num_confirmations);

        if let Some(collateral) = self.config.auto_register_with_collateral {
            if !is_registered(&self.btc_parachain, vault_id.clone()).await? {
                // bitcoin core is currently blocking, no need to try_join
                let public_key = bitcoin_core.get_new_public_key().await?;
                self.btc_parachain.register_vault(collateral, public_key).await?;
                tracing::info!("Automatically registered vault");
            } else {
                tracing::info!("Not registering vault -- already registered");
            }
        } else if let Some(faucet_url) = &self.config.auto_register_with_faucet_url {
            if !is_registered(&self.btc_parachain, vault_id.clone()).await? {
                faucet::fund_and_register(&self.btc_parachain, &bitcoin_core, faucet_url, vault_id.clone()).await?;
                tracing::info!("Automatically registered vault");
            } else {
                tracing::info!("Not registering vault -- already registered");
            }
        }

        if let Ok(vault) = self.btc_parachain.get_vault(vault_id.clone()).await {
            if !bitcoin_core.wallet_has_public_key(vault.wallet.public_key.0).await? {
                return Err(bitcoin::Error::MissingPublicKey.into());
            }
        }

        issue::add_keys_from_past_issue_request(&bitcoin_core, &self.btc_parachain).await?;

        let open_request_executor =
            execute_open_requests(self.btc_parachain.clone(), bitcoin_core.clone(), num_confirmations);
        tokio::spawn(async move {
            tracing::info!("Checking for open requests...");
            match open_request_executor.await {
                Ok(_) => tracing::info!("Done processing open requests"),
                Err(e) => tracing::error!("Failed to process open requests: {}", e),
            }
        });

        if !self.config.no_startup_collateral_increase {
            // check if the vault is registered
            match lock_required_collateral(self.btc_parachain.clone(), vault_id.clone(), self.config.max_collateral)
                .await
            {
                Err(Error::RuntimeError(runtime::Error::VaultNotFound)) => {} // not registered
                Err(e) => tracing::error!("Failed to lock required additional collateral: {}", e),
                _ => {} // collateral level now OK
            };
        }

        let collateral_maintainer = wait_or_shutdown(
            self.shutdown.clone(),
            maintain_collateralization_rate(self.btc_parachain.clone(), self.config.max_collateral),
        );

        // wait for a new block to arrive, to prevent processing an event that potentially
        // has been processed already prior to restarting
        tracing::info!("Waiting for new block...");
        let startup_height = self.btc_parachain.get_current_chain_height().await?;
        while startup_height == self.btc_parachain.get_current_chain_height().await? {
            delay_for(CHAIN_HEIGHT_POLLING_INTERVAL).await;
        }

        // issue handling
        let issue_set = Arc::new(IssueRequests::new());
        let btc_start_height = issue::initialize_issue_set(&bitcoin_core, &self.btc_parachain, &issue_set).await?;

        let (issue_event_tx, issue_event_rx) = mpsc::channel::<RequestEvent>(32);
        let (issue_block_tx, issue_block_rx) = mpsc::channel::<PolkaBtcHeader>(16);

        let issue_request_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_issue_requests(
                bitcoin_core.clone(),
                self.btc_parachain.clone(),
                issue_event_tx.clone(),
                issue_set.clone(),
            ),
        );

        let issue_execute_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_issue_executes(self.btc_parachain.clone(), issue_event_tx.clone(), issue_set.clone()),
        );

        let issue_cancel_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_issue_cancels(self.btc_parachain.clone(), issue_set.clone()),
        );

        let mut issue_cancellation_scheduler = CancellationScheduler::new(self.btc_parachain.clone(), vault_id.clone());

        let issue_block_provider = self.btc_parachain.clone();
        let issue_block_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            let issue_block_tx = &issue_block_tx;
            issue_block_provider
                .on_block(move |header| async move {
                    issue_block_tx
                        .clone()
                        .send(header.clone())
                        .await
                        .map_err(|_| RuntimeError::ChannelClosed)?;
                    Ok(())
                })
                .await?;
            Ok(())
        });

        let issue_cancel_scheduler = wait_or_shutdown(self.shutdown.clone(), async move {
            issue_cancellation_scheduler
                .handle_cancellation::<IssueCanceller>(issue_block_rx, issue_event_rx)
                .await?;
            Ok(())
        });

        let issue_executor = wait_or_shutdown(
            self.shutdown.clone(),
            issue::process_issue_requests(
                bitcoin_core.clone(),
                self.btc_parachain.clone(),
                issue_set.clone(),
                btc_start_height,
                num_confirmations,
            ),
        );

        // replace handling
        let (replace_event_tx, replace_event_rx) = mpsc::channel::<RequestEvent>(16);
        let (replace_block_tx, replace_block_rx) = mpsc::channel::<PolkaBtcHeader>(16);

        let request_replace_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_replace_requests(
                self.btc_parachain.clone(),
                bitcoin_core.clone(),
                replace_event_tx.clone(),
                !self.config.no_auto_replace,
            ),
        );

        let accept_replace_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_accept_replace(self.btc_parachain.clone(), bitcoin_core.clone(), num_confirmations),
        );

        let execute_replace_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_execute_replace(self.btc_parachain.clone(), replace_event_tx.clone()),
        );

        let auction_replace_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_auction_replace(self.btc_parachain.clone(), bitcoin_core.clone(), num_confirmations),
        );

        let mut replace_cancellation_scheduler =
            CancellationScheduler::new(self.btc_parachain.clone(), vault_id.clone());

        let replace_block_provider = self.btc_parachain.clone();
        let replace_block_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            let replace_block_tx = &replace_block_tx;
            replace_block_provider
                .on_block(move |header| async move {
                    replace_block_tx
                        .clone()
                        .send(header.clone())
                        .await
                        .map_err(|_| RuntimeError::ChannelClosed)?;
                    Ok(())
                })
                .await?;
            Ok(())
        });

        let replace_cancel_scheduler = wait_or_shutdown(self.shutdown.clone(), async move {
            replace_cancellation_scheduler
                .handle_cancellation::<ReplaceCanceller>(replace_block_rx, replace_event_rx)
                .await?;
            Ok(())
        });

        let third_party_collateral_listener = wait_or_shutdown(
            self.shutdown.clone(),
            monitor_collateral_of_vaults(
                self.btc_parachain.clone(),
                bitcoin_core.clone(),
                replace_event_tx.clone(),
                self.config.collateral_timeout_ms,
            ),
        );

        // redeem handling
        let redeem_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_redeem_requests(self.btc_parachain.clone(), bitcoin_core.clone(), num_confirmations),
        );

        // refund handling
        let refund_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_refund_requests(self.btc_parachain.clone(), bitcoin_core.clone(), num_confirmations),
        );

        let sla_provider = self.btc_parachain.clone();
        let sla_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            let vault_id = sla_provider.get_account_id();
            sla_provider
                .on_event::<UpdateVaultSLAEvent<PolkaBtcRuntime>, _, _, _>(
                    |event| async move {
                        if &event.vault_id == vault_id {
                            tracing::info!("Received event: new total SLA score = {:?}", event.new_sla);
                        }
                    },
                    |err| tracing::error!("Error (UpdateVaultSLAEvent): {}", err.to_string()),
                )
                .await?;
            Ok(())
        });

        let err_provider = self.btc_parachain.clone();
        let err_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            err_provider
                .on_event_error(|e| tracing::debug!("Received error event: {}", e))
                .await?;
            Ok(())
        });

        // misc copies of variables to move into spawn closures
        let no_auto_auction = self.config.no_auto_auction;
        let no_issue_execution = self.config.no_issue_execution;

        // starts all the tasks
        tracing::info!("Starting to listen for events...");
        let _ = tokio::join!(
            // runs error listener to log errors
            tokio::spawn(async move { err_listener.await }),
            // runs sla listener to log events
            tokio::spawn(async move { sla_listener.await }),
            // maintain collateralization rate
            tokio::spawn(async move {
                collateral_maintainer.await;
            }),
            // issue handling
            tokio::spawn(async move { issue_request_listener.await }),
            tokio::spawn(async move { issue_execute_listener.await }),
            tokio::spawn(async move { issue_cancel_listener.await }),
            tokio::spawn(async move { issue_block_listener.await }),
            tokio::spawn(async move { issue_cancel_scheduler.await }),
            tokio::spawn(async move {
                if !no_issue_execution {
                    let _ = issue_executor.await;
                }
            }),
            // replace handling
            tokio::spawn(async move { request_replace_listener.await }),
            tokio::spawn(async move { accept_replace_listener.await }),
            tokio::spawn(async move { execute_replace_listener.await }),
            tokio::spawn(async move { auction_replace_listener.await }),
            tokio::spawn(async move { replace_block_listener.await }),
            tokio::spawn(async move { replace_cancel_scheduler.await }),
            tokio::spawn(async move {
                if !no_auto_auction {
                    let _ = third_party_collateral_listener.await;
                }
            }),
            // redeem handling
            tokio::spawn(async move { redeem_listener.await }),
            // refund handling
            tokio::spawn(async move { refund_listener.await }),
        );

        Ok(())
    }
}

pub(crate) async fn is_registered(provider: &PolkaBtcProvider, vault_id: AccountId) -> Result<bool, Error> {
    match provider.get_vault(vault_id).await {
        Ok(_) => Ok(true),
        Err(RuntimeError::VaultNotFound) => Ok(false),
        Err(err) => Err(err.into()),
    }
}
