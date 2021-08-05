use crate::{
    collateral::lock_required_collateral, faucet, issue, relay::run_relayer, service::*, Error, Event, IssueRequests,
    Vaults, CHAIN_HEIGHT_POLLING_INTERVAL,
};
use async_trait::async_trait;
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use clap::Clap;
use futures::{
    channel::{mpsc, mpsc::Sender},
    executor::block_on,
    Future, SinkExt,
};
use git_version::git_version;
use runtime::{
    btc_relay::StoreMainChainHeaderEvent,
    cli::{parse_duration_minutes, parse_duration_ms},
    pallets::{security::UpdateActiveBlockEvent, sla::UpdateVaultSLAEvent},
    AccountId, BtcRelayPallet, Error as RuntimeError, InterBtcParachain, InterBtcRuntime, UtilFuncs,
    VaultRegistryPallet,
};
use service::{wait_or_shutdown, Error as ServiceError, Service, ShutdownSender};
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;

pub const VERSION: &str = git_version!(args = ["--tags"]);
pub const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

#[derive(Clap, Clone, Debug)]
pub struct VaultServiceConfig {
    /// Automatically register the vault with the given amount of collateral and a newly generated address.
    #[clap(long)]
    pub auto_register_with_collateral: Option<u128>,

    /// Automatically register the vault with the collateral received from the faucet and a newly generated address.
    /// The parameter is the URL of the faucet
    #[clap(long, conflicts_with("auto-register-with-collateral"))]
    pub auto_register_with_faucet_url: Option<String>,

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
    /// If unset, this will default to the account's total free balance.
    #[clap(long)]
    pub max_collateral: Option<u128>,

    /// Timeout in milliseconds to repeat collateralization checks.
    #[clap(long, parse(try_from_str = parse_duration_ms), default_value = "5000")]
    pub collateral_timeout_ms: Duration,

    /// How many bitcoin confirmations to wait for. If not specified, the
    /// parachain settings will be used (recommended).
    #[clap(long)]
    pub btc_confirmations: Option<u32>,

    /// Minimum time to the the redeem/replace execution deadline to make the bitcoin payment.
    #[clap(long, parse(try_from_str = parse_duration_minutes), default_value = "120")]
    pub payment_margin_minutes: Duration,

    /// Starting height for vault theft checks, if not defined
    /// automatically start from the chain tip.
    #[clap(long)]
    pub bitcoin_theft_start_height: Option<u32>,

    /// Timeout in milliseconds to poll Bitcoin.
    #[clap(long, parse(try_from_str = parse_duration_ms), default_value = "6000")]
    pub bitcoin_poll_interval_ms: Duration,

    /// Starting height to relay block headers, if not defined
    /// use the best height as reported by the relay module.
    #[clap(long)]
    pub bitcoin_relay_start_height: Option<u32>,

    /// Max batch size for combined block header submission.
    #[clap(long, default_value = "16")]
    pub max_batch_size: u32,

    /// Number of confirmations a block needs to have before it is submitted.
    #[clap(long, default_value = "0")]
    pub bitcoin_relay_confirmations: u32,

    /// Don't relay bitcoin block headers.
    #[clap(long)]
    pub no_bitcoin_block_relay: bool,

    /// Don't monitor vault thefts.
    #[clap(long)]
    pub no_vault_theft_report: bool,
}

async fn active_block_listener(
    parachain_rpc: InterBtcParachain,
    issue_tx: Sender<Event>,
    replace_tx: Sender<Event>,
) -> Result<(), ServiceError> {
    let issue_tx = &issue_tx;
    let replace_tx = &replace_tx;
    parachain_rpc
        .on_event::<UpdateActiveBlockEvent<InterBtcRuntime>, _, _, _>(
            |event| async move {
                let _ = issue_tx.clone().send(Event::ParachainBlock(event.height)).await;
                let _ = replace_tx.clone().send(Event::ParachainBlock(event.height)).await;
            },
            |err| tracing::error!("Error (UpdateActiveBlockEvent): {}", err.to_string()),
        )
        .await?;
    Ok(())
}

async fn relay_block_listener(
    parachain_rpc: InterBtcParachain,
    issue_tx: Sender<Event>,
    replace_tx: Sender<Event>,
) -> Result<(), ServiceError> {
    let issue_tx = &issue_tx;
    let replace_tx = &replace_tx;
    parachain_rpc
        .on_event::<StoreMainChainHeaderEvent<InterBtcRuntime>, _, _, _>(
            |event| async move {
                let _ = issue_tx.clone().send(Event::BitcoinBlock(event.block_height)).await;
                let _ = replace_tx.clone().send(Event::BitcoinBlock(event.block_height)).await;
            },
            |err| tracing::error!("Error (StoreMainChainHeaderEvent): {}", err.to_string()),
        )
        .await?;
    Ok(())
}

pub struct VaultService {
    btc_parachain: InterBtcParachain,
    bitcoin_core: BitcoinCore,
    config: VaultServiceConfig,
    shutdown: ShutdownSender,
}

#[async_trait]
impl Service<VaultServiceConfig> for VaultService {
    const NAME: &'static str = NAME;
    const VERSION: &'static str = VERSION;

    fn new_service(
        btc_parachain: InterBtcParachain,
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

async fn maybe_run_task(should_run: bool, task: impl Future) {
    if should_run {
        task.await;
    }
}

impl VaultService {
    fn new(
        btc_parachain: InterBtcParachain,
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
                tracing::info!("Automatically registering vault");
                // bitcoin core is currently blocking, no need to try_join
                let public_key = bitcoin_core.get_new_public_key().await?;
                self.btc_parachain.register_vault(collateral, public_key).await?;
            } else {
                tracing::info!("Not registering vault -- already registered");
            }
        } else if let Some(faucet_url) = &self.config.auto_register_with_faucet_url {
            if !is_registered(&self.btc_parachain, vault_id.clone()).await? {
                faucet::fund_and_register(&self.btc_parachain, &bitcoin_core, faucet_url, vault_id.clone()).await?;
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

        let open_request_executor = execute_open_requests(
            self.btc_parachain.clone(),
            bitcoin_core.clone(),
            num_confirmations,
            self.config.payment_margin_minutes,
        );
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
            sleep(CHAIN_HEIGHT_POLLING_INTERVAL).await;
        }
        tracing::info!("Got new block...");

        // get the relay chain tip but don't error because the relay may not be initialized
        let initial_btc_height = self.btc_parachain.get_best_block_height().await.unwrap_or_default();

        // issue handling
        let issue_set = Arc::new(IssueRequests::new());
        let oldest_issue_btc_height =
            issue::initialize_issue_set(&bitcoin_core, &self.btc_parachain, &issue_set).await?;

        let (issue_event_tx, issue_event_rx) = mpsc::channel::<Event>(32);

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

        let mut issue_cancellation_scheduler = CancellationScheduler::new(
            self.btc_parachain.clone(),
            startup_height,
            initial_btc_height,
            vault_id.clone(),
        );

        let issue_cancel_scheduler = wait_or_shutdown(self.shutdown.clone(), async move {
            issue_cancellation_scheduler
                .handle_cancellation::<IssueCanceller>(issue_event_rx)
                .await?;
            Ok(())
        });

        let issue_executor = maybe_run_task(
            !self.config.no_issue_execution,
            wait_or_shutdown(
                self.shutdown.clone(),
                issue::process_issue_requests(
                    bitcoin_core.clone(),
                    self.btc_parachain.clone(),
                    issue_set.clone(),
                    oldest_issue_btc_height,
                    num_confirmations,
                ),
            ),
        );

        // replace handling
        let (replace_event_tx, replace_event_rx) = mpsc::channel::<Event>(16);

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
            listen_for_accept_replace(
                self.btc_parachain.clone(),
                bitcoin_core.clone(),
                num_confirmations,
                self.config.payment_margin_minutes,
            ),
        );

        let execute_replace_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_execute_replace(self.btc_parachain.clone(), replace_event_tx.clone()),
        );

        let mut replace_cancellation_scheduler = CancellationScheduler::new(
            self.btc_parachain.clone(),
            startup_height,
            initial_btc_height,
            vault_id.clone(),
        );

        let replace_cancel_scheduler = wait_or_shutdown(self.shutdown.clone(), async move {
            replace_cancellation_scheduler
                .handle_cancellation::<ReplaceCanceller>(replace_event_rx)
                .await?;
            Ok(())
        });

        // listen for parachain blocks, used for cancellation
        let parachain_block_listener = wait_or_shutdown(
            self.shutdown.clone(),
            active_block_listener(
                self.btc_parachain.clone(),
                issue_event_tx.clone(),
                replace_event_tx.clone(),
            ),
        );

        // listen for bitcoin blocks, used for cancellation
        let bitcoin_block_listener = wait_or_shutdown(
            self.shutdown.clone(),
            relay_block_listener(
                self.btc_parachain.clone(),
                issue_event_tx.clone(),
                replace_event_tx.clone(),
            ),
        );

        // redeem handling
        let redeem_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_redeem_requests(
                self.btc_parachain.clone(),
                bitcoin_core.clone(),
                num_confirmations,
                self.config.payment_margin_minutes,
            ),
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
                .on_event::<UpdateVaultSLAEvent<InterBtcRuntime>, _, _, _>(
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

        // watch vault address registration and report potential thefts
        let vaults_listener = maybe_run_task(!self.config.no_vault_theft_report, self.start_theft_reporting().await?);

        // relay bitcoin block headers to the relay
        let relayer = maybe_run_task(
            !self.config.no_bitcoin_block_relay,
            wait_or_shutdown(
                self.shutdown.clone(),
                run_relayer(Runner::new(
                    bitcoin_core.clone(),
                    self.btc_parachain.clone(),
                    Config {
                        start_height: self.config.bitcoin_relay_start_height,
                        max_batch_size: self.config.max_batch_size,
                        interval: Some(self.config.bitcoin_poll_interval_ms),
                        btc_confirmations: self.config.bitcoin_relay_confirmations,
                    },
                )),
            ),
        );

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
            // replace & issue cancellation helpers
            tokio::spawn(async move { parachain_block_listener.await }),
            tokio::spawn(async move { bitcoin_block_listener.await }),
            // issue handling
            tokio::spawn(async move { issue_request_listener.await }),
            tokio::spawn(async move { issue_execute_listener.await }),
            tokio::spawn(async move { issue_cancel_listener.await }),
            tokio::spawn(async move { issue_cancel_scheduler.await }),
            tokio::spawn(async move { issue_executor.await }),
            // replace handling
            tokio::spawn(async move { request_replace_listener.await }),
            tokio::spawn(async move { accept_replace_listener.await }),
            tokio::spawn(async move { execute_replace_listener.await }),
            tokio::spawn(async move { replace_cancel_scheduler.await }),
            // redeem handling
            tokio::spawn(async move { redeem_listener.await }),
            // refund handling
            tokio::spawn(async move { refund_listener.await }),
            // runs vault theft checks
            tokio::spawn(async move { vaults_listener.await }),
            // relayer process
            tokio::task::spawn_blocking(move || block_on(relayer))
        );

        Ok(())
    }

    pub(crate) async fn start_theft_reporting(&self) -> Result<impl Future, Error> {
        // TODO: don't fetch vaults if reporting is disabled
        tracing::info!("Fetching all active vaults...");
        let vaults = self
            .btc_parachain
            .get_all_vaults()
            .await?
            .into_iter()
            .flat_map(|vault| {
                vault
                    .wallet
                    .addresses
                    .iter()
                    .map(|addr| (*addr, vault.id.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();

        // store vaults in Arc<RwLock>
        let vaults = Arc::new(Vaults::from(vaults));

        // scan from custom height or the current tip
        let bitcoin_theft_start_height = self
            .config
            .bitcoin_theft_start_height
            .unwrap_or(self.bitcoin_core.get_block_count().await? as u32 + 1);

        let vaults_listener = wait_or_shutdown(
            self.shutdown.clone(),
            report_vault_thefts(
                self.bitcoin_core.clone(),
                self.btc_parachain.clone(),
                bitcoin_theft_start_height,
                vaults.clone(),
            ),
        );

        // keep track of all registered vaults (i.e. keep the `vaults` map up-to-date)
        let vaults_registration_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_vaults_registered(self.btc_parachain.clone(), vaults.clone()),
        );

        // keep vault wallets up-to-date
        let wallet_update_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_wallet_updates(self.btc_parachain.clone(), vaults.clone()),
        );

        Ok(futures::future::join3(
            vaults_listener,
            vaults_registration_listener,
            wallet_update_listener,
        ))
    }
}

pub(crate) async fn is_registered(parachain_rpc: &InterBtcParachain, vault_id: AccountId) -> Result<bool, Error> {
    match parachain_rpc.get_vault(vault_id).await {
        Ok(_) => Ok(true),
        Err(RuntimeError::VaultNotFound) => Ok(false),
        Err(err) => Err(err.into()),
    }
}
