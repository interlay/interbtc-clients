use crate::{
    collateral::lock_required_collateral,
    error::Error,
    faucet, issue,
    metrics::{poll_metrics, PerCurrencyMetrics},
    relay::run_relayer,
    service::*,
    vaults::Vaults,
    Event, IssueRequests, CHAIN_HEIGHT_POLLING_INTERVAL,
};
use async_trait::async_trait;
use bitcoin::{BitcoinCore, BitcoinCoreApi, Error as BitcoinError};
use clap::Parser;
use futures::{
    channel::{mpsc, mpsc::Sender},
    executor::block_on,
    Future, SinkExt,
};
use git_version::git_version;
use runtime::{
    cli::{parse_duration_minutes, parse_duration_ms},
    parse_collateral_currency, BtcRelayPallet, CollateralBalancesPallet, CurrencyId, Error as RuntimeError,
    InterBtcParachain, RegisterVaultEvent, StoreMainChainHeaderEvent, UpdateActiveBlockEvent, UtilFuncs,
    VaultCurrencyPair, VaultId, VaultRegistryPallet,
};
use service::{wait_or_shutdown, Error as ServiceError, MonitoringConfig, Service, ShutdownSender};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{sync::RwLock, time::sleep};
pub const VERSION: &str = git_version!(args = ["--tags"]);
pub const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

#[derive(Parser, Clone, Debug)]
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

    /// Don't try to execute issues.
    #[clap(long)]
    pub no_issue_execution: bool,

    /// Don't run the RPC API.
    #[clap(long)]
    pub no_api: bool,

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

    /// Don't refund overpayments.
    #[clap(long)]
    pub no_auto_refund: bool,

    /// The currency to use for the collateral, e.g. "DOT" or "KSM".
    /// Defaults to the relay chain currency if not set.
    #[clap(long, parse(try_from_str = parse_collateral_currency))]
    pub collateral_currency_id: Option<CurrencyId>,
}

async fn active_block_listener(
    parachain_rpc: InterBtcParachain,
    issue_tx: Sender<Event>,
    replace_tx: Sender<Event>,
) -> Result<(), ServiceError> {
    let issue_tx = &issue_tx;
    let replace_tx = &replace_tx;
    parachain_rpc
        .on_event::<UpdateActiveBlockEvent, _, _, _>(
            |event| async move {
                let _ = issue_tx.clone().send(Event::ParachainBlock(event.block_number)).await;
                let _ = replace_tx.clone().send(Event::ParachainBlock(event.block_number)).await;
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
        .on_event::<StoreMainChainHeaderEvent, _, _, _>(
            |event| async move {
                let _ = issue_tx.clone().send(Event::BitcoinBlock(event.block_height)).await;
                let _ = replace_tx.clone().send(Event::BitcoinBlock(event.block_height)).await;
            },
            |err| tracing::error!("Error (StoreMainChainHeaderEvent): {}", err.to_string()),
        )
        .await?;
    Ok(())
}

#[derive(Clone)]
pub struct VaultData<BCA: BitcoinCoreApi + Clone + Send + Sync + 'static> {
    pub vault_id: VaultId,
    pub btc_rpc: BCA,
    pub metrics: PerCurrencyMetrics,
}

#[derive(Clone)]
pub struct VaultIdManager<BCA: BitcoinCoreApi + Clone + Send + Sync + 'static> {
    vault_data: Arc<RwLock<HashMap<VaultId, VaultData<BCA>>>>,
    btc_parachain: InterBtcParachain,
    // TODO: refactor this
    #[allow(clippy::type_complexity)]
    constructor: Arc<Box<dyn Fn(VaultId) -> Result<BCA, BitcoinError> + Send + Sync>>,
}

impl<BCA: BitcoinCoreApi + Clone + Send + Sync + 'static> VaultIdManager<BCA> {
    pub fn new(
        btc_parachain: InterBtcParachain,
        constructor: impl Fn(VaultId) -> Result<BCA, BitcoinError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            vault_data: Arc::new(RwLock::new(HashMap::new())),
            constructor: Arc::new(Box::new(constructor)),
            btc_parachain,
        }
    }

    // used for testing only
    pub fn from_map(btc_parachain: InterBtcParachain, map: HashMap<VaultId, BCA>) -> Self {
        let vault_data = map
            .into_iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    VaultData {
                        vault_id: key,
                        btc_rpc: value,
                        metrics: PerCurrencyMetrics::dummy(),
                    },
                )
            })
            .collect();
        Self {
            vault_data: Arc::new(RwLock::new(vault_data)),
            constructor: Arc::new(Box::new(|_| unimplemented!())),
            btc_parachain,
        }
    }

    async fn add_vault_id(&self, vault_id: VaultId) -> Result<BCA, Error> {
        let btc_rpc = (*self.constructor)(vault_id.clone())?;

        // load wallet. Exit on failure, since without wallet we can't do a lot
        btc_rpc
            .create_or_load_wallet()
            .await
            .map_err(Error::WalletInitializationFailure)?;

        if let Ok(vault) = self.btc_parachain.get_vault(&vault_id).await {
            if !btc_rpc.wallet_has_public_key(vault.wallet.public_key.0).await? {
                return Err(bitcoin::Error::MissingPublicKey.into());
            }
        }

        tracing::info!("Adding keys from past issues...");
        issue::add_keys_from_past_issue_request(&btc_rpc, &self.btc_parachain).await?;

        tracing::info!("Initializing metrics...");
        let metrics = PerCurrencyMetrics::new(&vault_id);
        let data = VaultData {
            vault_id: vault_id.clone(),
            btc_rpc: btc_rpc.clone(),
            metrics: metrics.clone(),
        };
        PerCurrencyMetrics::initialize_values(self.btc_parachain.clone(), &data).await;

        self.vault_data.write().await.insert(vault_id, data.clone());

        Ok(btc_rpc)
    }

    pub async fn fetch_vault_ids(&self, startup_collateral_increase: bool) -> Result<(), Error> {
        for vault_id in self
            .btc_parachain
            .get_vaults_by_account_id(self.btc_parachain.get_account_id())
            .await?
        {
            self.add_vault_id(vault_id.clone()).await?;

            if startup_collateral_increase {
                // check if the vault is registered
                match lock_required_collateral(self.btc_parachain.clone(), vault_id).await {
                    Err(Error::RuntimeError(runtime::Error::VaultNotFound)) => {} // not registered
                    Err(e) => tracing::error!("Failed to lock required additional collateral: {}", e),
                    _ => {} // collateral level now OK
                };
            }
        }
        Ok(())
    }

    pub async fn listen_for_vault_id_registrations(self) -> Result<(), ServiceError> {
        Ok(self
            .btc_parachain
            .on_event::<RegisterVaultEvent, _, _, _>(
                |event| async {
                    let vault_id = event.vault_id;
                    if self.btc_parachain.is_this_vault(&vault_id) {
                        tracing::info!("New vault registered: {}", vault_id.pretty_printed());
                        let _ = self.add_vault_id(vault_id).await;
                    }
                },
                |err| tracing::error!("Error (RegisterVaultEvent): {}", err.to_string()),
            )
            .await?)
    }

    pub async fn get_bitcoin_rpc(&self, vault_id: &VaultId) -> Option<BCA> {
        self.vault_data.read().await.get(vault_id).map(|x| x.btc_rpc.clone())
    }

    pub async fn get_vault(&self, vault_id: &VaultId) -> Option<VaultData<BCA>> {
        self.vault_data.read().await.get(vault_id).cloned()
    }

    pub async fn get_entries(&self) -> Vec<VaultData<BCA>> {
        self.vault_data
            .read()
            .await
            .iter()
            .map(|(_, value)| value.clone())
            .collect()
    }

    pub async fn get_vault_ids(&self) -> Vec<VaultId> {
        self.vault_data
            .read()
            .await
            .iter()
            .map(|(vault_id, _)| vault_id.clone())
            .collect()
    }

    pub async fn get_vault_btc_rpcs(&self) -> Vec<(VaultId, BCA)> {
        self.vault_data
            .read()
            .await
            .iter()
            .map(|(vault_id, data)| (vault_id.clone(), data.btc_rpc.clone()))
            .collect()
    }
}

pub struct VaultService {
    btc_parachain: InterBtcParachain,
    walletless_btc_rpc: BitcoinCore,
    config: VaultServiceConfig,
    monitoring_config: MonitoringConfig,
    shutdown: ShutdownSender,
    vault_id_manager: VaultIdManager<BitcoinCore>,
}

#[async_trait]
impl Service<VaultServiceConfig> for VaultService {
    const NAME: &'static str = NAME;
    const VERSION: &'static str = VERSION;

    fn new_service(
        btc_parachain: InterBtcParachain,
        walletless_btc_rpc: BitcoinCore,
        config: VaultServiceConfig,
        monitoring_config: MonitoringConfig,
        shutdown: ShutdownSender,
        constructor: Box<dyn Fn(VaultId) -> Result<BitcoinCore, BitcoinError> + Send + Sync>,
    ) -> Self {
        VaultService::new(
            btc_parachain,
            walletless_btc_rpc,
            config,
            monitoring_config,
            shutdown,
            constructor,
        )
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
        walletless_btc_rpc: BitcoinCore,
        config: VaultServiceConfig,
        monitoring_config: MonitoringConfig,
        shutdown: ShutdownSender,
        constructor: impl Fn(VaultId) -> Result<BitcoinCore, BitcoinError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            btc_parachain: btc_parachain.clone(),
            walletless_btc_rpc,
            config,
            monitoring_config,
            shutdown,
            vault_id_manager: VaultIdManager::new(btc_parachain, constructor),
        }
    }

    fn get_vault_id(&self) -> VaultId {
        let account_id = self.btc_parachain.get_account_id();

        let collateral_currency = if let Some(currency_id) = self.config.collateral_currency_id {
            currency_id
        } else {
            self.btc_parachain.relay_chain_currency_id
        };
        let wrapped_currency = self.btc_parachain.wrapped_currency_id;

        VaultId {
            account_id: account_id.clone(),
            currencies: VaultCurrencyPair {
                collateral: collateral_currency,
                wrapped: wrapped_currency,
            },
        }
    }

    async fn run_service(&self) -> Result<(), Error> {
        let account_id = self.btc_parachain.get_account_id().clone();

        let num_confirmations = match self.config.btc_confirmations {
            Some(x) => x,
            None => self.btc_parachain.get_bitcoin_confirmations().await?,
        };
        tracing::info!("Using {} bitcoin confirmations", num_confirmations);

        self.maybe_register_vault().await?;

        // purposefully _after_ maybe_register_vault and _before_ other calls
        self.vault_id_manager.fetch_vault_ids(false).await?;

        let startup_height = self.await_parachain_block().await?;

        let open_request_executor = execute_open_requests(
            self.shutdown.clone(),
            self.btc_parachain.clone(),
            self.vault_id_manager.clone(),
            self.walletless_btc_rpc.clone(),
            num_confirmations,
            self.config.payment_margin_minutes,
            !self.config.no_auto_refund,
        );
        tokio::spawn(async move {
            tracing::info!("Checking for open requests...");
            match open_request_executor.await {
                Ok(_) => tracing::info!("Done processing open requests"),
                Err(e) => tracing::error!("Failed to process open requests: {}", e),
            }
        });

        // get the relay chain tip but don't error because the relay may not be initialized
        let initial_btc_height = self.btc_parachain.get_best_block_height().await.unwrap_or_default();

        // issue handling
        let issue_set = Arc::new(IssueRequests::new());
        let oldest_issue_btc_height =
            issue::initialize_issue_set(&self.walletless_btc_rpc, &self.btc_parachain, &issue_set).await?;

        let (issue_event_tx, issue_event_rx) = mpsc::channel::<Event>(32);

        let issue_request_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_issue_requests(
                self.vault_id_manager.clone(),
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
            account_id.clone(),
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
                    self.walletless_btc_rpc.clone(),
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
                self.vault_id_manager.clone(),
                replace_event_tx.clone(),
                !self.config.no_auto_replace,
            ),
        );

        let accept_replace_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_accept_replace(
                self.shutdown.clone(),
                self.btc_parachain.clone(),
                self.vault_id_manager.clone(),
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
            account_id.clone(),
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
                self.shutdown.clone(),
                self.btc_parachain.clone(),
                self.vault_id_manager.clone(),
                num_confirmations,
                self.config.payment_margin_minutes,
            ),
        );

        // refund handling
        let refund_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_refund_requests(
                self.shutdown.clone(),
                self.btc_parachain.clone(),
                self.vault_id_manager.clone(),
                num_confirmations,
                !self.config.no_auto_refund,
            ),
        );

        let err_provider = self.btc_parachain.clone();
        let err_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            err_provider
                .on_event_error(|e| tracing::debug!("Received error event: {}", e))
                .await?;
            Ok(())
        });

        // watch vault address registration and report potential thefts
        let vaults_listener = maybe_run_task(
            !self.config.no_vault_theft_report,
            self.start_monitoring_btc_txs().await?,
        );

        let vault_id_registration_listener = wait_or_shutdown(
            self.shutdown.clone(),
            self.vault_id_manager.clone().listen_for_vault_id_registrations(),
        );

        // relay bitcoin block headers to the relay
        let relayer = maybe_run_task(
            !self.config.no_bitcoin_block_relay,
            wait_or_shutdown(
                self.shutdown.clone(),
                run_relayer(Runner::new(
                    self.walletless_btc_rpc.clone(),
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
        let bridge_metrics_listener = maybe_run_task(
            !self.monitoring_config.no_prometheus,
            monitor_bridge_metrics(self.btc_parachain.clone(), self.vault_id_manager.clone()),
        );

        let bridge_metrics_poller = maybe_run_task(
            !self.monitoring_config.no_prometheus,
            poll_metrics(self.btc_parachain.clone(), self.vault_id_manager.clone()),
        );

        // starts all the tasks
        tracing::info!("Starting to listen for events...");
        let _ = tokio::join!(
            // runs error listener to log errors
            tokio::spawn(async move { err_listener.await }),
            // handles new registrations of this vault done externally
            tokio::spawn(async move { vault_id_registration_listener.await }),
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
            // prometheus monitoring
            tokio::task::spawn(async move { bridge_metrics_poller.await }),
            tokio::task::spawn(async move { bridge_metrics_listener.await }),
            // relayer process
            tokio::task::spawn_blocking(move || block_on(relayer)),
        );

        Ok(())
    }

    async fn maybe_register_vault(&self) -> Result<(), Error> {
        let vault_id = self.get_vault_id();

        if is_vault_registered(&self.btc_parachain, &vault_id).await? {
            tracing::info!(
                "[{}] Not registering vault -- already registered",
                vault_id.pretty_printed()
            );
        } else {
            tracing::info!("[{}] Not registered", vault_id.pretty_printed());

            let bitcoin_core_with_wallet = self.vault_id_manager.add_vault_id(vault_id.clone()).await?;

            if let Some(collateral) = self.config.auto_register_with_collateral {
                tracing::info!("[{}] Automatically registering...", vault_id.pretty_printed());
                let public_key = bitcoin_core_with_wallet.get_new_public_key().await?;
                let free_balance = self
                    .btc_parachain
                    .get_free_balance(vault_id.collateral_currency())
                    .await?;
                self.btc_parachain
                    .register_vault(
                        &vault_id,
                        if collateral.gt(&free_balance) {
                            tracing::warn!(
                                "Cannot register with {}, using the available free balance: {}",
                                collateral,
                                free_balance
                            );
                            free_balance
                        } else {
                            collateral
                        },
                        public_key,
                    )
                    .await?;
            } else if let Some(faucet_url) = &self.config.auto_register_with_faucet_url {
                tracing::info!("[{}] Automatically registering...", vault_id.pretty_printed());
                faucet::fund_and_register(&self.btc_parachain, &bitcoin_core_with_wallet, faucet_url, &vault_id)
                    .await?;
            }
        }
        Ok(())
    }

    async fn await_parachain_block(&self) -> Result<u32, Error> {
        // wait for a new block to arrive, to prevent processing an event that potentially
        // has been processed already prior to restarting
        tracing::info!("Waiting for new block...");
        let startup_height = self.btc_parachain.get_current_chain_height().await?;
        while startup_height == self.btc_parachain.get_current_chain_height().await? {
            sleep(CHAIN_HEIGHT_POLLING_INTERVAL).await;
        }
        tracing::info!("Got new block...");
        Ok(startup_height)
    }
    pub(crate) async fn start_monitoring_btc_txs(&self) -> Result<impl Future, Error> {
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
            .unwrap_or(self.walletless_btc_rpc.get_block_count().await? as u32 + 1);

        let bitcoin_listener = wait_or_shutdown(
            self.shutdown.clone(),
            monitor_btc_txs(
                self.walletless_btc_rpc.clone(),
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
            listen_for_wallet_updates(
                self.btc_parachain.clone(),
                self.walletless_btc_rpc.network(),
                vaults.clone(),
            ),
        );

        Ok(futures::future::join3(
            bitcoin_listener,
            vaults_registration_listener,
            wallet_update_listener,
        ))
    }
}

pub(crate) async fn is_vault_registered(parachain_rpc: &InterBtcParachain, vault_id: &VaultId) -> Result<bool, Error> {
    match parachain_rpc.get_vault(vault_id).await {
        Ok(_) => Ok(true),
        Err(RuntimeError::VaultNotFound) => Ok(false),
        Err(err) => Err(err.into()),
    }
}
