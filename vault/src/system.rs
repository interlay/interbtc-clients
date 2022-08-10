use crate::{
    collateral::lock_required_collateral,
    delay::{OrderedVaultsDelay, RandomDelay, ZeroDelay},
    error::Error,
    faucet, issue,
    metrics::{poll_metrics, publish_tokio_metrics, PerCurrencyMetrics},
    relay::run_relayer,
    service::*,
    Event, IssueRequests, CHAIN_HEIGHT_POLLING_INTERVAL,
};
use async_trait::async_trait;
use bitcoin::{BitcoinCore, BitcoinCoreApi, Error as BitcoinError};
use clap::Parser;
use futures::{
    channel::{mpsc, mpsc::Sender},
    future::{join, join_all},
    Future, SinkExt, TryFutureExt,
};
use git_version::git_version;
use runtime::{
    cli::{parse_duration_minutes, parse_duration_ms},
    BtcRelayPallet, CollateralBalancesPallet, CurrencyId, Error as RuntimeError, InterBtcParachain, PrettyPrint,
    RegisterVaultEvent, StoreMainChainHeaderEvent, UpdateActiveBlockEvent, UtilFuncs, VaultCurrencyPair, VaultId,
    VaultRegistryPallet,
};
use service::{wait_or_shutdown, Error as ServiceError, MonitoringConfig, Service, ShutdownSender};
use std::{collections::HashMap, pin::Pin, sync::Arc, time::Duration};
use tokio::{sync::RwLock, time::sleep};

pub const VERSION: &str = git_version!(args = ["--tags"]);
pub const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

const RESTART_INTERVAL: Duration = Duration::from_secs(10800); // restart every 3 hours

fn parse_collateral_and_amount(
    s: &str,
) -> Result<(String, Option<u128>), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid CurrencyId=amount: no `=` found in `{}`", s))?;

    let val = &s[pos + 1..];
    Ok((
        s[..pos].to_string(),
        if val.contains("faucet") {
            None
        } else {
            Some(val.parse()?)
        },
    ))
}

#[derive(Parser, Clone, Debug)]
pub struct VaultServiceConfig {
    /// Automatically register the vault with the given amount of collateral and a newly generated address.
    #[clap(long, parse(try_from_str = parse_collateral_and_amount))]
    pub auto_register: Vec<(String, Option<u128>)>,

    /// Pass the faucet URL for auto-registration.
    #[clap(long)]
    pub faucet_url: Option<String>,

    /// Opt out of participation in replace requests.
    #[clap(long)]
    pub no_auto_replace: bool,

    /// Don't try to execute issues.
    #[clap(long)]
    pub no_issue_execution: bool,

    /// Don't run the RPC API.
    #[clap(long)]
    pub no_api: bool,

    /// Attempt to execute best-effort transactions immediately, rather than using a random delay.
    #[clap(long)]
    pub no_random_delay: bool,

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

    /// Don't refund overpayments.
    #[clap(long)]
    pub no_auto_refund: bool,
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
    btc_rpc_master_wallet: BCA,
    // TODO: refactor this
    #[allow(clippy::type_complexity)]
    constructor: Arc<Box<dyn Fn(VaultId) -> Result<BCA, BitcoinError> + Send + Sync>>,
}

impl<BCA: BitcoinCoreApi + Clone + Send + Sync + 'static> VaultIdManager<BCA> {
    pub fn new(
        btc_parachain: InterBtcParachain,
        btc_rpc_master_wallet: BCA,
        constructor: impl Fn(VaultId) -> Result<BCA, BitcoinError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            vault_data: Arc::new(RwLock::new(HashMap::new())),
            constructor: Arc::new(Box::new(constructor)),
            btc_rpc_master_wallet,
            btc_parachain,
        }
    }

    // used for testing only
    pub fn from_map(btc_parachain: InterBtcParachain, btc_rpc_master_wallet: BCA, map: HashMap<VaultId, BCA>) -> Self {
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
            btc_rpc_master_wallet,
            btc_parachain,
        }
    }

    async fn add_vault_id(&self, vault_id: VaultId) -> Result<(), Error> {
        let btc_rpc = (*self.constructor)(vault_id.clone())?;

        // load wallet. Exit on failure, since without wallet we can't do a lot
        btc_rpc
            .create_or_load_wallet()
            .await
            .map_err(Error::WalletInitializationFailure)?;

        tracing::info!("Adding derivation key...");
        let derivation_key = self
            .btc_parachain
            .get_public_key()
            .await?
            .ok_or(bitcoin::Error::MissingPublicKey)?;

        // migration to the new shared public key setup: copy the public key from the
        // currency-specific wallet to the master wallet. This can be removed once all
        // vaults have migrated
        if let Ok(private_key) = btc_rpc.dump_derivation_key(derivation_key.0) {
            self.btc_rpc_master_wallet.import_derivation_key(&private_key)?;
        }

        // Copy the derivation key from the master wallet to use currency-specific wallet
        match self.btc_rpc_master_wallet.dump_derivation_key(derivation_key.0) {
            Ok(private_key) => {
                btc_rpc.import_derivation_key(&private_key)?;
            }
            Err(err) => {
                tracing::error!("Could not find the derivation key in the bitcoin wallet");
                return Err(err.into());
            }
        }

        tracing::info!("Adding keys from past issues...");
        issue::add_keys_from_past_issue_request(&btc_rpc, &self.btc_parachain, &vault_id).await?;

        tracing::info!("Initializing metrics...");
        let metrics = PerCurrencyMetrics::new(&vault_id);
        let data = VaultData {
            vault_id: vault_id.clone(),
            btc_rpc: btc_rpc.clone(),
            metrics: metrics.clone(),
        };
        PerCurrencyMetrics::initialize_values(self.btc_parachain.clone(), &data).await;

        self.vault_data.write().await.insert(vault_id, data.clone());

        Ok(())
    }

    pub async fn fetch_vault_ids(&self, startup_collateral_increase: bool) -> Result<(), Error> {
        for vault_id in self
            .btc_parachain
            .get_vaults_by_account_id(self.btc_parachain.get_account_id())
            .await?
        {
            match is_vault_registered(&self.btc_parachain, &vault_id).await {
                Err(Error::RuntimeError(RuntimeError::VaultLiquidated)) => {
                    tracing::error!(
                        "[{}] Vault is liquidated -- not going to process events for this vault.",
                        vault_id.pretty_print()
                    );
                }
                Ok(_) => {
                    self.add_vault_id(vault_id.clone()).await?;
                }
                Err(x) => {
                    return Err(x);
                }
            }

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
                        tracing::info!("New vault registered: {}", vault_id.pretty_print());
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
    btc_rpc_master_wallet: BitcoinCore,
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
        btc_rpc_master_wallet: BitcoinCore,
        config: VaultServiceConfig,
        monitoring_config: MonitoringConfig,
        shutdown: ShutdownSender,
        constructor: Box<dyn Fn(VaultId) -> Result<BitcoinCore, BitcoinError> + Send + Sync>,
    ) -> Self {
        VaultService::new(
            btc_parachain,
            btc_rpc_master_wallet,
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

async fn run_and_monitor_tasks(shutdown_tx: ShutdownSender, items: Vec<(&str, ServiceTask)>) {
    let (metrics_iterators, tasks): (HashMap<String, _>, Vec<_>) = items
        .into_iter()
        .filter_map(|(name, task)| {
            let monitor = tokio_metrics::TaskMonitor::new();
            let metrics_iterator = monitor.intervals();
            let task = match task {
                ServiceTask::Optional(true, t) | ServiceTask::Essential(t) => {
                    Some(wait_or_shutdown(shutdown_tx.clone(), t))
                }
                _ => None,
            }?;
            let task = monitor.instrument(task);
            let task = tokio::spawn(task);
            Some(((name.to_string(), metrics_iterator), task))
        })
        .unzip();

    let tokio_metrics = tokio::spawn(wait_or_shutdown(
        shutdown_tx.clone(),
        publish_tokio_metrics(metrics_iterators),
    ));

    let _ = join(tokio_metrics, join_all(tasks)).await;
}

type Task = Pin<Box<dyn Future<Output = Result<(), service::Error>> + Send + 'static>>;

enum ServiceTask {
    Optional(bool, Task),
    Essential(Task),
}

fn maybe_run<F, E>(should_run: bool, task: F) -> ServiceTask
where
    F: Future<Output = Result<(), E>> + Send + 'static,
    E: Into<service::Error>,
{
    ServiceTask::Optional(should_run, Box::pin(task.map_err(|x| x.into())))
}
fn run<F, E>(task: F) -> ServiceTask
where
    F: Future<Output = Result<(), E>> + Send + 'static,
    E: Into<service::Error>,
{
    ServiceTask::Essential(Box::pin(task.map_err(|x| x.into())))
}

impl VaultService {
    fn new(
        btc_parachain: InterBtcParachain,
        btc_rpc_master_wallet: BitcoinCore,
        config: VaultServiceConfig,
        monitoring_config: MonitoringConfig,
        shutdown: ShutdownSender,
        constructor: impl Fn(VaultId) -> Result<BitcoinCore, BitcoinError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            btc_parachain: btc_parachain.clone(),
            btc_rpc_master_wallet: btc_rpc_master_wallet.clone(),
            config,
            monitoring_config,
            shutdown,
            vault_id_manager: VaultIdManager::new(btc_parachain, btc_rpc_master_wallet, constructor),
        }
    }

    fn get_vault_id(&self, collateral_currency: CurrencyId) -> VaultId {
        let account_id = self.btc_parachain.get_account_id();
        let wrapped_currency = self.btc_parachain.wrapped_currency_id;

        VaultId {
            account_id: account_id.clone(),
            currencies: VaultCurrencyPair {
                collateral: collateral_currency,
                wrapped: wrapped_currency,
            },
        }
    }

    async fn validate_bitcoin_network(&self) -> Result<(), Error> {
        let bitcoin_network = self.btc_rpc_master_wallet.network().to_string();
        let system_properties = self.btc_parachain.get_rpc_properties().await.unwrap_or_default();

        if let Some(parachain_bitcoin_network) = system_properties.get("bitcoinNetwork") {
            let parachain_bitcoin_network_string = parachain_bitcoin_network.as_str().unwrap_or_default().to_string();
            // `parachain_bitcoin_network` can be `bitcoin-mainnet`, `bitcoin-testnet`, or `bitcoin-regtest`
            // source: https://github.com/interlay/interbtc/blob/a71b970616b0a4a59cd2e709a606a9a78fce80ff/primitives/src/lib.rs#L23
            // `bitcoin_network` can be `mainnet`, `testnet`, regtest.
            // source: https://developer.bitcoin.org/reference/rpc/getblockchaininfo.html
            if !parachain_bitcoin_network_string.contains(&bitcoin_network) {
                return Err(
                    runtime::Error::BitcoinNetworkMismatch(parachain_bitcoin_network_string, bitcoin_network).into(),
                );
            }
        }

        Ok(())
    }

    async fn run_service(&self) -> Result<(), Error> {
        self.validate_bitcoin_network().await?;

        let account_id = self.btc_parachain.get_account_id().clone();

        let parsed_auto_register = join_all(self.config.auto_register.iter().map(|(symbol, amount)| async move {
            Ok((self.btc_parachain.parse_currency_id(symbol.to_string()).await?, amount))
        }))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, Error>>()?;

        // exit if auto-register uses faucet and faucet url not set
        if parsed_auto_register.iter().any(|(_, o)| o.is_none()) && self.config.faucet_url.is_none() {
            // TODO: validate before bitcoin / parachain connections
            return Err(Error::FaucetUrlNotSet);
        }

        let num_confirmations = match self.config.btc_confirmations {
            Some(x) => x,
            None => self.btc_parachain.get_bitcoin_confirmations().await?,
        };
        tracing::info!("Using {} bitcoin confirmations", num_confirmations);

        // Subscribe to an event (any event will do) so that a period of inactivity does not close the jsonrpsee
        // connection
        tracing::info!("Subscribing to error events...");
        let err_provider = self.btc_parachain.clone();
        let err_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            err_provider
                .on_event_error(|e| tracing::debug!("Received error event: {}", e))
                .await?;
            Ok(())
        });
        tokio::task::spawn(err_listener);

        self.maybe_register_public_key().await?;
        join_all(
            parsed_auto_register
                .iter()
                .map(|(currency_id, amount)| self.maybe_register_vault(currency_id, amount)),
        )
        .await;

        // purposefully _after_ maybe_register_vault and _before_ other calls
        self.vault_id_manager.fetch_vault_ids(false).await?;

        let startup_height = self.await_parachain_block().await?;

        let open_request_executor = execute_open_requests(
            self.shutdown.clone(),
            self.btc_parachain.clone(),
            self.vault_id_manager.clone(),
            self.btc_rpc_master_wallet.clone(),
            num_confirmations,
            self.config.payment_margin_minutes,
            !self.config.no_auto_refund,
        );
        tokio::spawn(async move {
            tracing::info!("Checking for open requests...");
            // TODO: kill task on shutdown signal to prevent double payment
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
            issue::initialize_issue_set(&self.btc_rpc_master_wallet, &self.btc_parachain, &issue_set).await?;

        let random_delay: Arc<Box<dyn RandomDelay + Send + Sync>> = if self.config.no_random_delay {
            Arc::new(Box::new(ZeroDelay))
        } else {
            Arc::new(Box::new(OrderedVaultsDelay::new(self.btc_parachain.clone()).await?))
        };

        let (issue_event_tx, issue_event_rx) = mpsc::channel::<Event>(32);
        let (replace_event_tx, replace_event_rx) = mpsc::channel::<Event>(16);

        let tasks = vec![
            (
                "Issue Request Listener",
                run(listen_for_issue_requests(
                    self.vault_id_manager.clone(),
                    self.btc_parachain.clone(),
                    issue_event_tx.clone(),
                    issue_set.clone(),
                )),
            ),
            (
                "Issue Execute Listener",
                run(listen_for_issue_executes(
                    self.btc_parachain.clone(),
                    issue_event_tx.clone(),
                    issue_set.clone(),
                )),
            ),
            (
                "Issue Cancel Listener",
                run(listen_for_issue_cancels(self.btc_parachain.clone(), issue_set.clone())),
            ),
            (
                "Issue Cancel Scheduler",
                run(CancellationScheduler::new(
                    self.btc_parachain.clone(),
                    startup_height,
                    initial_btc_height,
                    account_id.clone(),
                )
                .handle_cancellation::<IssueCanceller>(issue_event_rx)),
            ),
            (
                "Request Replace Listener",
                run(listen_for_replace_requests(
                    self.btc_parachain.clone(),
                    self.vault_id_manager.clone(),
                    replace_event_tx.clone(),
                    !self.config.no_auto_replace,
                )),
            ),
            (
                "Accept Replace Listener",
                run(listen_for_accept_replace(
                    self.shutdown.clone(),
                    self.btc_parachain.clone(),
                    self.vault_id_manager.clone(),
                    num_confirmations,
                    self.config.payment_margin_minutes,
                )),
            ),
            (
                "Execute Replace Listener",
                run(listen_for_execute_replace(
                    self.btc_parachain.clone(),
                    replace_event_tx.clone(),
                )),
            ),
            (
                "Replace Cancellation Scheduler",
                run(CancellationScheduler::new(
                    self.btc_parachain.clone(),
                    startup_height,
                    initial_btc_height,
                    account_id.clone(),
                )
                .handle_cancellation::<ReplaceCanceller>(replace_event_rx)),
            ),
            (
                "Parachain Block Listener",
                run(active_block_listener(
                    self.btc_parachain.clone(),
                    issue_event_tx.clone(),
                    replace_event_tx.clone(),
                )),
            ),
            (
                "Bitcoin Block Listener",
                run(relay_block_listener(
                    self.btc_parachain.clone(),
                    issue_event_tx.clone(),
                    replace_event_tx.clone(),
                )),
            ),
            (
                "Redeem Request Listener",
                run(listen_for_redeem_requests(
                    self.shutdown.clone(),
                    self.btc_parachain.clone(),
                    self.vault_id_manager.clone(),
                    num_confirmations,
                    self.config.payment_margin_minutes,
                )),
            ),
            (
                "Refund Request Listener",
                run(listen_for_refund_requests(
                    self.shutdown.clone(),
                    self.btc_parachain.clone(),
                    self.vault_id_manager.clone(),
                    num_confirmations,
                    !self.config.no_auto_refund,
                )),
            ),
            (
                "VaultId Registration Listener",
                run(self.vault_id_manager.clone().listen_for_vault_id_registrations()),
            ),
            (
                "Bitcoin Relay",
                maybe_run(
                    !self.config.no_bitcoin_block_relay,
                    run_relayer(Runner::new(
                        self.btc_rpc_master_wallet.clone(),
                        self.btc_parachain.clone(),
                        Config {
                            start_height: self.config.bitcoin_relay_start_height,
                            max_batch_size: self.config.max_batch_size,
                            interval: Some(self.config.bitcoin_poll_interval_ms),
                            btc_confirmations: self.config.bitcoin_relay_confirmations,
                        },
                        random_delay.clone(),
                    )),
                ),
            ),
            (
                "Issue Executor",
                maybe_run(
                    !self.config.no_issue_execution,
                    issue::process_issue_requests(
                        self.btc_rpc_master_wallet.clone(),
                        self.btc_parachain.clone(),
                        issue_set.clone(),
                        oldest_issue_btc_height,
                        num_confirmations,
                        random_delay,
                    ),
                ),
            ),
            (
                "Bridge Metrics Listener",
                maybe_run(
                    !self.monitoring_config.no_prometheus,
                    monitor_bridge_metrics(self.btc_parachain.clone(), self.vault_id_manager.clone()),
                ),
            ),
            (
                "Bridge Metrics Poller",
                maybe_run(
                    !self.monitoring_config.no_prometheus,
                    poll_metrics(self.btc_parachain.clone(), self.vault_id_manager.clone()),
                ),
            ),
            (
                "Restart Timer",
                run(async move {
                    tokio::time::sleep(RESTART_INTERVAL).await;
                    tracing::info!("Initiating periodic restart...");
                    Err(service::Error::ClientShutdown)
                }),
            ),
        ];

        run_and_monitor_tasks(self.shutdown.clone(), tasks).await;

        Ok(())
    }

    async fn maybe_register_public_key(&self) -> Result<(), Error> {
        if let Some(faucet_url) = &self.config.faucet_url {
            // fund the native token first to pay for tx fees
            crate::faucet::fund_account(faucet_url, &self.get_vault_id(self.btc_parachain.native_currency_id)).await?;
        }

        if self.btc_parachain.get_public_key().await?.is_none() {
            tracing::info!("Registering bitcoin public key to the parachain...");
            let new_key = self.btc_rpc_master_wallet.get_new_public_key().await?;
            self.btc_parachain.register_public_key(new_key).await?;
        }

        Ok(())
    }

    async fn maybe_register_vault(
        &self,
        collateral_currency: &CurrencyId,
        maybe_collateral_amount: &Option<u128>,
    ) -> Result<(), Error> {
        let vault_id = self.get_vault_id(*collateral_currency);

        match is_vault_registered(&self.btc_parachain, &vault_id).await {
            Err(Error::RuntimeError(RuntimeError::VaultLiquidated)) | Ok(true) => {
                tracing::info!(
                    "[{}] Not registering vault -- already registered",
                    vault_id.pretty_print()
                );
            }
            Ok(false) => {
                tracing::info!("[{}] Not registered", vault_id.pretty_print());
                if let Some(collateral) = maybe_collateral_amount {
                    tracing::info!("[{}] Automatically registering...", vault_id.pretty_print());
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
                                *collateral
                            },
                        )
                        .await?;
                } else if let Some(faucet_url) = &self.config.faucet_url {
                    tracing::info!("[{}] Automatically registering...", vault_id.pretty_print());
                    faucet::fund_and_register(&self.btc_parachain, faucet_url, &vault_id).await?;
                }
            }
            Err(x) => return Err(x),
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
}

pub(crate) async fn is_vault_registered(parachain_rpc: &InterBtcParachain, vault_id: &VaultId) -> Result<bool, Error> {
    match parachain_rpc.get_vault(vault_id).await {
        Ok(_) => Ok(true),
        Err(RuntimeError::VaultNotFound) => Ok(false),
        Err(err) => Err(err.into()),
    }
}
