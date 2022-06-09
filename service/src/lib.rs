use async_trait::async_trait;
use bitcoin::{cli::BitcoinOpts as BitcoinConfig, BitcoinCore, BitcoinCoreApi, Error as BitcoinError};
use futures::{future::Either, Future, FutureExt};
use runtime::{
    cli::ConnectionOpts as ParachainConfig, CurrencyId, CurrencyIdExt, CurrencyInfo, Error as RuntimeError,
    InterBtcParachain as BtcParachain, InterBtcSigner, PrettyPrint, VaultId,
};
use std::marker::PhantomData;

mod cli;
mod error;
mod trace;

pub use cli::{LoggingFormat, MonitoringConfig, RestartPolicy, ServiceConfig};
pub use error::Error;
pub use trace::init_subscriber;
pub use warp;

pub type ShutdownSender = tokio::sync::broadcast::Sender<Option<()>>;
pub type ShutdownReceiver = tokio::sync::broadcast::Receiver<Option<()>>;

#[async_trait]
pub trait Service<Config> {
    const NAME: &'static str;
    const VERSION: &'static str;

    fn new_service(
        btc_parachain: BtcParachain,
        bitcoin_core: BitcoinCore,
        config: Config,
        monitoring_config: MonitoringConfig,
        shutdown: ShutdownSender,
        constructor: Box<dyn Fn(VaultId) -> Result<BitcoinCore, BitcoinError> + Send + Sync>,
    ) -> Self;
    async fn start(&self) -> Result<(), Error>;
}

pub struct ConnectionManager<Config: Clone, S: Service<Config>, F: Fn()> {
    signer: InterBtcSigner,
    wallet_name: Option<String>,
    bitcoin_config: BitcoinConfig,
    parachain_config: ParachainConfig,
    service_config: ServiceConfig,
    monitoring_config: MonitoringConfig,
    config: Config,
    _marker: PhantomData<S>,
    increment_restart_counter: F,
}

impl<Config: Clone + Send + 'static, S: Service<Config>, F: Fn()> ConnectionManager<Config, S, F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer: InterBtcSigner,
        wallet_name: Option<String>,
        bitcoin_config: BitcoinConfig,
        parachain_config: ParachainConfig,
        service_config: ServiceConfig,
        monitoring_config: MonitoringConfig,
        config: Config,
        increment_restart_counter: F,
    ) -> Self {
        Self {
            signer,
            wallet_name,
            bitcoin_config,
            parachain_config,
            service_config,
            monitoring_config,
            config,
            _marker: PhantomData::default(),
            increment_restart_counter,
        }
    }
}

impl<Config: Clone + Send + 'static, S: Service<Config>, F: Fn()> ConnectionManager<Config, S, F> {
    pub async fn start(&self) -> Result<(), Error> {
        loop {
            tracing::info!("Version: {}", S::VERSION);
            tracing::info!("AccountId: {}", self.signer.account_id().pretty_print());

            let config = self.config.clone();
            let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);

            let prefix = self.wallet_name.clone().unwrap_or_else(|| "vault".to_string());
            let bitcoin_core = self.bitcoin_config.new_client(Some(format!("{prefix}-master"))).await?;
            bitcoin_core.sync().await?;
            bitcoin_core.create_or_load_wallet().await?;

            // only open connection to parachain after bitcoind sync to prevent timeout
            let signer = self.signer.clone();
            let btc_parachain = BtcParachain::from_url_and_config_with_retry(
                &self.parachain_config.btc_parachain_url,
                signer,
                self.parachain_config.max_concurrent_requests,
                self.parachain_config.max_notifs_per_subscription,
                self.parachain_config.btc_parachain_connection_timeout_ms,
                shutdown_tx.clone(),
            )
            .await?;

            let config_copy = self.bitcoin_config.clone();
            let network_copy = bitcoin_core.network();
            let constructor = move |vault_id: VaultId| {
                let collateral_currency: CurrencyId = vault_id.collateral_currency();
                let wrapped_currency: CurrencyId = vault_id.wrapped_currency();
                // convert to the native type
                let wallet_name = format!(
                    "{}-{}-{}",
                    prefix,
                    collateral_currency
                        .inner()
                        .map(|i| i.symbol().to_string())
                        .unwrap_or_default(),
                    wrapped_currency
                        .inner()
                        .map(|i| i.symbol().to_string())
                        .unwrap_or_default(),
                );
                config_copy.new_client_with_network(Some(wallet_name), network_copy)
            };

            let service = S::new_service(
                btc_parachain,
                bitcoin_core,
                config,
                self.monitoring_config.clone(),
                shutdown_tx,
                Box::new(constructor),
            );
            if let Err(outer) = service.start().await {
                match outer {
                    Error::BitcoinError(ref inner) if inner.is_transport_error() || inner.is_json_decode_error() => {}
                    Error::RuntimeError(RuntimeError::ChannelClosed) => (),
                    Error::RuntimeError(ref inner) if inner.is_rpc_error() => (),
                    other => return Err(other),
                };
                tracing::info!("Disconnected: {}", outer);
            } else {
                tracing::info!("Disconnected");
            }

            match self.service_config.restart_policy {
                RestartPolicy::Never => return Err(Error::ClientShutdown),
                RestartPolicy::Always => {
                    (self.increment_restart_counter)();
                    continue;
                }
            };
        }
    }
}

pub async fn wait_or_shutdown<F>(shutdown_tx: ShutdownSender, future2: F)
where
    F: Future<Output = Result<(), Error>>,
{
    match run_cancelable(shutdown_tx.subscribe(), future2).await {
        TerminationStatus::Cancelled => {
            tracing::trace!("Received shutdown signal");
        }
        TerminationStatus::Completed => {
            tracing::trace!("Sending shutdown signal");
            // TODO: shutdown signal should be error
            let _ = shutdown_tx.send(Some(()));
        }
    }
}

pub enum TerminationStatus {
    Cancelled,
    Completed,
}
async fn run_cancelable<F, Ret>(mut shutdown_rx: ShutdownReceiver, future2: F) -> TerminationStatus
where
    F: Future<Output = Ret>,
{
    let future1 = shutdown_rx.recv().fuse();
    let future2 = future2.fuse();

    futures::pin_mut!(future1);
    futures::pin_mut!(future2);

    match futures::future::select(future1, future2).await {
        Either::Left((_, _)) => TerminationStatus::Cancelled,
        Either::Right((_, _)) => TerminationStatus::Completed,
    }
}

pub fn spawn_cancelable<T: Future + Send + 'static>(shutdown_rx: ShutdownReceiver, future: T) {
    tokio::spawn(run_cancelable(shutdown_rx, future));
}

pub async fn on_shutdown(shutdown_tx: ShutdownSender, future2: impl Future) {
    let mut shutdown_rx = shutdown_tx.subscribe();
    let future1 = shutdown_rx.recv().fuse();

    let _ = future1.await;
    future2.await;
}
