use async_trait::async_trait;
use backoff::{retry, ExponentialBackoff};
use bitcoin::{cli::BitcoinOpts as BitcoinConfig, BitcoinCoreApi, Error as BitcoinError};
use futures::{future::Either, Future, FutureExt};
use governor::{Quota, RateLimiter};
use nonzero_ext::*;
use runtime::{
    cli::ConnectionOpts as ParachainConfig, CurrencyId, InterBtcParachain as BtcParachain, InterBtcSigner, PrettyPrint,
    RuntimeCurrencyInfo, VaultId,
};
use std::{fmt, sync::Arc, time::Duration};
mod cli;
pub mod trace;
pub use crate::Error;
pub use cli::{LoggingFormat, MonitoringConfig, RestartPolicy, ServiceConfig};
pub use runtime::{ShutdownReceiver, ShutdownSender};
pub use trace::init_subscriber;
pub use warp;

pub type DynBitcoinCoreApi = Arc<dyn BitcoinCoreApi + Send + Sync>;

#[async_trait]
pub trait Service<Config> {
    const NAME: &'static str;
    const VERSION: &'static str;

    fn new_service(
        btc_parachain: BtcParachain,
        bitcoin_core_master: DynBitcoinCoreApi,
        bitcoin_core_shared: DynBitcoinCoreApi,
        config: Config,
        monitoring_config: MonitoringConfig,
        shutdown: ShutdownSender,
        constructor: Box<dyn Fn(VaultId) -> Result<DynBitcoinCoreApi, BitcoinError> + Send + Sync>,
        keyname: String,
    ) -> Self;
    async fn start(&self) -> Result<(), backoff::Error<Error>>;
}

pub struct ConnectionManager<Config: Clone, F: Fn()> {
    signer: InterBtcSigner,
    wallet_name: Option<String>,
    bitcoin_config: BitcoinConfig,
    parachain_config: ParachainConfig,
    service_config: ServiceConfig,
    monitoring_config: MonitoringConfig,
    config: Config,
    increment_restart_counter: F,
    db_path: String,
}

impl<Config: Clone + Send + 'static, F: Fn()> ConnectionManager<Config, F> {
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
        db_path: String,
    ) -> Self {
        Self {
            signer,
            wallet_name,
            bitcoin_config,
            parachain_config,
            service_config,
            monitoring_config,
            config,
            increment_restart_counter,
            db_path,
        }
    }

    pub async fn start<S: Service<Config>>(&self) -> Result<(), Error> {
        loop {
            tracing::info!("Version: {}", S::VERSION);
            tracing::info!("AccountId: {}", self.signer.account_id.pretty_print());

            let config = self.config.clone();
            let shutdown_tx = ShutdownSender::new();

            let prefix = self.wallet_name.clone().unwrap_or_else(|| "vault".to_string());
            let bitcoin_core_master = self.bitcoin_config.new_client(Some(format!("{prefix}-master"))).await?;

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
            let network_copy = bitcoin_core_master.network();

            // use a separate wallet for all bitcoin transactions
            // to make exporting the private key easier from the
            // master wallet if we switch to descriptor wallets
            let bitcoin_core_shared =
                config_copy.new_client_with_network(Some(format!("{prefix}-shared")), network_copy)?;

            let constructor = move |vault_id: VaultId| {
                let collateral_currency: CurrencyId = vault_id.collateral_currency();
                let wrapped_currency: CurrencyId = vault_id.wrapped_currency();
                let wallet_name = format!(
                    "{}-{}-{}",
                    prefix,
                    collateral_currency
                        .symbol()
                        .map_err(|_| BitcoinError::FailedToConstructWalletName)?,
                    wrapped_currency
                        .symbol()
                        .map_err(|_| BitcoinError::FailedToConstructWalletName)?,
                );
                config_copy.new_client_with_network(Some(wallet_name), network_copy)
            };

            let service = S::new_service(
                btc_parachain,
                bitcoin_core_master,
                bitcoin_core_shared,
                config,
                self.monitoring_config.clone(),
                shutdown_tx.clone(),
                Box::new(constructor),
                self.db_path.clone(),
            );

            let backoff = ExponentialBackoff::default();

            backoff::future::retry::<(), Error, _, _, _>(backoff, || async {
                match service.start().await {
                    Ok(()) => Ok(()),
                    //ToDo: log errors only return for Permanent error, others ignore
                    Err(err) => Err(err),
                }
            })
            .await?;

            // propagate shutdown signal from main tasks
            let _ = shutdown_tx.send(());

            let rate_limiter = RateLimiter::direct(Quota::per_minute(nonzero!(4u32)));

            loop {
                match shutdown_tx.receiver_count() {
                    0 => break,
                    count => {
                        if rate_limiter.check().is_ok() {
                            tracing::error!("Waiting for {count} tasks to shut down...");
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            tracing::info!("All tasks successfully shut down");

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

pub async fn wait_or_shutdown<F, E>(shutdown_tx: ShutdownSender, future2: F) -> Result<(), E>
where
    F: Future<Output = Result<(), E>>,
{
    match run_cancelable(shutdown_tx.subscribe(), future2).await {
        TerminationStatus::Cancelled => {
            tracing::trace!("Received shutdown signal");
            Ok(())
        }
        TerminationStatus::Completed(res) => {
            tracing::trace!("Sending shutdown signal");
            let _ = shutdown_tx.send(());
            res
        }
    }
}

pub enum TerminationStatus<Res> {
    Cancelled,
    Completed(Res),
}

async fn run_cancelable<F, Res>(mut shutdown_rx: ShutdownReceiver, future2: F) -> TerminationStatus<Res>
where
    F: Future<Output = Res>,
{
    let future1 = shutdown_rx.recv().fuse();
    let future2 = future2.fuse();

    futures::pin_mut!(future1);
    futures::pin_mut!(future2);

    match futures::future::select(future1, future2).await {
        Either::Left((_, _)) => TerminationStatus::Cancelled,
        Either::Right((res, _)) => TerminationStatus::Completed(res),
    }
}

pub fn spawn_cancelable<T: Future + Send + 'static>(shutdown_rx: ShutdownReceiver, future: T)
where
    <T as futures::Future>::Output: Send,
{
    tokio::spawn(run_cancelable(shutdown_rx, future));
}

pub async fn on_shutdown(shutdown_tx: ShutdownSender, future2: impl Future) {
    let mut shutdown_rx = shutdown_tx.subscribe();
    let future1 = shutdown_rx.recv().fuse();

    let _ = future1.await;
    future2.await;
}
