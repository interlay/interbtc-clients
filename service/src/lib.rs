use async_trait::async_trait;
use bitcoin::{cli::BitcoinOpts as BitcoinConfig, BitcoinCore};
use futures::{future::Either, Future, FutureExt};
use runtime::{
    cli::ConnectionOpts as ParachainConfig, substrate_subxt::Signer, CurrencyInfo, Error as RuntimeError,
    InterBtcParachain as BtcParachain, InterBtcSigner, VaultId,
};
use sp_core::crypto::Ss58Codec;
use std::marker::PhantomData;

mod cli;
mod error;
mod telemetry;
mod trace;

use telemetry::TelemetryClient;

pub use cli::{LoggingFormat, RestartPolicy, ServiceConfig};
pub use error::Error;
pub use trace::init_subscriber;
use bitcoin::Error as BitcoinError;

pub type ShutdownSender = tokio::sync::broadcast::Sender<Option<()>>;

#[async_trait]
pub trait Service<Config> {
    const NAME: &'static str;
    const VERSION: &'static str;

    fn new_service(
        btc_parachain: BtcParachain,
        bitcoin_core: BitcoinCore,
        config: Config,
        shutdown: ShutdownSender,
        constructor: Box<dyn Fn(VaultId) -> Result<BitcoinCore, BitcoinError> + Send + Sync>,
    ) -> Self;
    async fn start(&self) -> Result<(), Error>;
}

pub struct ConnectionManager<Config: Clone, S: Service<Config>> {
    signer: InterBtcSigner,
    wallet_name: Option<String>,
    bitcoin_config: BitcoinConfig,
    parachain_config: ParachainConfig,
    service_config: ServiceConfig,
    config: Config,
    _marker: PhantomData<S>,
}

impl<Config: Clone + Send + 'static, S: Service<Config>> ConnectionManager<Config, S> {
    pub fn new(
        signer: InterBtcSigner,
        wallet_name: Option<String>,
        bitcoin_config: BitcoinConfig,
        parachain_config: ParachainConfig,
        service_config: ServiceConfig,
        config: Config,
    ) -> Self {
        Self {
            signer,
            wallet_name,
            bitcoin_config,
            parachain_config,
            service_config,
            config,
            _marker: PhantomData::default(),
        }
    }
}

impl<Config: Clone + Send + 'static, S: Service<Config>> ConnectionManager<Config, S> {
    pub async fn start(&self) -> Result<(), Error> {
        if let Some(uri) = &self.service_config.telemetry_url {
            // run telemetry client heartbeat
            let telemetry_client = TelemetryClient::new(uri.clone(), self.signer.clone());
            tokio::spawn(async move { telemetry::do_update(&telemetry_client, S::NAME, S::VERSION).await });
        }

        tracing::info!("AccountId: {}", self.signer.account_id().to_ss58check());

        loop {
            let config = self.config.clone();
            let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);

            let bitcoin_core = self.bitcoin_config.new_client(None)?;
            bitcoin_core.connect().await?;
            bitcoin_core.sync().await?;

            // only open connection to parachain after bitcoind sync to prevent timeout
            let signer = self.signer.clone();
            let btc_parachain = BtcParachain::from_url_and_config_with_retry(
                &self.parachain_config.btc_parachain_url,
                signer,
                self.parachain_config.max_concurrent_requests,
                self.parachain_config.max_notifs_per_subscription,
                self.parachain_config.btc_parachain_connection_timeout_ms,
            )
            .await?;

            let config_copy = self.bitcoin_config.clone();
            let prefix = self.wallet_name.clone().unwrap_or("vault".to_string());
            let constructor = move |vault_id: VaultId| {
                let wallet_name = format!(
                    "{}-{}-{}",
                    prefix,
                    vault_id.collateral_currency().symbol(),
                    vault_id.wrapped_currency().symbol()
                );
                let btc_rpc = config_copy.new_client(Some(wallet_name))?;
                Ok(btc_rpc)
            };

            let service = S::new_service(btc_parachain, bitcoin_core, config, shutdown_tx, Box::new(constructor));
            if let Err(outer) = service.start().await {
                match outer {
                    Error::BitcoinError(ref inner)
                        if inner.is_connection_aborted()
                            || inner.is_connection_refused()
                            || inner.is_json_decode_error() => {}
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
                RestartPolicy::Always => continue,
            };
        }
    }
}

pub async fn wait_or_shutdown<F>(shutdown_tx: ShutdownSender, future2: F)
where
    F: Future<Output = Result<(), Error>>,
{
    let mut shutdown_rx = shutdown_tx.subscribe();

    let future1 = shutdown_rx.recv().fuse();
    let future2 = future2.fuse();

    futures::pin_mut!(future1);
    futures::pin_mut!(future2);

    match futures::future::select(future1, future2).await {
        Either::Left((_, _)) => {
            tracing::trace!("Received shutdown signal");
        }
        Either::Right((_, _)) => {
            tracing::trace!("Sending shutdown signal");
            // TODO: shutdown signal should be error
            let _ = shutdown_tx.send(Some(()));
        }
    };
}

pub async fn on_shutdown(shutdown_tx: ShutdownSender, future2: impl Future) {
    let mut shutdown_rx = shutdown_tx.subscribe();
    let future1 = shutdown_rx.recv().fuse();

    let _ = future1.await;
    future2.await;
}
