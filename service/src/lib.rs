use async_trait::async_trait;
use bitcoin::{cli::BitcoinOpts as BitcoinConfig, BitcoinCore, Error as BitcoinError};
use futures::{future::Either, Future, FutureExt};
use runtime::{
    cli::ConnectionOpts as ParachainConfig, CurrencyId, CurrencyIdExt, CurrencyInfo, Error as RuntimeError,
    InterBtcParachain as BtcParachain, InterBtcSigner, Signer, Ss58Codec, VaultId,
};
use std::marker::PhantomData;

mod cli;
mod error;
mod trace;

pub use cli::{LoggingFormat, RestartPolicy, ServiceConfig};
pub use error::Error;
pub use trace::init_subscriber;

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
        tracing::info!("AccountId: {}", self.signer.account_id().to_ss58check());

        loop {
            let config = self.config.clone();
            let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);

            let bitcoin_core = self.bitcoin_config.new_client(None).await?;
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
            let network_copy = bitcoin_core.network();
            let prefix = self.wallet_name.clone().unwrap_or_else(|| "vault".to_string());
            let constructor = move |vault_id: VaultId| {
                let collateral_currency: CurrencyId = vault_id.collateral_currency();
                let wrapped_currency: CurrencyId = vault_id.wrapped_currency();
                // convert to the native type
                let wallet_name = format!(
                    "{}-{}-{}",
                    prefix,
                    collateral_currency.inner().symbol(),
                    wrapped_currency.inner().symbol()
                );
                config_copy.new_client_with_network(Some(wallet_name), network_copy)
            };

            let service = S::new_service(btc_parachain, bitcoin_core, config, shutdown_tx, Box::new(constructor));
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
                RestartPolicy::Always => continue,
            };
        }
    }
}

pub async fn wait_or_shutdown<F>(name: &str, shutdown_tx: ShutdownSender, future2: F)
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
        Either::Right((ret, _)) => {
            tracing::info!(
                "Sending shutdown signal to all tasks because service {} returned {:?}.",
                name,
                ret
            );
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
