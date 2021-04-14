use async_trait::async_trait;
use bitcoin::BitcoinCore;
use futures::{future::Either, Future, FutureExt};
use runtime::{cli::ConnectionOpts as ParachainConfig, Error, PolkaBtcProvider as BtcParachain, PolkaBtcSigner};
use std::marker::PhantomData;

mod cli;

pub use cli::RestartPolicy;

pub type ShutdownSender = tokio::sync::broadcast::Sender<Option<()>>;

#[async_trait]
pub trait Service<Bitcoin: Sync, Config> {
    async fn initialize(_: &Bitcoin) -> Result<(), Error> {
        Ok(())
    }
    fn new_service(btc_parachain: BtcParachain, bitcoin: Bitcoin, config: Config, shutdown: ShutdownSender) -> Self;
    async fn start(&self) -> Result<(), Error>;
}

pub struct ConnectionManager<Bitcoin: Sync, Config: Clone, S: Service<Bitcoin, Config>> {
    signer: PolkaBtcSigner,
    bitcoin: Bitcoin,
    parachain_config: ParachainConfig,
    service_config: Config,
    restart_policy: RestartPolicy,
    _marker: PhantomData<S>,
}

impl<Config: Clone + Send + 'static, S: Service<BitcoinCore, Config>> ConnectionManager<BitcoinCore, Config, S> {
    pub fn new(
        signer: PolkaBtcSigner,
        bitcoin: BitcoinCore,
        parachain_config: ParachainConfig,
        service_config: Config,
        restart_policy: RestartPolicy,
    ) -> Self {
        Self {
            signer,
            bitcoin,
            parachain_config,
            service_config,
            restart_policy,
            _marker: PhantomData::default(),
        }
    }
}

impl<Config: Clone + Send + 'static, S: Service<(), Config>> ConnectionManager<(), Config, S> {
    pub fn new(
        signer: PolkaBtcSigner,
        parachain_config: ParachainConfig,
        service_config: Config,
        restart_policy: RestartPolicy,
    ) -> Self {
        Self {
            signer,
            bitcoin: (),
            parachain_config,
            service_config,
            restart_policy,
            _marker: PhantomData::default(),
        }
    }
}

impl<Bitcoin: Clone + Sync, Config: Clone + Send + 'static, S: Service<Bitcoin, Config>>
    ConnectionManager<Bitcoin, Config, S>
{
    pub async fn start(&self) -> Result<(), Error> {
        loop {
            let config = self.service_config.clone();
            let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);

            let bitcoin_core = &self.bitcoin;
            S::initialize(bitcoin_core).await?;

            // only open connection to parachain after bitcoind sync to prevent timeout
            let signer = self.signer.clone();
            let btc_parachain = BtcParachain::from_url_and_config_with_retry(
                &self.parachain_config.polka_btc_url,
                signer,
                self.parachain_config.max_concurrent_requests,
                self.parachain_config.max_notifs_per_subscription,
                self.parachain_config.polka_btc_connection_timeout_ms,
            )
            .await?;

            let service = S::new_service(btc_parachain, bitcoin_core.clone(), config, shutdown_tx);
            service.start().await?;

            log::info!("Disconnected");
            match self.restart_policy {
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
            log::trace!("Received shutdown signal");
        }
        Either::Right((_, _)) => {
            log::trace!("Sending shutdown signal");
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
