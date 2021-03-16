use crate::{error::JsonRpseeError, Error, PolkaBtcSigner};
use async_trait::async_trait;
use futures::{Future, FutureExt};
use jsonrpsee_ws_client::{WsClient, WsConfig};
use log::{info, trace};
use std::{marker::PhantomData, str::FromStr, sync::Arc, time::Duration};
use substrate_subxt::RpcClient;
use tokio::{
    runtime::Handle,
    time::{delay_for, timeout},
};

const RETRY_TIMEOUT: Duration = Duration::from_millis(1000);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

pub type ShutdownReceiver = tokio::sync::watch::Receiver<Option<()>>;

#[async_trait]
pub trait Provider {
    async fn connect<T>(rpc_client: T, signer: PolkaBtcSigner) -> Result<Self, Error>
    where
        Self: Sized,
        T: Into<RpcClient> + Send;
}

#[async_trait]
pub trait Service<C, P: Provider> {
    async fn start(provider: P, config: C, handle: Handle, shutdown: ShutdownReceiver) -> Result<(), Error>;
}

pub(crate) async fn new_websocket_client(
    url: &String,
    max_concurrent_requests: Option<usize>,
    max_notifs_per_subscription: Option<usize>,
) -> Result<WsClient, Error> {
    let parsed_url = url::Url::parse(&url)?;
    let path = parsed_url.path();
    let config = WsConfig {
        url,
        max_request_body_size: 10 * 1024 * 1024,
        request_timeout: None,
        connection_timeout: CONNECTION_TIMEOUT,
        origin: None,
        handshake_url: path.into(),
        max_concurrent_requests: max_concurrent_requests.unwrap_or(256),
        max_notifs_per_subscription: max_notifs_per_subscription.unwrap_or(128),
    };
    Ok(WsClient::new(config).await?)
}

pub(crate) async fn new_websocket_client_with_retry(
    url: &String,
    max_concurrent_requests: Option<usize>,
    max_notifs_per_subscription: Option<usize>,
    connection_timeout: Duration,
) -> Result<WsClient, Error> {
    info!("Connecting to the btc-parachain...");
    timeout(connection_timeout, async move {
        loop {
            match new_websocket_client(url, max_concurrent_requests, max_notifs_per_subscription).await {
                Err(Error::JsonRpseeError(JsonRpseeError::TransportError(err))) => {
                    trace!("could not connect to parachain: {}", err);
                    delay_for(RETRY_TIMEOUT).await;
                    continue;
                }
                Ok(rpc) => {
                    info!("Connected!");
                    return Ok(rpc);
                }
                Err(err) => return Err(err),
            }
        }
    })
    .await?
}

#[derive(Clone, Debug)]
pub enum RestartPolicy {
    Never,
    Always,
}

impl FromStr for RestartPolicy {
    type Err = String;
    fn from_str(code: &str) -> Result<Self, Self::Err> {
        match code {
            "never" => Ok(RestartPolicy::Never),
            "always" => Ok(RestartPolicy::Always),
            _ => Err("Could not parse input as RestartPolicy".to_string()),
        }
    }
}

/// Connection settings for the service
pub struct ManagerConfig {
    /// Fail to connect to server if elapsed
    pub connection_timeout: Duration,
    /// Whether to restart the client
    pub restart_policy: RestartPolicy,
    /// Maximum number of concurrent requests
    pub max_concurrent_requests: Option<usize>,
    /// Maximum notification capacity for each subscription
    pub max_notifs_per_subscription: Option<usize>,
}

pub struct Manager<C: Clone, P: Provider, S: Service<C, P>> {
    url: String,
    signer: PolkaBtcSigner,
    service_config: C,
    manager_config: ManagerConfig,
    handle: Handle,
    _marker: PhantomData<(P, S)>,
}

impl<C: Clone + Send + 'static, P: Provider + Send, S: Service<C, P>> Manager<C, P, S> {
    pub fn new(
        url: String,
        signer: PolkaBtcSigner,
        service_config: C,
        manager_config: ManagerConfig,
        handle: Handle,
    ) -> Self {
        Self {
            url,
            signer,
            service_config,
            manager_config,
            handle,
            _marker: PhantomData::default(),
        }
    }

    pub async fn start(&self) -> Result<(), Error> {
        loop {
            let ws_client = new_websocket_client_with_retry(
                &self.url,
                self.manager_config.max_concurrent_requests,
                self.manager_config.max_notifs_per_subscription,
                self.manager_config.connection_timeout,
            )
            .await?;
            let ws_client = Arc::new(ws_client);

            let signer = self.signer.clone();
            let config = self.service_config.clone();
            let handle = self.handle.clone();

            let (shutdown_sender, shutdown_receiver) = tokio::sync::watch::channel(None);
            let wait_for_shutdown = is_connected(ws_client.clone());

            // run service and shutdown listener to terminate child
            // processes if the websocket client disconnects
            let _ = tokio::join! {
                async move {
                    // TODO: propogate shutdown signal from children
                    wait_for_shutdown.await;
                    // signal shutdown to child processes
                    let _ = shutdown_sender.broadcast(Some(()));
                },
                async move {
                    let provider = P::connect(ws_client, signer).await?;
                    let _ = S::start(provider, config, handle, shutdown_receiver).await;
                    Ok::<(), Error>(())
                }
            };

            info!("Disconnected");

            match self.manager_config.restart_policy {
                RestartPolicy::Never => return Err(Error::ChannelClosed),
                RestartPolicy::Always => continue,
            };
        }
    }
}

async fn is_connected(client: Arc<WsClient>) {
    while client.is_connected() {
        delay_for(Duration::from_millis(500)).await;
    }
}

pub async fn wait_or_shutdown(mut shutdown: ShutdownReceiver, future2: impl Future) {
    let future1 = async move { while let Some(None) = shutdown.recv().await {} }.fuse();
    let future2 = future2.fuse();

    futures::pin_mut!(future1);
    futures::pin_mut!(future2);

    let _ = futures::select! {
        _ = future1 => (),
        _ = future2 => (),
    };
}

pub async fn on_shutdown(mut shutdown: ShutdownReceiver, future2: impl Future) {
    let future1 = async move { while let Some(None) = shutdown.recv().await {} }.fuse();

    future1.await;
    future2.await;
}
