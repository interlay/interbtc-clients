use crate::{error::JsonRpseeError, Error, PolkaBtcSigner};
use async_trait::async_trait;
use futures::Future;
use jsonrpsee_ws_client::{WsClient, WsConfig};
use log::{debug, trace};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use substrate_subxt::RpcClient;
use tokio::time::{delay_for, timeout};

const RETRY_DURATION: Duration = Duration::from_millis(1000);

#[async_trait]
pub trait Provider {
    async fn connect<T>(rpc_client: T, signer: Arc<PolkaBtcSigner>) -> Result<Self, Error>
    where
        Self: Sized,
        T: Into<RpcClient> + Send;
}

#[async_trait]
pub trait Service<C, P: Provider> {
    async fn connect(provider: P, config: C) -> Result<(), Error>;
}

pub struct Manager<C: Clone, P: Provider, S: Service<C, P>> {
    url: String,
    signer: Arc<PolkaBtcSigner>,
    config: C,
    _marker: PhantomData<(P, S)>,
}

pub(crate) async fn new_websocket_client(url: String) -> Result<(WsClient, impl Future), Error> {
    let parsed_url = url::Url::parse(&url)?;
    let path = parsed_url.path();
    let config = WsConfig {
        url: &url,
        max_request_body_size: 10 * 1024 * 1024,
        request_timeout: None,
        connection_timeout: Duration::from_secs(10),
        origin: None,
        handshake_url: path.into(),
        max_concurrent_requests: 256,
        max_notifs_per_subscription: 128,
    };
    Ok(WsClient::new_and_background(config).await?)
}

pub(crate) async fn new_websocket_client_with_retry(
    url: String,
    duration: Duration,
) -> Result<(WsClient, impl Future), Error> {
    debug!("Connecting to the btc-parachain...");
    timeout(duration, async move {
        loop {
            match new_websocket_client(url.clone()).await {
                Err(Error::JsonRpseeError(JsonRpseeError::TransportError(err))) => {
                    trace!("could not connect to parachain: {}", err);
                    delay_for(RETRY_DURATION).await;
                    continue;
                }
                Ok(rpc) => {
                    debug!("Connected!");
                    return Ok(rpc);
                }
                Err(err) => return Err(err),
            }
        }
    })
    .await?
}

impl<C: Clone, P: Provider, S: Service<C, P>> Manager<C, P, S> {
    pub fn new(url: String, signer: Arc<PolkaBtcSigner>, config: C) -> Self {
        Self {
            url,
            signer,
            config,
            _marker: PhantomData::default(),
        }
    }

    pub async fn start(&self) -> Result<(), Error> {
        loop {
            let (ws_client, background) =
                new_websocket_client_with_retry(self.url.clone(), Duration::from_secs(10)).await?;

            futures::future::select(
                Box::pin(background),
                Box::pin(async move {
                    let provider = P::connect(ws_client, self.signer.clone()).await?;
                    S::connect(provider, self.config.clone()).await?;
                    Ok::<(), Error>(())
                }),
            )
            .await;
        }
    }
}
