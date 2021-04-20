use crate::{error::JsonRpseeError, Error};
use jsonrpsee_ws_client::{WsClient, WsConfig};
use std::time::Duration;
use tokio::time::{delay_for, timeout};

const RETRY_TIMEOUT: Duration = Duration::from_millis(1000);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn new_websocket_config(
    url: &str,
    max_concurrent_requests: Option<usize>,
    max_notifs_per_subscription: Option<usize>,
) -> Result<WsConfig, Error> {
    let parsed_url = url::Url::parse(&url)?;
    let path = parsed_url.path().to_string();
    Ok(WsConfig {
        url,
        max_request_body_size: 10 * 1024 * 1024,
        request_timeout: None,
        connection_timeout: CONNECTION_TIMEOUT,
        origin: None,
        handshake_url: path.into(),
        max_concurrent_requests: max_concurrent_requests.unwrap_or(1024),
        max_notifs_per_subscription: max_notifs_per_subscription.unwrap_or(256),
    })
}

pub(crate) async fn new_websocket_client(config: WsConfig<'_>) -> Result<WsClient, Error> {
    Ok(WsClient::new(config).await?)
}

pub(crate) async fn new_websocket_client_with_retry(
    config: WsConfig<'_>,
    connection_timeout: Duration,
) -> Result<WsClient, Error> {
    log::info!("Connecting to the btc-parachain...");
    timeout(connection_timeout, async move {
        loop {
            match new_websocket_client(config.clone()).await {
                Err(Error::JsonRpseeError(JsonRpseeError::TransportError(err))) => {
                    log::trace!("could not connect to parachain: {}", err);
                    delay_for(RETRY_TIMEOUT).await;
                    continue;
                }
                Ok(rpc) => {
                    log::info!("Connected!");
                    return Ok(rpc);
                }
                Err(err) => return Err(err),
            }
        }
    })
    .await?
}
