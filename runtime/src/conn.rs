use crate::{error::JsonRpseeError, Error};
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use std::time::Duration;
use tokio::time::{sleep, timeout};

const RETRY_TIMEOUT: Duration = Duration::from_millis(1000);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) async fn new_websocket_client(
    url: &str,
    max_concurrent_requests: Option<usize>,
    max_notifs_per_subscription: Option<usize>,
) -> Result<WsClient, Error> {
    let ws_client = WsClientBuilder::default()
        .connection_timeout(CONNECTION_TIMEOUT)
        .max_concurrent_requests(max_concurrent_requests.unwrap_or(1024))
        .max_notifs_per_subscription(max_notifs_per_subscription.unwrap_or(256))
        .build(url)
        .await?;
    Ok(ws_client)
}

pub(crate) async fn new_websocket_client_with_retry(
    url: &str,
    max_concurrent_requests: Option<usize>,
    max_notifs_per_subscription: Option<usize>,
    connection_timeout: Duration,
) -> Result<WsClient, Error> {
    log::info!("Connecting to the btc-parachain...");
    timeout(connection_timeout, async move {
        loop {
            match new_websocket_client(url, max_concurrent_requests, max_notifs_per_subscription).await {
                Err(Error::JsonRpseeError(JsonRpseeError::Transport(err))) => {
                    log::trace!("could not connect to parachain: {}", err);
                    sleep(RETRY_TIMEOUT).await;
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
