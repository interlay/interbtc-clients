use crate::execution::execute_open_requests;
use async_trait::async_trait;
use bitcoin::BitcoinCoreApi;
use log::*;
use runtime::{Error as RuntimeError, PolkaBtcProvider, Service};

#[derive(Clone)]
pub struct SystemServiceConfig<B> {
    /// the bitcoin RPC handle
    pub bitcoin_core: B,
    /// the number of bitcoin confirmation to await
    pub num_confirmations: u32,
}

pub struct SystemService<B> {
    btc_parachain: PolkaBtcProvider,
    bitcoin_core: B,
    num_confirmations: u32,
}

#[async_trait]
impl<B: BitcoinCoreApi + Clone + Send + Sync + 'static>
    Service<SystemServiceConfig<B>, PolkaBtcProvider> for SystemService<B>
{
    async fn connect(
        btc_parachain: PolkaBtcProvider,
        config: SystemServiceConfig<B>,
    ) -> Result<(), RuntimeError> {
        SystemService::new(btc_parachain, config)
            .run_service()
            .await
            .map_err(|_| RuntimeError::ChannelClosed)
    }
}

impl<B: BitcoinCoreApi + Clone + Send + Sync + 'static> SystemService<B> {
    fn new(btc_parachain: PolkaBtcProvider, config: SystemServiceConfig<B>) -> Self {
        Self {
            btc_parachain,
            bitcoin_core: config.bitcoin_core,
            num_confirmations: config.num_confirmations,
        }
    }

    async fn listen_for_error_events(&self) -> Result<(), RuntimeError> {
        self.btc_parachain
            .on_event_error(|e| debug!("Received error event: {}", e))
            .await
    }

    async fn run_service(&mut self) -> Result<(), RuntimeError> {
        let open_request_executor = execute_open_requests(
            self.btc_parachain.clone(),
            self.bitcoin_core.clone(),
            self.num_confirmations,
        );

        let _ = futures::future::join(
            Box::pin(async move {
                info!("Checking for open replace/redeem requests...");
                match open_request_executor.await {
                    Ok(_) => info!("Done processing open replace/redeem requests"),
                    Err(e) => error!("Failed to process open replace/redeem requests: {}", e),
                }
            }),
            Box::pin(self.listen_for_error_events()),
        )
        .await;
        Ok(())
    }
}
