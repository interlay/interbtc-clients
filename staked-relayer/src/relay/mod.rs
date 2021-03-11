mod backing;
mod error;
mod issuing;

pub use error::Error;

pub use backing::Client as BitcoinClient;

pub use issuing::Client as PolkaBtcClient;

use crate::core::{Config, Runner};
use async_trait::async_trait;
use backing::RPC;
use log::error;
use runtime::{Error as RuntimeError, PolkaBtcProvider, Service};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct RelayerServiceConfig {
    pub bitcoin_core: Arc<RPC>,
    pub bitcoin_relay_start_height: Option<u32>,
    pub max_batch_size: u32,
    pub required_btc_confirmations: u32,
    pub bitcoin_timeout: Duration,
    pub parachain_timeout: Duration,
}

pub struct RelayerService {
    btc_parachain: Arc<PolkaBtcProvider>,
    runner: Runner<Error, BitcoinClient, PolkaBtcClient>,
    timeout: Duration,
}

#[async_trait]
impl Service<RelayerServiceConfig, PolkaBtcProvider> for RelayerService {
    async fn connect(
        btc_parachain: PolkaBtcProvider,
        config: RelayerServiceConfig,
    ) -> Result<(), RuntimeError> {
        RelayerService::new(btc_parachain, config)
            .run_service()
            .await
            .map_err(|_| RuntimeError::ChannelClosed)
    }
}

impl RelayerService {
    pub fn new(btc_parachain: PolkaBtcProvider, config: RelayerServiceConfig) -> Self {
        let btc_parachain = Arc::new(btc_parachain);
        Self {
            btc_parachain: btc_parachain.clone(),
            runner: Runner::new(
                BitcoinClient::new(config.bitcoin_core),
                PolkaBtcClient::new(btc_parachain),
                Config {
                    start_height: config.bitcoin_relay_start_height,
                    max_batch_size: config.max_batch_size,
                    timeout: Some(config.bitcoin_timeout),
                    required_btc_confirmations: config.required_btc_confirmations,
                },
            ),
            timeout: config.parachain_timeout,
        }
    }

    pub async fn run_service(&self) -> Result<(), Error> {
        loop {
            super::utils::wait_until_registered(&self.btc_parachain, self.timeout).await;
            if let Err(err) = self.runner.submit_next().await {
                error!("Failed to submit_next: {}", err);
            }
        }
    }
}
