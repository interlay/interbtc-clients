use crate::http;
use crate::Error;
use async_trait::async_trait;
use runtime::{on_shutdown, Error as RuntimeError, PolkaBtcProvider, Service, ShutdownReceiver};
use std::net::SocketAddr;

#[derive(Clone)]
pub struct FaucetServiceConfig {
    pub http_addr: SocketAddr,
    pub rpc_cors_domain: String,
    pub user_allowance: u128,
    pub vault_allowance: u128,
    pub staked_relayer_allowance: u128,
}

pub struct FaucetService {
    btc_parachain: PolkaBtcProvider,
    config: FaucetServiceConfig,
    handle: tokio::runtime::Handle,
    shutdown: ShutdownReceiver,
}

#[async_trait]
impl Service<FaucetServiceConfig, PolkaBtcProvider> for FaucetService {
    async fn start(
        btc_parachain: PolkaBtcProvider,
        config: FaucetServiceConfig,
        handle: tokio::runtime::Handle,
        shutdown: ShutdownReceiver,
    ) -> Result<(), RuntimeError> {
        FaucetService::new(btc_parachain, config, handle, shutdown)
            .run_service()
            .await
            .map_err(|_| RuntimeError::ChannelClosed)
    }
}

impl FaucetService {
    fn new(
        btc_parachain: PolkaBtcProvider,
        config: FaucetServiceConfig,
        handle: tokio::runtime::Handle,
        shutdown: ShutdownReceiver,
    ) -> Self {
        Self {
            btc_parachain,
            config,
            handle,
            shutdown,
        }
    }

    async fn run_service(&self) -> Result<(), Error> {
        let close_handle = http::start_http(
            self.btc_parachain.clone(),
            self.config.http_addr,
            self.config.rpc_cors_domain.clone(),
            self.config.user_allowance,
            self.config.vault_allowance,
            self.config.staked_relayer_allowance,
            self.handle.clone(),
        )
        .await;

        on_shutdown(self.shutdown.clone(), async move {
            close_handle.close();
        })
        .await;

        Ok(())
    }
}
