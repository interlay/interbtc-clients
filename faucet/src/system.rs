use crate::{http, Error};
use async_trait::async_trait;
use futures::future;
use log::debug;
use runtime::{on_shutdown, wait_or_shutdown, Error as RuntimeError, PolkaBtcProvider, Service, ShutdownSender};
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
    shutdown: ShutdownSender,
}

#[async_trait]
impl Service<FaucetServiceConfig, PolkaBtcProvider> for FaucetService {
    fn new_service(
        btc_parachain: PolkaBtcProvider,
        config: FaucetServiceConfig,
        handle: tokio::runtime::Handle,
        shutdown: ShutdownSender,
    ) -> Self {
        FaucetService::new(btc_parachain, config, handle, shutdown)
    }

    async fn start(&self) -> Result<(), RuntimeError> {
        match self.run_service().await {
            Ok(_) => Ok(()),
            Err(Error::RuntimeError(err)) => Err(err),
            Err(err) => Err(RuntimeError::Other(err.to_string())),
        }
    }
}

impl FaucetService {
    fn new(
        btc_parachain: PolkaBtcProvider,
        config: FaucetServiceConfig,
        handle: tokio::runtime::Handle,
        shutdown: ShutdownSender,
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

        let provider = self.btc_parachain.clone();
        // run block listener to restart faucet on disconnect
        let block_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            provider
                .on_block(move |header| async move {
                    debug!("Got block {:?}", header);
                    Ok(())
                })
                .await
        });

        let http_server = on_shutdown(self.shutdown.clone(), async move {
            close_handle.close();
        });

        let _ = future::join(block_listener, http_server).await;

        Ok(())
    }
}
