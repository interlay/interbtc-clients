use crate::{http, Error};
use async_trait::async_trait;
use clap::Clap;
use futures::future;
use log::debug;
use runtime::{Error as RuntimeError, PolkaBtcProvider};
use service::{on_shutdown, wait_or_shutdown, Service, ShutdownSender};
use std::net::SocketAddr;

#[derive(Clap, Clone)]
pub struct FaucetServiceConfig {
    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::0]:3033")]
    http_addr: SocketAddr,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    rpc_cors_domain: String,

    /// DOT allowance per request for regular users.
    #[clap(long, default_value = "1")]
    user_allowance: u128,

    /// DOT allowance per request for vaults.
    #[clap(long, default_value = "500")]
    vault_allowance: u128,

    /// DOT allowance per request for vaults.
    #[clap(long, default_value = "500")]
    staked_relayer_allowance: u128,
}

pub struct FaucetService {
    btc_parachain: PolkaBtcProvider,
    config: FaucetServiceConfig,
    shutdown: ShutdownSender,
}

#[async_trait]
impl Service<(), FaucetServiceConfig> for FaucetService {
    const NAME: &'static str = env!("CARGO_PKG_NAME");
    const VERSION: &'static str = env!("CARGO_PKG_VERSION");

    fn new_service(
        btc_parachain: PolkaBtcProvider,
        _bitcoin_core: (),
        config: FaucetServiceConfig,
        shutdown: ShutdownSender,
    ) -> Self {
        FaucetService::new(btc_parachain, config, shutdown)
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
    fn new(btc_parachain: PolkaBtcProvider, config: FaucetServiceConfig, shutdown: ShutdownSender) -> Self {
        Self {
            btc_parachain,
            config,
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

        log::info!("Running...");
        let _ = future::join(block_listener, http_server).await;

        Ok(())
    }
}
