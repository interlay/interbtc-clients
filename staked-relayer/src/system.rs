use crate::{relay::*, service::*, utils::*, Error, Vaults};
use async_trait::async_trait;
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use futures::executor::block_on;
use log::*;
use runtime::{
    pallets::sla::UpdateRelayerSLAEvent, wait_or_shutdown, Error as RuntimeError, PolkaBtcProvider, PolkaBtcRuntime,
    Service, ShutdownSender, StakedRelayerPallet, UtilFuncs, VaultRegistryPallet,
};
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct RelayerServiceConfig {
    /// the bitcoin RPC handle
    pub bitcoin_core: BitcoinCore,
    pub auto_register_with_stake: Option<u128>,
    pub auto_register_with_faucet_url: Option<String>,
    pub bitcoin_theft_start_height: Option<u32>,
    pub bitcoin_relay_start_height: Option<u32>,
    pub max_batch_size: u32,
    pub bitcoin_timeout: Duration,
    pub oracle_timeout: Duration,
    pub required_btc_confirmations: u32,
    pub status_update_deposit: u128,
    pub rpc_cors_domain: String,
}

pub struct RelayerService {
    btc_parachain: PolkaBtcProvider,
    config: RelayerServiceConfig,
    shutdown: ShutdownSender,
}

#[async_trait]
impl Service<RelayerServiceConfig, PolkaBtcProvider> for RelayerService {
    async fn initialize(config: &RelayerServiceConfig) -> Result<(), RuntimeError> {
        Self::connect_bitcoin(&config.bitcoin_core)
            .await
            .map_err(|err| RuntimeError::Other(err.to_string()))
    }

    fn new_service(btc_parachain: PolkaBtcProvider, config: RelayerServiceConfig, shutdown: ShutdownSender) -> Self {
        RelayerService::new(btc_parachain, config, shutdown)
    }

    async fn start(&self) -> Result<(), RuntimeError> {
        match self.run_service().await {
            Ok(_) => Ok(()),
            Err(Error::RuntimeError(err)) => Err(err),
            Err(err) => Err(RuntimeError::Other(err.to_string())),
        }
    }
}

impl RelayerService {
    async fn connect_bitcoin(bitcoin_core: &BitcoinCore) -> Result<(), Error> {
        bitcoin_core.connect().await?;
        bitcoin_core.sync().await?;
        Ok(())
    }

    fn new(btc_parachain: PolkaBtcProvider, config: RelayerServiceConfig, shutdown: ShutdownSender) -> Self {
        Self {
            btc_parachain,
            config,
            shutdown,
        }
    }

    async fn run_service(&self) -> Result<(), Error> {
        let bitcoin_core = self.config.bitcoin_core.clone();

        if let Some(stake) = self.config.auto_register_with_stake {
            if !is_registered(&self.btc_parachain).await? {
                self.btc_parachain.register_staked_relayer(stake).await?;
                info!("Automatically registered staked relayer");
            } else {
                info!("Not registering staked relayer -- already registered");
            }
        } else if let Some(faucet_url) = &self.config.auto_register_with_faucet_url {
            if !is_registered(&self.btc_parachain).await? {
                fund_and_register(&self.btc_parachain, faucet_url).await?;
                info!("Automatically registered staked relayer");
            } else {
                info!("Not registering staked relayer -- already registered");
            }
        }

        info!("Fetching all active vaults...");
        let vaults = self
            .btc_parachain
            .get_all_vaults()
            .await?
            .into_iter()
            .flat_map(|vault| {
                vault
                    .wallet
                    .addresses
                    .iter()
                    .map(|addr| (addr.clone(), vault.id.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();

        // store vaults in Arc<RwLock>
        let vaults = Arc::new(Vaults::from(vaults));

        // scan from custom height or the current tip
        let bitcoin_theft_start_height = self
            .config
            .bitcoin_theft_start_height
            .unwrap_or(bitcoin_core.get_block_count().await? as u32 + 1);

        let vaults_listener = wait_or_shutdown(
            self.shutdown.clone(),
            report_vault_thefts(
                bitcoin_core.clone(),
                self.btc_parachain.clone(),
                bitcoin_theft_start_height,
                vaults.clone(),
                self.config.bitcoin_timeout,
            ),
        );

        let vaults_registration_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_vaults_registered(self.btc_parachain.clone(), vaults.clone()),
        );

        let wallet_update_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_wallet_updates(self.btc_parachain.clone(), vaults.clone()),
        );

        let sla_provider = self.btc_parachain.clone();
        let sla_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            let relayer_id = sla_provider.get_account_id();
            sla_provider
                .on_event::<UpdateRelayerSLAEvent<PolkaBtcRuntime>, _, _, _>(
                    |event| async move {
                        if &event.relayer_id == relayer_id {
                            info!("Received event: new total SLA score = {:?}", event.new_sla);
                        }
                    },
                    |err| error!("Error (UpdateRelayerSLAEvent): {}", err.to_string()),
                )
                .await
        });

        let status_update_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_status_updates(bitcoin_core.clone(), self.btc_parachain.clone()),
        );

        let relay_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_blocks_stored(
                bitcoin_core.clone(),
                self.btc_parachain.clone(),
                self.config.status_update_deposit,
            ),
        );

        let relayer = wait_or_shutdown(
            self.shutdown.clone(),
            run_relayer(
                Runner::new(
                    BitcoinClient::new(bitcoin_core.clone()),
                    PolkaBtcClient::new(self.btc_parachain.clone()),
                    Config {
                        start_height: self.config.bitcoin_relay_start_height,
                        max_batch_size: self.config.max_batch_size,
                        timeout: Some(self.config.bitcoin_timeout),
                        required_btc_confirmations: self.config.required_btc_confirmations,
                    },
                ),
                self.btc_parachain.clone(),
                Duration::from_secs(1),
            ),
        );

        let oracle_listener = wait_or_shutdown(
            self.shutdown.clone(),
            report_offline_oracle(self.btc_parachain.clone(), self.config.oracle_timeout),
        );

        info!("Starting system services...");
        let _ = tokio::join!(
            // keep track of all registered vaults (i.e. keep the `vaults` map up-to-date)
            tokio::spawn(async move { vaults_registration_listener.await }),
            // keep vault wallets up-to-date
            tokio::spawn(async move { wallet_update_listener.await }),
            // runs vault theft checks
            tokio::spawn(async move { vaults_listener.await }),
            // runs sla listener to log events
            tokio::spawn(async move { sla_listener.await }),
            // runs oracle liveness check
            tokio::spawn(async move { oracle_listener.await }),
            // runs `NO_DATA` checks and submits status updates
            tokio::spawn(async move { relay_listener.await }),
            // runs subscription service for status updates
            tokio::spawn(async move { status_update_listener.await }),
            // runs blocking relayer
            tokio::task::spawn_blocking(move || block_on(relayer))
        );

        Ok(())
    }
}
