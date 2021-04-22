use crate::{relay::*, service::*, utils::*, Error, Vaults};
use async_trait::async_trait;
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use clap::Clap;
use futures::executor::block_on;
use git_version::git_version;
use runtime::{
    cli::parse_duration_ms, pallets::sla::UpdateRelayerSLAEvent, PolkaBtcProvider, PolkaBtcRuntime,
    StakedRelayerPallet, UtilFuncs, VaultRegistryPallet,
};
use service::{wait_or_shutdown, Error as ServiceError, Service, ShutdownSender};
use std::{sync::Arc, time::Duration};

pub const VERSION: &str = git_version!(args = ["--tags"]);
pub const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

#[derive(Clone, Clap)]
pub struct RelayerServiceConfig {
    /// Starting height for vault theft checks, if not defined
    /// automatically start from the chain tip.
    #[clap(long)]
    pub bitcoin_theft_start_height: Option<u32>,

    /// Timeout in milliseconds to poll Bitcoin.
    #[clap(long, parse(try_from_str = parse_duration_ms), default_value = "6000")]
    pub bitcoin_poll_timeout_ms: Duration,

    /// Starting height to relay block headers, if not defined
    /// use the best height as reported by the relay module.
    #[clap(long)]
    pub bitcoin_relay_start_height: Option<u32>,

    /// Max batch size for combined block header submission.
    #[clap(long, default_value = "16")]
    pub max_batch_size: u32,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    pub rpc_cors_domain: String,

    /// Automatically register the relayer with the given stake (in Planck).
    #[clap(long)]
    pub auto_register_with_stake: Option<u128>,

    /// Automatically register the staked relayer with collateral received from the faucet and a newly generated
    /// address. The parameter is the URL of the faucet
    #[clap(long, conflicts_with("auto-register-with-stake"))]
    pub auto_register_with_faucet_url: Option<String>,

    /// Number of confirmations a block needs to have before it is submitted.
    #[clap(long, default_value = "0")]
    pub required_btc_confirmations: u32,
}

pub struct RelayerService {
    btc_parachain: PolkaBtcProvider,
    bitcoin_core: BitcoinCore,
    config: RelayerServiceConfig,
    shutdown: ShutdownSender,
}

#[async_trait]
impl Service<RelayerServiceConfig> for RelayerService {
    const NAME: &'static str = NAME;
    const VERSION: &'static str = VERSION;

    fn new_service(
        btc_parachain: PolkaBtcProvider,
        bitcoin_core: BitcoinCore,
        config: RelayerServiceConfig,
        shutdown: ShutdownSender,
    ) -> Self {
        RelayerService::new(btc_parachain, bitcoin_core, config, shutdown)
    }

    async fn start(&self) -> Result<(), ServiceError> {
        match self.run_service().await {
            Ok(_) => Ok(()),
            Err(Error::RuntimeError(err)) => Err(ServiceError::RuntimeError(err)),
            Err(Error::BitcoinError(err)) => Err(ServiceError::BitcoinError(err)),
            Err(err) => Err(ServiceError::Other(err.to_string())),
        }
    }
}

impl RelayerService {
    fn new(
        btc_parachain: PolkaBtcProvider,
        bitcoin_core: BitcoinCore,
        config: RelayerServiceConfig,
        shutdown: ShutdownSender,
    ) -> Self {
        Self {
            btc_parachain,
            bitcoin_core,
            config,
            shutdown,
        }
    }

    async fn run_service(&self) -> Result<(), Error> {
        let bitcoin_core = self.bitcoin_core.clone();

        if let Some(stake) = self.config.auto_register_with_stake {
            if !is_registered(&self.btc_parachain).await? {
                self.btc_parachain.register_staked_relayer(stake).await?;
                tracing::info!("Automatically registered staked relayer");
            } else {
                tracing::info!("Not registering staked relayer -- already registered");
            }
        } else if let Some(faucet_url) = &self.config.auto_register_with_faucet_url {
            if !is_registered(&self.btc_parachain).await? {
                fund_and_register(&self.btc_parachain, faucet_url).await?;
                tracing::info!("Automatically registered staked relayer");
            } else {
                tracing::info!("Not registering staked relayer -- already registered");
            }
        }

        tracing::info!("Fetching all active vaults...");
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
                    .map(|addr| (*addr, vault.id.clone()))
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
                self.config.bitcoin_poll_timeout_ms,
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
                            tracing::info!("Received event: new total SLA score = {:?}", event.new_sla);
                        }
                    },
                    |err| tracing::error!("Error (UpdateRelayerSLAEvent): {}", err.to_string()),
                )
                .await?;
            Ok(())
        });

        let relayer = wait_or_shutdown(
            self.shutdown.clone(),
            run_relayer(
                Runner::new(
                    BitcoinClient::new(bitcoin_core.clone()),
                    PolkaBtcClient::new(self.btc_parachain.clone()),
                    Config {
                        start_height: self.config.bitcoin_relay_start_height,
                        max_batch_size: self.config.max_batch_size,
                        timeout: Some(self.config.bitcoin_poll_timeout_ms),
                        required_btc_confirmations: self.config.required_btc_confirmations,
                    },
                ),
                self.btc_parachain.clone(),
                Duration::from_secs(1),
            ),
        );

        tracing::info!("Starting system services...");
        let _ = tokio::join!(
            // keep track of all registered vaults (i.e. keep the `vaults` map up-to-date)
            tokio::spawn(async move { vaults_registration_listener.await }),
            // keep vault wallets up-to-date
            tokio::spawn(async move { wallet_update_listener.await }),
            // runs vault theft checks
            tokio::spawn(async move { vaults_listener.await }),
            // runs sla listener to log events
            tokio::spawn(async move { sla_listener.await }),
            // runs blocking relayer
            tokio::task::spawn_blocking(move || block_on(relayer))
        );

        Ok(())
    }
}
