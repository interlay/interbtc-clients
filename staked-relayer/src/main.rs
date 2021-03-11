use staked_relayer::relay::*;
use staked_relayer::service::*;
use staked_relayer::utils::*;
use staked_relayer::Error;
use staked_relayer::Vaults;

use bitcoin::{BitcoinCore, BitcoinCoreApi as _};
use clap::Clap;
use futures::executor::block_on;
use log::*;
use runtime::{
    substrate_subxt::PairSigner, AccountId, BtcAddress, PolkaBtcSigner, StakedRelayerPallet,
};
use runtime::{PolkaBtcProvider, PolkaBtcRuntime, VaultRegistryPallet};
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

/// The Staked Relayer client intermediates between Bitcoin Core
/// and the PolkaBTC Parachain.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::0]:3030")]
    http_addr: String,

    /// Starting height for vault theft checks, if not defined
    /// automatically start from the chain tip.
    #[clap(long)]
    bitcoin_theft_start_height: Option<u32>,

    /// Timeout in milliseconds to poll Bitcoin.
    #[clap(long, default_value = "6000")]
    bitcoin_timeout_ms: u64,

    /// Starting height to relay block headers, if not defined
    /// use the best height as reported by the relay module.
    #[clap(long)]
    bitcoin_relay_start_height: Option<u32>,

    /// Max batch size for combined block header submission.
    #[clap(long, default_value = "16")]
    max_batch_size: u32,

    /// Timeout in milliseconds to repeat oracle liveness check.
    #[clap(long, default_value = "10000")]
    oracle_timeout_ms: u64,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    rpc_cors_domain: String,

    /// keyring / keyfile options.
    #[clap(flatten)]
    account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    bitcoin: bitcoin::cli::BitcoinOpts,

    /// Automatically register the relayer with the given stake (in Planck).
    #[clap(long)]
    pub auto_register_with_stake: Option<u128>,

    /// Automatically register the staked relayer with collateral received from the faucet and a newly generated address.
    /// The parameter is the URL of the faucet
    #[clap(long, conflicts_with("auto-register-with-stake"))]
    auto_register_with_faucet_url: Option<String>,

    /// Number of confirmations a block needs to have before it is submitted.
    #[clap(long, default_value = "0")]
    required_btc_confirmations: u32,

    /// Timeout in milliseconds to wait for connection to btc-parachain.
    #[clap(long, default_value = "60000")]
    connection_timeout_ms: u64,
}

async fn start() -> Result<(), Error> {
    env_logger::init_from_env(env_logger::Env::default().filter_or(
        env_logger::DEFAULT_FILTER_ENV,
        log::LevelFilter::Info.as_str(),
    ));
    let opts: Opts = Opts::parse();
    let http_addr = opts.http_addr.parse()?;
    let bitcoin_timeout_ms = opts.bitcoin_timeout_ms;

    let dummy_network = bitcoin::Network::Regtest; // we don't make any transaction so this is not used
    let btc_rpc = BitcoinCore::new_with_retry(
        Arc::new(opts.bitcoin.new_client(None)?),
        dummy_network,
        Duration::from_millis(opts.connection_timeout_ms),
    )
    .await?;

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);
    let signer = Arc::new(PolkaBtcSigner::from(signer));

    // only open connection to parachain after bitcoind sync to prevent timeout
    let provider = Arc::new(
        PolkaBtcProvider::from_url_with_retry(
            opts.polka_btc_url.clone(),
            signer.clone(),
            Duration::from_millis(opts.connection_timeout_ms),
        )
        .await?,
    );

    if let Some(stake) = opts.auto_register_with_stake {
        if !is_registered(&provider).await? {
            provider.register_staked_relayer(stake).await?;
            info!("Automatically registered staked relayer");
        } else {
            info!("Not registering staked relayer -- already registered");
        }
    } else if let Some(faucet_url) = opts.auto_register_with_faucet_url {
        if !is_registered(&provider).await? {
            fund_and_register(&provider, faucet_url).await?;
            info!("Automatically registered staked relayer");
        } else {
            info!("Not registering staked relayer -- already registered");
        }
    }

    let relayer_runner = runtime::conn::Manager::<_, _, RelayerService>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        RelayerServiceConfig {
            bitcoin_core: Arc::new(opts.bitcoin.new_client(None)?),
            bitcoin_relay_start_height: opts.bitcoin_relay_start_height,
            max_batch_size: opts.max_batch_size,
            required_btc_confirmations: opts.required_btc_confirmations,
            bitcoin_timeout: Duration::from_millis(bitcoin_timeout_ms),
            parachain_timeout: Duration::from_secs(1),
        },
    );

    // TODO: if disconnect, we need to refresh this
    let vaults = provider
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
        .collect::<HashMap<BtcAddress, AccountId>>();

    // store vaults in Arc<RwLock>
    let vaults = Arc::new(Vaults::from(vaults));
    // scan from custom height or the current tip
    let bitcoin_theft_start_height = opts
        .bitcoin_theft_start_height
        .unwrap_or(btc_rpc.get_block_count().await? as u32 + 1);

    let oracle_listener = runtime::conn::Manager::<_, _, OracleService<_>>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        OracleServiceConfig {
            timeout: Duration::from_millis(opts.oracle_timeout_ms),
        },
    );

    let vault_theft_listener = runtime::conn::Manager::<_, _, VaultTheftService<_, _>>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        VaultTheftServiceConfig::<_> {
            btc_height: bitcoin_theft_start_height,
            timeout: Duration::from_millis(opts.bitcoin_timeout_ms),
            bitcoin_core: btc_rpc.clone(),
            vaults: vaults.clone(),
        },
    );

    let vault_wallet_update_listener = runtime::conn::Manager::<_, _, VaultUpdateService>::new(
        opts.polka_btc_url.clone(),
        signer.clone(),
        VaultUpdateServiceConfig { vaults },
    );

    let sla_update_listener =
        runtime::conn::Manager::<_, _, SlaUpdateService>::new(opts.polka_btc_url, signer, ());

    let http_server = start_http(provider.clone(), http_addr, opts.rpc_cors_domain);

    let result = tokio::try_join!(
        // runs json-rpc server for incoming requests
        tokio::spawn(async move { http_server.await }),
        // listen for and report sla updates
        tokio::spawn(async move { sla_update_listener.start().await.unwrap() }),
        // keep track of all registered vaults (i.e. keep the `vaults` map up-to-date)
        tokio::spawn(async move { vault_wallet_update_listener.start().await.unwrap() }),
        // runs vault theft checks
        tokio::spawn(async move {
            vault_theft_listener.start().await.unwrap();
        }),
        // runs oracle liveness check
        tokio::spawn(async move { oracle_listener.start().await }),
        // runs blocking relayer
        tokio::task::spawn_blocking(move || block_on(relayer_runner.start()).unwrap())
    );
    match result {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::InternalError),
    }
}

#[tokio::main]
async fn main() {
    let exit_code = if let Err(err) = start().await {
        eprintln!("Error: {}", err);
        1
    } else {
        0
    };
    std::process::exit(exit_code);
}
