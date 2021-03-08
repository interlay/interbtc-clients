use staked_relayer::relay::*;
use staked_relayer::service::*;
use staked_relayer::utils::*;
use staked_relayer::Error;
use staked_relayer::Vaults;

use bitcoin::{BitcoinCore, BitcoinCoreApi as _};
use clap::Clap;
use log::*;
use relayer_core::{Config, Runner};
use runtime::{
    pallets::sla::UpdateRelayerSLAEvent, substrate_subxt::PairSigner, StakedRelayerPallet,
    UtilFuncs, VaultRegistryPallet,
};
use runtime::{PolkaBtcProvider, PolkaBtcRuntime};
use std::sync::Arc;
use std::time::Duration;

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
    #[clap(long, default_value = "5000")]
    oracle_timeout_ms: u64,

    /// Default deposit for all automated status proposals.
    #[clap(long, default_value = "100")]
    status_update_deposit: u128,

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
    let oracle_timeout_ms = opts.oracle_timeout_ms;

    let dummy_network = bitcoin::Network::Regtest; // we don't make any transaction so this is not used
    let btc_rpc = Arc::new(
        BitcoinCore::new_with_retry(
            opts.bitcoin.new_client(None)?,
            dummy_network,
            Duration::from_millis(opts.connection_timeout_ms),
        )
        .await?,
    );

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);
    // only open connection to parachain after bitcoind sync to prevent timeout
    let provider = Arc::new(
        PolkaBtcProvider::from_url_with_retry(
            opts.polka_btc_url,
            signer,
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

    let relayer = Runner::new(
        BitcoinClient::new(opts.bitcoin.new_client(None)?),
        PolkaBtcClient::new(provider.clone()),
        Config {
            start_height: opts.bitcoin_relay_start_height,
            max_batch_size: opts.max_batch_size,
            timeout: Some(Duration::from_millis(bitcoin_timeout_ms)),
            required_btc_confirmations: opts.required_btc_confirmations,
        },
    );
    let relayer_provider = provider.clone();

    let oracle_monitor =
        report_offline_oracle(provider.clone(), Duration::from_millis(oracle_timeout_ms));

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
        .collect();
    // store vaults in Arc<RwLock>
    let vaults = Arc::new(Vaults::from(vaults));

    if let Ok(status_updates) = provider.get_all_status_updates().await {
        for (status_update_id, status_update) in status_updates {
            if let Err(err) =
                process_status_update(&btc_rpc, &provider, status_update_id, status_update).await
            {
                error!("Failed to process active status update: {}", err);
            }
        }
    }

    // scan from custom height or the current tip
    let bitcoin_theft_start_height = opts
        .bitcoin_theft_start_height
        .unwrap_or(btc_rpc.get_block_count().await? as u32 + 1);
    let vaults_monitor = report_vault_thefts(
        bitcoin_theft_start_height,
        btc_rpc.clone(),
        vaults.clone(),
        provider.clone(),
        Duration::from_millis(bitcoin_timeout_ms),
    );

    let wallet_update_listener = listen_for_wallet_updates(provider.clone(), vaults.clone());
    let vaults_listener = listen_for_vaults_registered(provider.clone(), vaults);
    let status_update_listener = listen_for_status_updates(btc_rpc.clone(), provider.clone());
    let relay_listener = listen_for_blocks_stored(
        btc_rpc.clone(),
        provider.clone(),
        opts.status_update_deposit,
    );

    let http_server = start_http(provider.clone(), http_addr, opts.rpc_cors_domain);

    let result = tokio::try_join!(
        tokio::spawn(async move {
            let relayer_id = provider.get_account_id();
            provider
                .on_event::<UpdateRelayerSLAEvent<PolkaBtcRuntime>, _, _, _>(
                    |event| async move {
                        if &event.relayer_id == relayer_id {
                            info!("Received event: new total SLA score = {:?}", event.new_sla);
                        }
                    },
                    |err| error!("Error (UpdateRelayerSLAEvent): {}", err.to_string()),
                )
                .await
                .unwrap();
        }),
        // runs json-rpc server for incoming requests
        tokio::spawn(async move { http_server.await }),
        // keep track of all registered vaults (i.e. keep the `vaults` map up-to-date)
        tokio::spawn(async move { vaults_listener.await.unwrap() }),
        // runs vault theft checks
        tokio::spawn(async move {
            vaults_monitor.await.unwrap();
        }),
        // keep vault wallets up-to-date
        tokio::spawn(async move {
            wallet_update_listener.await.unwrap();
        }),
        // runs oracle liveness check
        tokio::spawn(async move { oracle_monitor.await }),
        // runs `NO_DATA` checks and submits status updates
        tokio::spawn(async move {
            relay_listener.await.unwrap();
        }),
        // runs subscription service for status updates
        tokio::spawn(async move {
            status_update_listener.await.unwrap();
        }),
        // runs blocking relayer
        tokio::task::spawn_blocking(move || run_relayer(
            relayer,
            relayer_provider,
            Duration::from_secs(1)
        ))
    );
    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            error!("{:?}", err);
            Err(Error::InternalError)
        }
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
