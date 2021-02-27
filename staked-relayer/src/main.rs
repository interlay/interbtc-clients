use staked_relayer::relay::*;
use staked_relayer::service::*;
use staked_relayer::utils::*;
use staked_relayer::Error;
use staked_relayer::Vaults;

use bitcoin::{BitcoinCore, BitcoinCoreApi as _};
use clap::Clap;
use jsonrpc_core_client::{transports::http as jsonrpc_http, TypedClient};
use log::*;
use relayer_core::{Config, Runner};
use runtime::pallets::sla::UpdateRelayerSLAEvent;
use runtime::{substrate_subxt::PairSigner, StakedRelayerPallet, UtilFuncs};
use runtime::{PolkaBtcProvider, PolkaBtcRuntime, PLANCK_PER_DOT, TX_FEES};
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
    #[clap(long, conflicts_with("auto-register-with-faucet-url"))]
    pub auto_register_with_stake: Option<u128>,

    /// Automatically register the staked relayer with collateral received from the faucet and a newly generated address.
    /// The parameter is the URL of the faucet
    #[clap(long)]
    auto_register_with_faucet_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let http_addr = opts.http_addr.parse()?;
    let bitcoin_timeout_ms = opts.bitcoin_timeout_ms;
    let oracle_timeout_ms = opts.oracle_timeout_ms;

    let dummy_network = bitcoin::Network::Regtest; // we don't make any transaction so this is not used
    let btc_rpc = Arc::new(BitcoinCore::new(
        opts.bitcoin.new_client(None)?,
        dummy_network,
    ));

    info!("Waiting for bitcoin core to sync");
    btc_rpc
        .wait_for_block_sync(Duration::from_millis(bitcoin_timeout_ms))
        .await?;

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);
    // only open connection to parachain after bitcoind sync to prevent timeout
    let provider = Arc::new(PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?);

    if let Some(stake) = opts.auto_register_with_stake {
        if !is_registered(&provider).await? {
            provider.register_staked_relayer(stake).await?;
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

    let api = start_api(provider.clone(), http_addr, opts.rpc_cors_domain);

    if let Some(faucet_url) = opts.auto_register_with_faucet_url {
        let connection = jsonrpc_http::connect::<TypedClient>(&faucet_url).await?;

        // Receive user allowance from faucet
        match get_funding(
            connection.clone(),
            provider.clone().get_account_id().clone(),
        )
        .await
        {
            Ok(_) => {
                let user_allowance_in_dot: u128 =
                    get_faucet_allowance(connection.clone(), "user_allowance").await?;
                let registration_stake = user_allowance_in_dot
                    .checked_mul(PLANCK_PER_DOT)
                    .ok_or(Error::MathError)?
                    .checked_sub(TX_FEES)
                    .ok_or(Error::MathError)?;
                if !is_registered(&provider).await? {
                    provider.register_staked_relayer(registration_stake).await?;
                }
            }
            Err(e) => error!("Faucet error: {}", e.to_string()),
        }

        // Receive staked relayer allowance from faucet
        if let Err(e) = get_funding(
            connection.clone(),
            provider.clone().get_account_id().clone(),
        )
        .await
        {
            error!("Faucet error: {}", e.to_string())
        };
    }

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
        tokio::spawn(async move { api.await }),
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
        Ok(res) => {
            println!("{:?}", res);
        }
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    };
    Ok(())
}
