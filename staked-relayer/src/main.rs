use jsonrpc_http_server::jsonrpc_core::Value;
use staked_relayer::relay::{BitcoinClient, PolkaBtcClient};
use staked_relayer::service::*;
use staked_relayer::Error;
use staked_relayer::Vaults;

use bitcoin::{BitcoinCore, BitcoinCoreApi as _};
use clap::Clap;
use hex::FromHex;
use jsonrpc_core_client::{transports::http as jsonrpc_http, TypedClient};
use log::*;
use parity_scale_codec::{Decode, Encode};
use relayer_core::{Config, Runner};
use runtime::pallets::sla::UpdateRelayerSLAEvent;
use runtime::{substrate_subxt::PairSigner, AccountId, StakedRelayerPallet, UtilFuncs};
use runtime::{PolkaBtcProvider, PolkaBtcRuntime, DOT_TO_PLANCK, TX_FEES};
use serde::{Deserialize, Deserializer};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawBytes(#[serde(deserialize_with = "hex_to_buffer")] pub(crate) Vec<u8>);

pub fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        Vec::from_hex(&string[2..]).map_err(|err| Error::custom(err.to_string()))
    })
}

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
    scan_start_height: Option<u32>,

    /// Delay for checking Bitcoin for new blocks (in seconds).
    #[clap(long, default_value = "60")]
    scan_block_delay: u64,

    /// Starting height to relay block headers, if not defined
    /// use the best height as reported by the relay module.
    #[clap(long)]
    relay_start_height: Option<u32>,

    /// Max batch size for combined block header submission.
    #[clap(long, default_value = "16")]
    max_batch_size: u32,

    /// Timeout in milliseconds to repeat oracle liveness check.
    #[clap(long, default_value = "5000")]
    oracle_timeout_ms: u64,

    /// Timeout in milliseconds to repeat oracle liveness check.
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

    /// Automatically register the staked relayer with collateral received from the faucet and a newly generated address.
    /// The parameter is the URL of the faucet
    #[clap(long)]
    auto_register_with_faucet_url: Option<String>,
}

#[derive(Encode, Decode, Debug, Clone, serde::Serialize)]
struct FundAccountJsonRpcRequest {
    pub account_id: AccountId,
}

async fn get_funding(
    faucet_connection: TypedClient,
    staked_relayer_id: AccountId,
) -> Result<(), Error> {
    let funding_request = FundAccountJsonRpcRequest {
        account_id: staked_relayer_id,
    };
    let eq = format!("0x{}", hex::encode(funding_request.encode()));
    faucet_connection
        .call_method::<Vec<String>, Value>("fund_account", "", vec![eq.clone()])
        .await?;
    Ok(())
}

async fn get_faucet_allowance(
    faucet_connection: TypedClient,
    allowance_type: &str,
) -> Result<u128, Error> {
    let raw_allowance = faucet_connection
        .call_method::<(), RawBytes>(&allowance_type, "", ())
        .await?;
    Ok(Decode::decode(&mut &raw_allowance.0[..])?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let http_addr = opts.http_addr.parse()?;
    let oracle_timeout_ms = opts.oracle_timeout_ms;

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);
    let provider = Arc::new(PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?);

    let dummy_network = bitcoin::Network::Regtest; // we don't make any transaction so this is not used
    let btc_rpc = Arc::new(BitcoinCore::new(
        opts.bitcoin.new_client(None)?,
        dummy_network,
    ));

    let current_height = btc_rpc.get_block_count().await? as u32;

    let mut relayer = Runner::new(
        PolkaBtcClient::new(provider.clone()),
        BitcoinClient::new(opts.bitcoin.new_client(None)?),
        Config {
            start_height: opts.relay_start_height.unwrap_or(current_height),
            max_batch_size: opts.max_batch_size,
        },
    )?;

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
    let scan_start_height = opts.scan_start_height.unwrap_or(current_height + 1);
    let vaults_monitor = report_vault_thefts(
        scan_start_height,
        btc_rpc.clone(),
        vaults.clone(),
        provider.clone(),
        Duration::from_secs(opts.scan_block_delay),
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
        get_funding(
            connection.clone(),
            provider.clone().get_account_id().clone(),
        )
        .await?;
        let user_allowance_in_dot: u128 =
            get_faucet_allowance(connection.clone(), "user_allowance").await?;
        let registration_stake = user_allowance_in_dot
            .checked_mul(DOT_TO_PLANCK)
            .ok_or(Error::MathError)?
            .checked_sub(TX_FEES)
            .ok_or(Error::MathError)?;
        provider.register_staked_relayer(registration_stake).await?;

        // Receive staked relayer allowance from faucet
        get_funding(
            connection.clone(),
            provider.clone().get_account_id().clone(),
        )
        .await?;
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
        tokio::task::spawn_blocking(move || relayer.run().unwrap())
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
