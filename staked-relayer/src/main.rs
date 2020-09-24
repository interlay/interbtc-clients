mod bitcoin;
mod error;
mod http;
mod oracle;
mod relay;
mod utils;

use clap::Clap;
use error::Error;
use futures::stream::iter;
use futures::stream::StreamExt;
use log::{error, info};
use oracle::Oracle;
use relay::Client as PolkaClient;
use relay::Error as RelayError;
use relayer_core::bitcoin::Client as BtcClient;
use relayer_core::{Backing, Config, Runner};
use runtime::{
    AccountId, H256Le, PolkaBtcProvider, PolkaBtcRuntime, PolkaBtcVault, StakedRelayerPallet,
};
use sp_core::H160;
use sp_keyring::AccountKeyring;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use substrate_subxt::PairSigner;
use tokio::sync::RwLock;

/// The Staked Relayer client intermediates between Bitcoin Core
/// and the PolkaBTC Parachain.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::1]:3030")]
    http_addr: String,

    /// Starting height for vault theft checks, if not defined
    /// automatically start from the chain tip.
    #[clap(long)]
    scan_start_height: Option<u32>,

    /// Starting height to relay block headers, if not defined
    /// use the best height as reported by the relay module.
    #[clap(long)]
    relay_start_height: Option<u32>,

    /// Max batch size for combined block header submission,
    /// currently unsupported.
    #[clap(long, default_value = "1", possible_value = "1")]
    max_batch_size: u32,

    /// Timeout in milliseconds to repeat oracle liveness check.
    #[clap(long, default_value = "5000")]
    oracle_timeout_ms: u64,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let oracle_timeout_ms = opts.oracle_timeout_ms;

    let signer = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Alice.pair());
    let provider =
        PolkaBtcProvider::from_url(opts.polka_btc_url, Arc::new(RwLock::new(signer))).await?;
    let shared_prov = Arc::new(provider);
    let tx_provider = shared_prov.clone();

    let api_prov = shared_prov.clone();
    let btc_client = BtcClient::new::<RelayError>(bitcoin::bitcoin_rpc_from_env()?);

    // scan from custom height or the current tip
    let mut btc_height = if let Some(height) = opts.scan_start_height {
        height
    } else {
        btc_client.get_block_count()? + 1
    };
    let btc_rpc = bitcoin::BitcoinMonitor::new(bitcoin::bitcoin_rpc_from_env()?);

    let mut runner = Runner::new(
        PolkaClient::new(shared_prov.clone()),
        btc_client,
        Config {
            start_height: opts.relay_start_height.unwrap_or(0),
            max_batch_size: opts.max_batch_size,
        },
    )?;

    let vault_prov = shared_prov.clone();
    let vaults = vault_prov
        .get_all_vaults()
        .await?
        .into_iter()
        .map(|vault| (vault.btc_address, vault));

    // collect (btc_address, vault) into HashMap
    let vaults = Arc::new(Vaults::from(vaults.into_iter().collect()));
    let vaults_rw = vaults.clone();
    let vaults_ro = vaults.clone();

    let http_addr = opts.http_addr.parse()?;

    let result = tokio::try_join!(
        // runs grpc server for incoming requests
        tokio::spawn(async move { http::start(api_prov, http_addr).await }),
        // runs subscription service to update registered vaults
        tokio::spawn(async move {
            vault_prov
                .on_register(
                    |vault| async {
                        info!("Vault registered: {}", vault.id);
                        vaults_rw.write(vault.btc_address, vault).await;
                    },
                    |err| error!("{}", err.to_string()),
                )
                .await
                .unwrap()
        }),
        // runs oracle liveness check
        tokio::spawn(async move {
            let oracle = Oracle::new(shared_prov.clone());
            utils::check_every(Duration::from_millis(oracle_timeout_ms), || async {
                oracle.report_offline().await
            })
            .await
        }),
        // runs vault theft checks
        tokio::spawn(async move {
            loop {
                info!("Scanning height {}", btc_height);
                let hash = btc_rpc.wait_for_block(btc_height).await.unwrap();
                for maybe_tx in btc_rpc.get_block_transactions(&hash).unwrap() {
                    if let Some(tx) = maybe_tx {
                        let tx_id = tx.txid;
                        // TODO: spawn_blocking?
                        let raw_tx = btc_rpc.get_raw_tx(&tx_id, &hash).unwrap();
                        let proof = btc_rpc.get_proof(tx_id.clone(), &hash).unwrap();
                        // filter matching vaults
                        let vault_ids = iter(bitcoin::extract_btc_addresses(tx))
                            .filter_map(|addr| vaults_ro.contains_key(addr))
                            .collect::<Vec<AccountId>>()
                            .await;

                        for vault_id in vault_ids {
                            info!("Found tx from vault {}", vault_id);
                            // check if matching redeem or replace request
                            if tx_provider
                                .is_transaction_invalid(vault_id.clone(), raw_tx.clone())
                                .await
                                .unwrap()
                            {
                                // TODO: prevent blocking here
                                info!("Transaction is invalid");
                                match tx_provider
                                    .report_vault_theft(
                                        vault_id,
                                        H256Le::from_bytes_le(&tx_id.as_hash()),
                                        btc_height,
                                        proof.clone(),
                                        raw_tx.clone(),
                                    )
                                    .await
                                {
                                    Ok(_) => info!("Successfully reported invalid transaction"),
                                    Err(e) => error!(
                                        "Failed to report invalid transaction: {}",
                                        e.to_string()
                                    ),
                                }
                            }
                        }
                    }
                }
                btc_height += 1;
            }
        }),
        tokio::task::spawn_blocking(move || runner.run().unwrap())
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

struct Vaults(RwLock<HashMap<H160, PolkaBtcVault>>);

impl Vaults {
    fn from(vaults: HashMap<H160, PolkaBtcVault>) -> Self {
        Self(RwLock::new(vaults))
    }

    async fn write(&self, key: H160, value: PolkaBtcVault) {
        self.0.write().await.insert(key, value);
    }

    async fn contains_key(&self, addr: H160) -> Option<AccountId> {
        let vaults = self.0.read().await;
        if let Some(vault) = vaults.get(&addr.clone()) {
            return Some(vault.id.clone());
        }
        None
    }
}
