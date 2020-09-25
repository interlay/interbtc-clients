use crate::bitcoin;
use crate::bitcoin::BitcoinMonitor;
use futures::stream::iter;
use futures::stream::StreamExt;
use log::{error, info};
use runtime::{AccountId, H256Le, PolkaBtcProvider, PolkaBtcVault, StakedRelayerPallet};
use sp_core::H160;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct Vaults(RwLock<HashMap<H160, PolkaBtcVault>>);

impl Vaults {
    pub fn from(vaults: HashMap<H160, PolkaBtcVault>) -> Self {
        Self(RwLock::new(vaults))
    }

    pub async fn write(&self, key: H160, value: PolkaBtcVault) {
        self.0.write().await.insert(key, value);
    }

    pub async fn contains_key(&self, addr: H160) -> Option<AccountId> {
        let vaults = self.0.read().await;
        if let Some(vault) = vaults.get(&addr.clone()) {
            return Some(vault.id.clone());
        }
        None
    }
}

pub struct VaultsWatcher {
    btc_height: u32,
    btc_rpc: Arc<BitcoinMonitor>,
    vaults: Arc<Vaults>,
    polka_rpc: Arc<PolkaBtcProvider>,
}

impl VaultsWatcher {
    pub fn new(
        btc_height: u32,
        btc_rpc: Arc<BitcoinMonitor>,
        vaults: Arc<Vaults>,
        polka_rpc: Arc<PolkaBtcProvider>,
    ) -> Self {
        Self {
            btc_height,
            btc_rpc,
            vaults,
            polka_rpc,
        }
    }

    pub async fn watch(&mut self) {
        loop {
            info!("Scanning height {}", self.btc_height);
            let hash = self.btc_rpc.wait_for_block(self.btc_height).await.unwrap();
            for maybe_tx in self.btc_rpc.get_block_transactions(&hash).unwrap() {
                if let Some(tx) = maybe_tx {
                    let tx_id = tx.txid;
                    // TODO: spawn_blocking?
                    let raw_tx = self.btc_rpc.get_raw_tx(&tx_id, &hash).unwrap();
                    let proof = self.btc_rpc.get_proof(tx_id.clone(), &hash).unwrap();
                    // filter matching vaults
                    let vault_ids = iter(bitcoin::extract_btc_addresses(tx))
                        .filter_map(|addr| self.vaults.contains_key(addr))
                        .collect::<Vec<AccountId>>()
                        .await;

                    for vault_id in vault_ids {
                        info!("Found tx from vault {}", vault_id);
                        // check if matching redeem or replace request
                        if self
                            .polka_rpc
                            .is_transaction_invalid(vault_id.clone(), raw_tx.clone())
                            .await
                            .unwrap()
                        {
                            // TODO: prevent blocking here
                            info!("Transaction is invalid");
                            match self
                                .polka_rpc
                                .report_vault_theft(
                                    vault_id,
                                    H256Le::from_bytes_le(&tx_id.as_hash()),
                                    self.btc_height,
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
            self.btc_height += 1;
        }
    }
}
