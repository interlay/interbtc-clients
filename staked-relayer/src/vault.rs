use crate::utils;
use crate::Error;
use bitcoin::{BitcoinCoreApi, BlockHash, GetRawTransactionResult, Txid};
use futures::stream::iter;
use futures::stream::StreamExt;
use log::{error, info};
use runtime::{
    AccountId, Error as RuntimeError, H256Le, PolkaBtcProvider, PolkaBtcVault, StakedRelayerPallet,
};
use sp_core::H160;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Default)]
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

pub struct VaultsMonitor<P: StakedRelayerPallet, B: BitcoinCoreApi> {
    btc_height: u32,
    btc_rpc: Arc<B>,
    polka_rpc: Arc<P>,
    vaults: Arc<Vaults>,
    delay: Duration,
}

impl<P: StakedRelayerPallet, B: BitcoinCoreApi> VaultsMonitor<P, B> {
    pub fn new(
        btc_height: u32,
        btc_rpc: Arc<B>,
        vaults: Arc<Vaults>,
        polka_rpc: Arc<P>,
        delay: Duration,
    ) -> Self {
        Self {
            btc_height,
            btc_rpc,
            polka_rpc,
            vaults,
            delay,
        }
    }

    fn get_raw_tx_and_proof(
        &self,
        tx_id: Txid,
        hash: &BlockHash,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let raw_tx = self.btc_rpc.get_raw_tx_for(&tx_id, hash)?;
        let proof = self.btc_rpc.get_proof_for(tx_id, hash)?;
        Ok((raw_tx, proof))
    }

    async fn report_invalid(
        &self,
        vault_id: AccountId,
        tx_id: &Txid,
        raw_tx: Vec<u8>,
        proof: Vec<u8>,
    ) -> Result<(), Error> {
        info!("Found tx from vault {}", vault_id);
        // check if matching redeem or replace request
        if self
            .polka_rpc
            .is_transaction_invalid(vault_id.clone(), raw_tx.clone())
            .await?
        {
            info!("Transaction is invalid");
            self.polka_rpc
                .report_vault_theft(
                    vault_id,
                    H256Le::from_bytes_le(&tx_id.as_hash()),
                    self.btc_height,
                    proof,
                    raw_tx,
                )
                .await?;
        }

        Ok(())
    }

    async fn check_transaction(
        &self,
        tx: GetRawTransactionResult,
        block_hash: BlockHash,
    ) -> Result<(), Error> {
        let tx_id = tx.txid;

        // TODO: spawn_blocking?
        let (raw_tx, proof) = self.get_raw_tx_and_proof(tx_id.clone(), &block_hash)?;

        let addresses = bitcoin::extract_btc_addresses(tx);
        let vault_ids = filter_matching_vaults(addresses, &self.vaults).await;

        for vault_id in vault_ids {
            self.report_invalid(vault_id, &tx_id, raw_tx.clone(), proof.clone())
                .await?;
        }

        Ok(())
    }

    async fn scan_next_height(&mut self) -> Result<(), Error> {
        utils::wait_until_registered(&self.polka_rpc, self.delay).await;

        info!("Scanning height {}", self.btc_height);
        let block_hash = self
            .btc_rpc
            .wait_for_block(self.btc_height, self.delay)
            .await?;
        for maybe_tx in self.btc_rpc.get_block_transactions(&block_hash)? {
            if let Some(tx) = maybe_tx {
                self.check_transaction(tx, block_hash).await?
            }
        }
        self.btc_height += 1;
        Ok(())
    }

    pub async fn scan(&mut self) {
        loop {
            if let Err(err) = self.scan_next_height().await {
                error!("Something went wrong: {}", err.to_string());
            }
        }
    }
}

pub async fn listen_for_vaults_registered(
    polka_rpc: Arc<PolkaBtcProvider>,
    vaults: Arc<Vaults>,
) -> Result<(), RuntimeError> {
    polka_rpc
        .on_register(
            |vault| async {
                info!("Vault registered: {}", vault.id);
                vaults.write(vault.btc_address, vault).await;
            },
            |err| error!("Error: {}", err.to_string()),
        )
        .await
}

async fn filter_matching_vaults(addresses: Vec<H160>, vaults: &Vaults) -> Vec<AccountId> {
    iter(addresses)
        .filter_map(|addr| vaults.contains_key(addr))
        .collect::<Vec<AccountId>>()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bitcoin::{Error as BitcoinError, TransactionMetadata};
    use runtime::PolkaBtcStatusUpdate;
    use runtime::{AccountId, Error as RuntimeError, ErrorCode, H256Le, StatusCode};
    use sp_keyring::AccountKeyring;

    mockall::mock! {
        Provider {}

        #[async_trait]
        trait StakedRelayerPallet {
            async fn get_stake(&self) -> Result<u64, RuntimeError>;
            async fn register_staked_relayer(&self, stake: u128) -> Result<(), RuntimeError>;
            async fn deregister_staked_relayer(&self) -> Result<(), RuntimeError>;
            async fn suggest_status_update(
                &self,
                deposit: u128,
                status_code: StatusCode,
                add_error: Option<ErrorCode>,
                remove_error: Option<ErrorCode>,
                block_hash: Option<H256Le>,
                message: String,
            ) -> Result<(), RuntimeError>;
            async fn vote_on_status_update(
                &self,
                status_update_id: u64,
                approve: bool,
            ) -> Result<(), RuntimeError>;
            async fn get_status_update(&self, id: u64) -> Result<PolkaBtcStatusUpdate, RuntimeError>;
            async fn report_oracle_offline(&self) -> Result<(), RuntimeError>;
            async fn report_vault_theft(
                &self,
                vault_id: AccountId,
                tx_id: H256Le,
                tx_block_height: u32,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn is_transaction_invalid(
                &self,
                vault_id: AccountId,
                raw_tx: Vec<u8>,
            ) -> Result<bool, RuntimeError>;
        }
    }

    mockall::mock! {
        Bitcoin {}

        #[async_trait]
        trait BitcoinCoreApi {
            async fn wait_for_block(&self, height: u32, delay: Duration) -> Result<BlockHash, BitcoinError>;

            fn get_block_transactions(
                &self,
                hash: &BlockHash,
            ) -> Result<Vec<Option<GetRawTransactionResult>>, BitcoinError>;

            fn get_raw_tx_for(
                &self,
                txid: &Txid,
                block_hash: &BlockHash,
            ) -> Result<Vec<u8>, BitcoinError>;

            fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;

            fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, BitcoinError>;

            fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, BitcoinError>;

            async fn send_to_address(
                &self,
                address: String,
                sat: u64,
                redeem_id: &[u8; 32],
                op_timeout: Duration,
            ) -> Result<TransactionMetadata, BitcoinError>;
        }
    }

    #[tokio::test]
    async fn test_filter_matching_vaults() {
        let mut vault = PolkaBtcVault::default();
        vault.id = AccountKeyring::Bob.to_account_id();
        let vaults = Vaults::from(
            vec![(H160::from_slice(&[0; 20]), vault)]
                .into_iter()
                .collect(),
        );

        assert_eq!(
            filter_matching_vaults(vec![H160::from_slice(&[0; 20])], &vaults).await,
            vec![AccountKeyring::Bob.to_account_id()],
        );

        assert_eq!(
            filter_matching_vaults(vec![H160::from_slice(&[1; 20])], &vaults).await,
            vec![],
        );
    }

    #[tokio::test]
    async fn test_report_valid_transaction() {
        let mut parachain = MockProvider::default();
        parachain
            .expect_is_transaction_invalid()
            .returning(|_, _| Ok(false));
        parachain
            .expect_report_vault_theft()
            .never()
            .returning(|_, _, _, _, _| Ok(()));

        let monitor = VaultsMonitor::new(
            0,
            Arc::new(MockBitcoin::default()),
            Arc::new(Vaults::default()),
            Arc::new(parachain),
            Duration::from_millis(100),
        );

        monitor
            .report_invalid(
                AccountKeyring::Bob.to_account_id(),
                &Txid::default(),
                vec![],
                vec![],
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_report_invalid_transaction() {
        let mut parachain = MockProvider::default();
        parachain
            .expect_is_transaction_invalid()
            .returning(|_, _| Ok(true));
        parachain
            .expect_report_vault_theft()
            .once()
            .returning(|_, _, _, _, _| Ok(()));

        let monitor = VaultsMonitor::new(
            0,
            Arc::new(MockBitcoin::default()),
            Arc::new(Vaults::default()),
            Arc::new(parachain),
            Duration::from_millis(100),
        );

        monitor
            .report_invalid(
                AccountKeyring::Bob.to_account_id(),
                &Txid::default(),
                vec![],
                vec![],
            )
            .await
            .unwrap();
    }
}
