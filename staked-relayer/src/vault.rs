use crate::error::{get_retry_policy, Error};
use crate::utils;
use backoff::backoff::Backoff;
use bitcoin::{BitcoinCoreApi, BlockHash, Transaction, TransactionExt as _, Txid};
use futures::stream::iter;
use futures::stream::StreamExt;
use log::*;
use runtime::{
    pallets::vault_registry::{RegisterAddressEvent, RegisterVaultEvent},
    AccountId, BtcAddress, BtcRelayPallet, Error as RuntimeError, H256Le, PolkaBtcProvider,
    PolkaBtcRuntime, PolkaBtcVault, StakedRelayerPallet, VaultRegistryPallet,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Default)]
pub struct Vaults(RwLock<HashMap<BtcAddress, AccountId>>);

impl Vaults {
    pub fn from(vaults: HashMap<BtcAddress, AccountId>) -> Self {
        Self(RwLock::new(vaults))
    }

    pub async fn write(&self, key: BtcAddress, value: AccountId) {
        self.0.write().await.insert(key, value);
    }

    pub async fn add_vault(&self, vault: PolkaBtcVault) {
        let mut vaults = self.0.write().await;
        for address in vault.wallet.addresses {
            vaults.insert(address, vault.id.clone());
        }
    }

    pub async fn contains_key(&self, key: BtcAddress) -> Option<AccountId> {
        let vaults = self.0.read().await;
        vaults.get(&key).map(|id| id.clone())
    }
}

pub struct VaultTheftMonitor<P: StakedRelayerPallet + BtcRelayPallet, B: BitcoinCoreApi> {
    btc_height: u32,
    btc_rpc: Arc<B>,
    polka_rpc: Arc<P>,
    vaults: Arc<Vaults>,
    delay: Duration,
}

impl<P: StakedRelayerPallet + BtcRelayPallet, B: BitcoinCoreApi> VaultTheftMonitor<P, B> {
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

    async fn get_raw_tx_and_proof(
        &self,
        tx_id: Txid,
        hash: &BlockHash,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let raw_tx = self.btc_rpc.get_raw_tx_for(&tx_id, hash).await?;
        let proof = self.btc_rpc.get_proof_for(tx_id, hash).await?;
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
                    proof,
                    raw_tx,
                )
                .await?;
        }

        Ok(())
    }

    async fn check_transaction(
        &self,
        tx: Transaction,
        block_hash: BlockHash,
        num_confirmations: u32,
    ) -> Result<(), Error> {
        // at this point we know that the transaction has `num_confirmations` on the bitcoin chain,
        // but the relay can introduce a delay, so wait until the relay also confirms the transaction.
        self.polka_rpc
            .wait_for_block_in_relay(
                H256Le::from_bytes_le(&block_hash.to_vec()),
                num_confirmations,
            )
            .await?;

        let tx_id = tx.txid();

        let (raw_tx, proof) = self.get_raw_tx_and_proof(tx_id, &block_hash).await?;

        let addresses = tx.extract_input_addresses();
        let vault_ids = filter_matching_vaults(addresses, &self.vaults).await;

        for vault_id in vault_ids {
            self.report_invalid(vault_id, &tx_id, raw_tx.clone(), proof.clone())
                .await?;
        }

        Ok(())
    }

    pub async fn scan(&mut self) -> Result<(), Error> {
        utils::wait_until_registered(&self.polka_rpc, self.delay).await;

        let num_confirmations = self.polka_rpc.get_bitcoin_confirmations().await?;

        let mut backoff = get_retry_policy();

        let mut stream = bitcoin::stream_in_chain_transactions(
            self.btc_rpc.clone(),
            self.btc_height,
            num_confirmations,
        )
        .await;

        loop {
            match stream.next().await.unwrap() {
                Ok((block_hash, tx)) => match self
                    .check_transaction(tx, block_hash, num_confirmations)
                    .await
                {
                    Ok(_) => {
                        backoff.reset();
                        continue; // don't execute the delay below
                    }
                    Err(e) => error!("Failed to check transaction: {}", e),
                },
                Err(e) => {
                    warn!("Failed to fetch transaction: {}", e);
                }
            }
            // error occurred. Sleep before retrying
            match backoff.next_backoff() {
                Some(wait) => {
                    tokio::time::delay_for(wait).await;
                }
                None => return Err(Error::TransactionFetchingError),
            }
        }
    }
}

pub async fn listen_for_wallet_updates(
    polka_rpc: Arc<PolkaBtcProvider>,
    vaults: Arc<Vaults>,
) -> Result<(), RuntimeError> {
    let vaults = &vaults;
    polka_rpc
        .on_event::<RegisterAddressEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                info!(
                    "Added new btc address {} for vault {}",
                    event.btc_address, event.vault_id
                );
                vaults.write(event.btc_address, event.vault_id).await;
            },
            |err| error!("Error (RegisterAddressEvent): {}", err.to_string()),
        )
        .await
}

pub async fn listen_for_vaults_registered(
    polka_rpc: Arc<PolkaBtcProvider>,
    vaults: Arc<Vaults>,
) -> Result<(), RuntimeError> {
    polka_rpc
        .on_event::<RegisterVaultEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async {
                match polka_rpc.get_vault(event.account_id).await {
                    Ok(vault) => {
                        info!("Vault registered: {}", vault.id);
                        vaults.add_vault(vault).await;
                    }
                    Err(err) => error!("Error getting vault: {}", err.to_string()),
                };
            },
            |err| error!("Error (RegisterVaultEvent): {}", err.to_string()),
        )
        .await
}

async fn filter_matching_vaults(addresses: Vec<BtcAddress>, vaults: &Vaults) -> Vec<AccountId> {
    iter(addresses)
        .filter_map(|addr| vaults.contains_key(addr))
        .collect::<Vec<AccountId>>()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bitcoin::{
        Block, Error as BitcoinError, GetBlockResult, LockedTransaction, PartialAddress,
        Transaction, TransactionMetadata, PUBLIC_KEY_SIZE,
    };
    use runtime::PolkaBtcStatusUpdate;
    use runtime::{AccountId, Error as RuntimeError, ErrorCode, H256Le, StatusCode};
    use runtime::{BitcoinBlockHeight, RawBlockHeader, RichBlockHeader};
    use sp_core::H160;
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
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn is_transaction_invalid(
                &self,
                vault_id: AccountId,
                raw_tx: Vec<u8>,
            ) -> Result<bool, RuntimeError>;
            async fn set_maturity_period(&self, period: u32) -> Result<(), RuntimeError>;
        }

        #[async_trait]
        pub trait BtcRelayPallet {
            async fn get_best_block(&self) -> Result<H256Le, RuntimeError>;
            async fn get_best_block_height(&self) -> Result<u32, RuntimeError>;
            async fn get_block_hash(&self, height: u32) -> Result<H256Le, RuntimeError>;
            async fn get_block_header(&self, hash: H256Le) -> Result<RichBlockHeader, RuntimeError>;
            async fn initialize_btc_relay(
                &self,
                header: RawBlockHeader,
                height: BitcoinBlockHeight,
            ) -> Result<(), RuntimeError>;
            async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), RuntimeError>;
            async fn store_block_headers(&self, headers: Vec<RawBlockHeader>) -> Result<(), RuntimeError>;
            async fn get_bitcoin_confirmations(&self) -> Result<u32, RuntimeError>;
            async fn wait_for_block_in_relay(
                &self,
                block_hash: H256Le,
                num_confirmations: u32,
            ) -> Result<(), RuntimeError>;
        }
    }

    mockall::mock! {
        Bitcoin {}

        #[async_trait]
        trait BitcoinCoreApi {
            async fn wait_for_block(&self, height: u32, delay: Duration, num_confirmations: u32) -> Result<BlockHash, BitcoinError>;
            async fn get_block_count(&self) -> Result<u64, BitcoinError>;
            async fn get_raw_tx_for(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
           async  fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, BitcoinError>;
            async fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, BitcoinError>;
            async fn get_new_address<A: PartialAddress + Send + 'static>(&self) -> Result<A, BitcoinError>;
            async fn get_new_public_key<P: From<[u8; PUBLIC_KEY_SIZE]> + 'static>(&self) -> Result<P, BitcoinError>;
            async fn add_new_deposit_key<P: Into<[u8; PUBLIC_KEY_SIZE]> + Send + Sync + 'static>(
                &self,
                public_key: P,
                secret_key: Vec<u8>,
            ) -> Result<(), BitcoinError>;
            async fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinError>;
            async fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinError>;
            async fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, BitcoinError>;
            async fn get_mempool_transactions<'a>(
                self: Arc<Self>,
            ) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send +'a>, BitcoinError>;
            async fn wait_for_transaction_metadata(
                &self,
                txid: Txid,
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_transaction<A: PartialAddress + Send + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: &[u8; 32],
            ) -> Result<LockedTransaction, BitcoinError>;
            async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, BitcoinError>;
            async fn create_and_send_transaction<A: PartialAddress + Send + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: &[u8; 32],
            ) -> Result<Txid, BitcoinError>;
            async fn send_to_address<A: PartialAddress + Send + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: &[u8; 32],
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_wallet(&self, wallet: &str) -> Result<(), BitcoinError>;
            async fn wallet_has_public_key<P>(&self, public_key: P) -> Result<bool, BitcoinError>
                where
                    P: Into<[u8; PUBLIC_KEY_SIZE]> + From<[u8; PUBLIC_KEY_SIZE]> + Clone + PartialEq + Send + Sync + 'static;
        }
    }

    #[tokio::test]
    async fn test_filter_matching_vaults() {
        let vaults = Vaults::from(
            vec![(
                BtcAddress::P2PKH(H160::from_slice(&[0; 20])),
                AccountKeyring::Bob.to_account_id(),
            )]
            .into_iter()
            .collect(),
        );

        assert_eq!(
            filter_matching_vaults(vec![BtcAddress::P2PKH(H160::from_slice(&[0; 20]))], &vaults)
                .await,
            vec![AccountKeyring::Bob.to_account_id()],
        );

        assert_eq!(
            filter_matching_vaults(vec![BtcAddress::P2PKH(H160::from_slice(&[1; 20]))], &vaults)
                .await,
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
            .returning(|_, _, _, _| Ok(()));

        let monitor = VaultTheftMonitor::new(
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
            .returning(|_, _, _, _| Ok(()));

        let monitor = VaultTheftMonitor::new(
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
