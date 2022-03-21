use crate::error::Error;
use bitcoin::{stream_blocks, BitcoinCoreApi, BlockHash, Network, PartialAddress, Transaction, TransactionExt as _};
use futures::{
    prelude::*,
    stream::{iter, StreamExt},
};
use runtime::{
    BtcAddress, BtcRelayPallet, Error as RuntimeError, H256Le, InterBtcParachain, InterBtcVault, RegisterAddressEvent,
    RegisterVaultEvent, RelayPallet, Ss58Codec, VaultId, VaultRegistryPallet,
};
use service::Error as ServiceError;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Default)]
pub struct Vaults(RwLock<HashMap<BtcAddress, VaultId>>);

impl Vaults {
    pub fn from(vaults: HashMap<BtcAddress, VaultId>) -> Self {
        Self(RwLock::new(vaults))
    }

    pub async fn write(&self, key: BtcAddress, value: VaultId) {
        self.0.write().await.insert(key, value);
    }

    pub async fn add_vault(&self, vault: InterBtcVault) {
        let mut vaults = self.0.write().await;
        for address in vault.wallet.addresses {
            vaults.insert(address, vault.id.clone());
        }
    }

    pub async fn contains_key(&self, key: BtcAddress) -> Option<VaultId> {
        let vaults = self.0.read().await;
        vaults.get(&key).cloned()
    }
}

pub async fn monitor_btc_txs<
    P: RelayPallet + BtcRelayPallet + Send + Sync,
    B: BitcoinCoreApi + Send + Sync + Clone + 'static,
>(
    bitcoin_core: B,
    btc_parachain: P,
    btc_height: u32,
    vaults: Arc<Vaults>,
) -> Result<(), ServiceError> {
    match BitcoinMonitor::new(bitcoin_core, btc_parachain, btc_height, vaults)
        .process_blocks()
        .await
    {
        Ok(_) => Ok(()),
        Err(err) => Err(ServiceError::RuntimeError(err)),
    }
}

pub struct BitcoinMonitor<
    P: RelayPallet + BtcRelayPallet + Send + Sync,
    B: BitcoinCoreApi + Send + Sync + Clone + 'static,
> {
    bitcoin_core: B,
    btc_parachain: P,
    btc_height: u32,
    vaults: Arc<Vaults>,
}

impl<P: RelayPallet + BtcRelayPallet + Send + Sync, B: BitcoinCoreApi + Send + Sync + Clone + 'static>
    BitcoinMonitor<P, B>
{
    pub fn new(bitcoin_core: B, btc_parachain: P, btc_height: u32, vaults: Arc<Vaults>) -> Self {
        Self {
            bitcoin_core,
            btc_parachain,
            btc_height,
            vaults,
        }
    }

    /// Check a bitcoin transaction made by the given vault, and try to report it if it is invalid.
    /// Note that since this is not essential to the vault's operation, this is done on a best-effort
    /// basis. I.e., we don't retry on failure.  
    async fn check_vault_transaction(
        &self,
        vault_id: &VaultId,
        transaction: &Transaction,
        block_hash: BlockHash,
    ) -> Result<(), Error> {
        tracing::debug!(
            "Found txid {} from vault {}",
            transaction.txid(),
            vault_id.pretty_printed()
        );
        // check if matching redeem or replace request
        let raw_tx = bitcoin::serialize(transaction);
        if self.btc_parachain.is_transaction_invalid(vault_id, &raw_tx).await? {
            tracing::info!(
                "Detected theft by vault {} - txid {}. Reporting...",
                vault_id.pretty_printed(),
                transaction.txid()
            );

            let proof = self.bitcoin_core.get_proof(transaction.txid(), &block_hash).await?;
            self.btc_parachain.report_vault_theft(vault_id, &proof, &raw_tx).await?;
        } else {
            // valid payment.. but check that it is not a duplicate payment
            for (txid_2, block_hash_2) in self.bitcoin_core.find_duplicate_payments(transaction).await? {
                let raw_tx_2 = self.bitcoin_core.get_raw_tx(&txid_2, &block_hash_2).await?;
                if !self.btc_parachain.is_transaction_invalid(vault_id, &raw_tx_2).await? {
                    tracing::info!(
                        "Detected double payment by vault {} - txids {} and {}. Reporting...",
                        vault_id.pretty_printed(),
                        transaction.txid(),
                        txid_2
                    );
                    let proof_1 = self.bitcoin_core.get_proof(transaction.txid(), &block_hash).await?;
                    let proof_2 = self.bitcoin_core.get_proof(txid_2, &block_hash_2).await?;
                    self.btc_parachain
                        .report_vault_double_payment(
                            vault_id,
                            (proof_1.to_vec(), proof_2.to_vec()),
                            (raw_tx.to_vec(), raw_tx_2.to_vec()),
                        )
                        .await?;
                }
            }
        }

        Ok(())
    }

    async fn stream_relayed_transactions(
        &self,
        rpc: B,
        from_height: u32,
        num_confirmations: u32,
    ) -> impl Stream<Item = Result<(BlockHash, Transaction), Error>> + Send + Unpin + '_ {
        Box::pin(
            stream_blocks(rpc, from_height, num_confirmations)
                .await
                .then(move |block| async move {
                    let transactions: Box<dyn Stream<Item = _> + Unpin + Send> = match block {
                        Ok(e) => {
                            let block_hash = e.block_hash();
                            // at this point we know that the transaction has `num_confirmations` on the bitcoin chain,
                            // but the relay can introduce a delay, so wait until the relay also confirms the
                            // transaction.
                            let transactions: Box<dyn Stream<Item = _> + Unpin + Send> = match self
                                .btc_parachain
                                .wait_for_block_in_relay(
                                    H256Le::from_bytes_le(&block_hash.to_vec()),
                                    Some(num_confirmations),
                                )
                                .await
                            {
                                Ok(_) => {
                                    tracing::debug!("Scanning block {} for transactions...", block_hash);
                                    Box::new(stream::iter(e.txdata.into_iter().map(move |x| Ok((block_hash, x)))))
                                }
                                Err(e) => Box::new(stream::iter(std::iter::once(Err(e.into())))),
                            };
                            transactions
                        }
                        Err(e) => Box::new(stream::iter(std::iter::once(Err(e.into())))),
                    };
                    transactions
                })
                .flatten(),
        )
    }

    async fn check_transaction(&self, tx: Transaction, block_hash: BlockHash) -> Result<(), Error> {
        let tx_id = tx.txid();
        tracing::debug!("Checking transaction {}", tx_id);
        let addresses = tx.extract_input_addresses();
        let vault_ids = filter_matching_vaults(addresses, &self.vaults).await;

        for vault_id in vault_ids {
            self.check_vault_transaction(&vault_id, &tx, block_hash).await?;
        }

        Ok(())
    }

    pub async fn process_blocks(&mut self) -> Result<(), RuntimeError> {
        let num_confirmations = self.btc_parachain.get_bitcoin_confirmations().await?;
        tracing::info!("Starting bitcoin monitoring...");

        let mut stream = self
            .stream_relayed_transactions(self.bitcoin_core.clone(), self.btc_height, num_confirmations)
            .await;

        while let Some(Ok((block_hash, tx))) = stream.next().await {
            if let Err(err) = self.check_transaction(tx, block_hash).await {
                tracing::error!("Failed to check transaction: {}", err);
            }
        }

        // stream should not end, signal restart
        Err(RuntimeError::ChannelClosed)
    }
}

pub async fn listen_for_wallet_updates(
    btc_parachain: InterBtcParachain,
    btc_network: Network,
    vaults: Arc<Vaults>,
) -> Result<(), ServiceError> {
    let vaults = &vaults;
    btc_parachain
        .on_event::<RegisterAddressEvent, _, _, _>(
            |event| async move {
                let btc_address = event.address;
                tracing::info!(
                    "Added new btc address {} for vault {}",
                    btc_address
                        .encode_str(btc_network)
                        .unwrap_or(format!("{:?}", btc_address)),
                    event.vault_id.account_id.to_ss58check()
                );
                vaults.write(btc_address, event.vault_id).await;
            },
            |err| tracing::error!("Error (RegisterAddressEvent): {}", err.to_string()),
        )
        .await?;
    Ok(())
}

pub async fn listen_for_vaults_registered(
    btc_parachain: InterBtcParachain,
    vaults: Arc<Vaults>,
) -> Result<(), ServiceError> {
    btc_parachain
        .on_event::<RegisterVaultEvent, _, _, _>(
            |event| async {
                let vault_id = event.vault_id;
                match btc_parachain.get_vault(&vault_id).await {
                    Ok(vault) => {
                        tracing::info!("Vault registered: {}", vault.id.pretty_printed());
                        vaults.add_vault(vault).await;
                    }
                    Err(err) => tracing::error!("Error getting vault: {}", err.to_string()),
                };
            },
            |err| tracing::error!("Error (RegisterVaultEvent): {}", err.to_string()),
        )
        .await?;
    Ok(())
}

async fn filter_matching_vaults(addresses: Vec<BtcAddress>, vaults: &Vaults) -> Vec<VaultId> {
    iter(addresses)
        .filter_map(|addr| vaults.contains_key(addr))
        .collect::<Vec<VaultId>>()
        .await
}

#[cfg(all(test, feature = "standalone-metadata"))]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bitcoin::{
        json, Amount, Block, BlockHeader, Error as BitcoinError, GetBlockResult, Hash as _, LockedTransaction,
        PartialAddress, PrivateKey, Transaction, TransactionMetadata, Txid, PUBLIC_KEY_SIZE,
    };
    use runtime::{
        AccountId, BitcoinBlockHeight, BlockNumber, Error as RuntimeError, H256Le, InterBtcRichBlockHeader,
        RawBlockHeader, Token, DOT, INTERBTC,
    };
    use sp_core::{H160, H256};

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait RelayPallet {
            async fn report_vault_theft(
                &self,
                vault_id: &VaultId,
                merkle_proof: &[u8],
                raw_tx: &[u8],
            ) -> Result<(), RuntimeError>;
            async fn report_vault_double_payment(
                &self,
                vault_id: &VaultId,
                merkle_proofs: (Vec<u8>, Vec<u8>),
                raw_txs: (Vec<u8>, Vec<u8>),
            ) -> Result<(), RuntimeError>;
            async fn is_transaction_invalid(&self, vault_id: &VaultId, raw_tx: &[u8]) -> Result<bool, RuntimeError>;
            async fn initialize_btc_relay(&self, header: RawBlockHeader, height: BitcoinBlockHeight) -> Result<(), RuntimeError>;
            async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), RuntimeError>;
            async fn store_block_headers(&self, headers: Vec<RawBlockHeader>) -> Result<(), RuntimeError>;
        }

        #[async_trait]
        pub trait BtcRelayPallet {
            async fn get_best_block(&self) -> Result<H256Le, RuntimeError>;
            async fn get_best_block_height(&self) -> Result<u32, RuntimeError>;
            async fn get_block_hash(&self, height: u32) -> Result<H256Le, RuntimeError>;
            async fn get_block_header(&self, hash: H256Le) -> Result<InterBtcRichBlockHeader, RuntimeError>;
            async fn get_bitcoin_confirmations(&self) -> Result<u32, RuntimeError>;
            async fn get_parachain_confirmations(&self) -> Result<BlockNumber, RuntimeError>;
            async fn wait_for_block_in_relay(
                &self,
                block_hash: H256Le,
                btc_confirmations: Option<BlockNumber>,
            ) -> Result<(), RuntimeError>;
            async fn verify_block_header_inclusion(&self, block_hash: H256Le) -> Result<(), RuntimeError>;
        }
    }

    impl Clone for MockProvider {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    mockall::mock! {
        Bitcoin {}

        #[async_trait]
        trait BitcoinCoreApi {
            fn network(&self) -> Network;
            async fn wait_for_block(&self, height: u32, num_confirmations: u32) -> Result<Block, BitcoinError>;
            async fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, BitcoinError>;
            async fn list_transactions(&self, max_count: Option<usize>) -> Result<Vec<json::ListTransactionResult>, BitcoinError>;
            async fn get_block_count(&self) -> Result<u64, BitcoinError>;
            async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_transaction(&self, txid: &Txid, block_hash: Option<BlockHash>) -> Result<Transaction, BitcoinError>;
            async fn get_proof(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_block_hash(&self, height: u32) -> Result<BlockHash, BitcoinError>;
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
            async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, BitcoinError>;
            async fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, BitcoinError>;
            async fn get_mempool_transactions<'a>(
                &'a self,
            ) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send +'a>, BitcoinError>;
            async fn wait_for_transaction_metadata(
                &self,
                txid: Txid,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_transaction<A: PartialAddress + Send + Sync + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: Option<H256>,
            ) -> Result<LockedTransaction, BitcoinError>;
            async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, BitcoinError>;
            async fn create_and_send_transaction<A: PartialAddress + Send + Sync + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: Option<H256>,
            ) -> Result<Txid, BitcoinError>;
            async fn send_to_address<A: PartialAddress + Send + Sync + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: Option<H256>,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_or_load_wallet(&self) -> Result<(), BitcoinError>;
            async fn wallet_has_public_key<P>(&self, public_key: P) -> Result<bool, BitcoinError>
                where
                    P: Into<[u8; PUBLIC_KEY_SIZE]> + From<[u8; PUBLIC_KEY_SIZE]> + Clone + PartialEq + Send + Sync + 'static;
            async fn import_private_key(&self, privkey: PrivateKey) -> Result<(), BitcoinError>;
            async fn rescan_blockchain(&self, start_height: usize) -> Result<(), BitcoinError>;
            async fn find_duplicate_payments(&self, transaction: &Transaction) -> Result<Vec<(Txid, BlockHash)>, BitcoinError>;
            async fn get_utxo_count(&self) -> Result<usize, BitcoinError>;
        }
    }

    impl Clone for MockBitcoin {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    fn dummy_vault_id() -> VaultId {
        VaultId::new(AccountId::new([1u8; 32]), Token(DOT), Token(INTERBTC))
    }

    #[tokio::test]
    async fn test_filter_matching_vaults() {
        let dummy_vault = dummy_vault_id();
        let vaults = Vaults::from(
            vec![(BtcAddress::P2PKH(H160::from_slice(&[0; 20])), dummy_vault.clone())]
                .into_iter()
                .collect(),
        );

        assert_eq!(
            filter_matching_vaults(vec![BtcAddress::P2PKH(H160::from_slice(&[0; 20]))], &vaults).await,
            vec![dummy_vault],
        );

        assert_eq!(
            filter_matching_vaults(vec![BtcAddress::P2PKH(H160::from_slice(&[1; 20]))], &vaults).await,
            vec![],
        );
    }

    fn dummy_tx() -> Transaction {
        Transaction {
            version: 2,
            lock_time: 1,
            input: vec![],
            output: vec![],
        }
    }

    #[tokio::test]
    async fn test_report_valid_transaction() {
        let mut parachain = MockProvider::default();
        parachain.expect_is_transaction_invalid().returning(|_, _| Ok(false));
        parachain
            .expect_report_vault_theft()
            .never()
            .returning(|_, _, _| Ok(()));

        let mut bitcoin_core = MockBitcoin::default();
        bitcoin_core.expect_find_duplicate_payments().returning(|_| Ok(vec![]));

        let monitor = BitcoinMonitor::new(bitcoin_core, parachain, 0, Arc::new(Vaults::default()));

        let block_hash = BlockHash::from_slice(&[0; 32]).unwrap();
        monitor
            .check_vault_transaction(&dummy_vault_id(), &dummy_tx(), block_hash)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_check_vault_transaction_transaction() {
        let mut parachain = MockProvider::default();
        let mut btc_rpc = MockBitcoin::default();
        parachain.expect_is_transaction_invalid().returning(|_, _| Ok(true));
        parachain.expect_report_vault_theft().once().returning(|_, _, _| Ok(()));
        btc_rpc.expect_get_proof().once().returning(|_, _| Ok(vec![]));

        let monitor = BitcoinMonitor::new(btc_rpc, parachain, 0, Arc::new(Vaults::default()));

        let block_hash = BlockHash::from_slice(&[0; 32]).unwrap();
        monitor
            .check_vault_transaction(&dummy_vault_id(), &dummy_tx(), block_hash)
            .await
            .unwrap();
    }
}
