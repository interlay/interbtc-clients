use crate::error::Error;
use async_trait::async_trait;
use bitcoin::{
    sha256, stream_blocks, BitcoinCoreApi, BlockHash, Hash, Network, PartialAddress, Transaction, TransactionExt as _,
};
use futures::{
    prelude::*,
    stream::{iter, StreamExt},
};
use runtime::{
    AccountId, BtcAddress, BtcRelayPallet, Error as RuntimeError, H256Le, InterBtcParachain, InterBtcVault,
    PrettyPrint, RegisterAddressEvent, RegisterVaultEvent, RelayPallet, UtilFuncs, VaultId, VaultRegistryPallet,
    VaultStatus,
};
use service::Error as ServiceError;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};
use tokio::sync::RwLock;

#[derive(Default, Debug)]
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

    /// Returns the position of a given vault in a randomised ordering based on a
    /// piece of seed data.
    ///
    /// # Arguments
    /// * `data` - the seed used as a basis for the ordering (for example, an issue_id)
    /// * `account_id` - the AccountId we wish to order relative to the list of vaults
    pub async fn get_random_position(&self, data: &[u8; 32], account_id: &AccountId) -> usize {
        fn hash_vault(data: &[u8; 32], account_id: &AccountId) -> sha256::Hash {
            let account_id: [u8; 32] = account_id.clone().into();
            let xor = data
                .zip(account_id) // will need to refactor if we don't want experimental array_zip
                .map(|(a, b)| a ^ b);
            sha256::Hash::hash(&xor)
        }

        let hash = hash_vault(data, account_id);
        let mut hash_set = HashSet::new(); // for deduping
        self.0
            .read()
            .await
            .iter()
            .filter(|&(_, vault_id)| hash_set.insert(hash_vault(data, &vault_id.account_id) < hash))
            .count()
    }
}

#[async_trait]
pub trait RandomDelay {
    async fn delay(&self, seed_data: &[u8; 32]) -> Result<(), RuntimeError>;
}

#[derive(Clone)]
pub struct OrderedVaultsDelay {
    btc_parachain: InterBtcParachain,
    /// Order relative to this set of vaults
    vaults: Arc<Vaults>,
}

impl OrderedVaultsDelay {
    pub fn new(btc_parachain: InterBtcParachain, vaults: Arc<Vaults>) -> Self {
        Self { btc_parachain, vaults }
    }
}

impl fmt::Debug for OrderedVaultsDelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedDelayableVaults")
            .field("btc_parachain", &self.btc_parachain.get_account_id())
            .field("vaults", &self.vaults)
            .finish()
    }
}

#[async_trait]
impl RandomDelay for OrderedVaultsDelay {
    async fn delay(&self, seed_data: &[u8; 32]) -> Result<(), RuntimeError> {
        let random_ordering = self
            .vaults
            .get_random_position(seed_data, self.btc_parachain.get_account_id())
            .await;
        let delay: u32 = (random_ordering + 1).log2();
        self.btc_parachain.delay_for_blocks(delay).await
    }
}

/// For testing only
#[async_trait]
impl RandomDelay for () {
    async fn delay(&self, _seed_data: &[u8; 32]) -> Result<(), RuntimeError> {
        Ok(())
    }
}

pub async fn monitor_btc_txs<
    P: VaultRegistryPallet + RelayPallet + BtcRelayPallet + Send + Sync,
    B: BitcoinCoreApi + Send + Sync + Clone + 'static,
    RD: RandomDelay + Send + Sync,
>(
    bitcoin_core: B,
    btc_parachain: P,
    random_delay: RD,
    btc_height: u32,
    vaults: Arc<Vaults>,
) -> Result<(), ServiceError> {
    match BitcoinMonitor::new(bitcoin_core, btc_parachain, random_delay, btc_height, vaults)
        .process_blocks()
        .await
    {
        Ok(_) => Ok(()),
        Err(err) => Err(ServiceError::RuntimeError(err)),
    }
}

pub(crate) async fn initialize_active_vaults<P: VaultRegistryPallet + Send + Sync>(
    btc_parachain: P,
) -> Result<Arc<Vaults>, Error> {
    tracing::info!("Fetching all active vaults...");
    let vaults = btc_parachain
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
    Ok(Arc::new(Vaults::from(vaults)))
}

pub struct BitcoinMonitor<
    P: VaultRegistryPallet + RelayPallet + BtcRelayPallet + Send + Sync,
    B: BitcoinCoreApi + Send + Sync + Clone + 'static,
    RD: RandomDelay + Send + Sync,
> {
    bitcoin_core: B,
    btc_parachain: P,
    random_delay: RD,
    btc_height: u32,
    vaults: Arc<Vaults>,
}

impl<
        P: VaultRegistryPallet + RelayPallet + BtcRelayPallet + Send + Sync,
        B: BitcoinCoreApi + Send + Sync + Clone + 'static,
        RD: RandomDelay + Send + Sync,
    > BitcoinMonitor<P, B, RD>
{
    pub fn new(bitcoin_core: B, btc_parachain: P, random_delay: RD, btc_height: u32, vaults: Arc<Vaults>) -> Self {
        Self {
            bitcoin_core,
            btc_parachain,
            random_delay,
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
            vault_id.pretty_print()
        );
        // check if matching redeem or replace request
        let raw_tx = bitcoin::serialize(transaction);

        // wait a random amount of blocks before checking, to avoid all vaults
        // flooding the parachain with this transaction
        self.random_delay.delay(transaction.txid().as_inner()).await?;
        let vault = self.btc_parachain.get_vault(vault_id).await?;
        if vault.status == VaultStatus::CommittedTheft {
            tracing::debug!(
                "Vault {} has already been reported - doing nothing.",
                vault_id.pretty_print()
            );
            return Ok(());
        }

        if self.btc_parachain.is_transaction_invalid(vault_id, &raw_tx).await? {
            tracing::info!(
                "Detected theft by vault {} - txid {}. Reporting...",
                vault_id.pretty_print(),
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
                        vault_id.pretty_print(),
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
                                .wait_for_block_in_relay(H256Le::from_bytes_le(&block_hash), Some(num_confirmations))
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
                    event.vault_id.account_id.pretty_print()
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
                        tracing::info!("Vault registered: {}", vault.id.pretty_print());
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
        json, Amount, Block, BlockHeader, Error as BitcoinError, GetBlockResult, LockedTransaction, PartialAddress,
        PrivateKey, Transaction, TransactionMetadata, Txid, PUBLIC_KEY_SIZE,
    };
    use runtime::{
        AccountId, BitcoinBlockHeight, BlockNumber, BtcPublicKey, CurrencyId, Error as RuntimeError, H256Le,
        InterBtcRichBlockHeader, RawBlockHeader, Token, DOT, IBTC, Wallet,
    };
    use sp_core::{H160, H256};
    use std::collections::BTreeSet;

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait VaultRegistryPallet {
            async fn get_vault(&self, vault_id: &VaultId) -> Result<InterBtcVault, RuntimeError>;
            async fn get_vaults_by_account_id(&self, account_id: &AccountId) -> Result<Vec<VaultId>, RuntimeError>;
            async fn get_all_vaults(&self) -> Result<Vec<InterBtcVault>, RuntimeError>;
            async fn register_vault(&self, vault_id: &VaultId, collateral: u128) -> Result<(), RuntimeError>;
            async fn deposit_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
            async fn withdraw_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
            async fn get_public_key(&self) -> Result<Option<BtcPublicKey>, RuntimeError>;
            async fn register_public_key(&self, public_key: BtcPublicKey) -> Result<(), RuntimeError>;
            async fn register_address(&self, vault_id: &VaultId, btc_address: BtcAddress) -> Result<(), RuntimeError>;
            async fn get_required_collateral_for_wrapped(
                &self,
                amount_btc: u128,
                collateral_currency: CurrencyId,
            ) -> Result<u128, RuntimeError>;
            async fn get_required_collateral_for_vault(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
            async fn get_vault_total_collateral(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
            async fn get_collateralization_from_vault(&self, vault_id: VaultId, only_issued: bool) -> Result<u128, RuntimeError>;
        }

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
            fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, BitcoinError>;
            fn list_transactions(&self, max_count: Option<usize>) -> Result<Vec<json::ListTransactionResult>, BitcoinError>;
            async fn get_block_count(&self) -> Result<u64, BitcoinError>;
            async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_transaction(&self, txid: &Txid, block_hash: Option<BlockHash>) -> Result<Transaction, BitcoinError>;
            async fn get_proof(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_block_hash(&self, height: u32) -> Result<BlockHash, BitcoinError>;
            async fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, BitcoinError>;
            async fn get_new_address<A: PartialAddress + Send + 'static>(&self) -> Result<A, BitcoinError>;
            async fn get_new_public_key<P: From<[u8; PUBLIC_KEY_SIZE]> + 'static>(&self) -> Result<P, BitcoinError>;
            fn dump_derivation_key<P: Into<[u8; PUBLIC_KEY_SIZE]> + Send + Sync + 'static>(&self, public_key: P) -> Result<PrivateKey, BitcoinError>;
            fn import_derivation_key(&self, private_key: &PrivateKey) -> Result<(), BitcoinError>;
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
            async fn rescan_blockchain(&self, start_height: usize, end_height: usize) -> Result<(), BitcoinError>;
            async fn find_duplicate_payments(&self, transaction: &Transaction) -> Result<Vec<(Txid, BlockHash)>, BitcoinError>;
            fn get_utxo_count(&self) -> Result<usize, BitcoinError>;
        }
    }

    impl Clone for MockBitcoin {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    fn dummy_vault_id() -> VaultId {
        VaultId::new(AccountId::new([1u8; 32]), Token(DOT), Token(IBTC))
    }

    fn dummy_wallet() -> Wallet {
        Wallet {
            addresses: BTreeSet::default(),
        }
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
        parachain.expect_get_vault().returning(|_| Ok(InterBtcVault {
            id: dummy_vault_id(),
            wallet: dummy_wallet(),
            status: VaultStatus::Active(true),
            banned_until: None,
            to_be_issued_tokens: 0,
            issued_tokens: 0,
            to_be_redeemed_tokens: 0,
            to_be_replaced_tokens: 0,
            replace_collateral: 0,
            active_replace_collateral: 0,
            liquidated_collateral: 0,
        }));

        let mut bitcoin_core = MockBitcoin::default();
        bitcoin_core.expect_find_duplicate_payments().returning(|_| Ok(vec![]));

        let monitor = BitcoinMonitor::new(bitcoin_core, parachain, (), 0, Arc::new(Vaults::default()));

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
        parachain.expect_get_vault().returning(|_| Ok(InterBtcVault {
            id: dummy_vault_id(),
            wallet: dummy_wallet(),
            status: VaultStatus::Active(true),
            banned_until: None,
            to_be_issued_tokens: 0,
            issued_tokens: 0,
            to_be_redeemed_tokens: 0,
            to_be_replaced_tokens: 0,
            replace_collateral: 0,
            active_replace_collateral: 0,
            liquidated_collateral: 0,
        }));
        btc_rpc.expect_get_proof().once().returning(|_, _| Ok(vec![]));

        let monitor = BitcoinMonitor::new(btc_rpc, parachain, (), 0, Arc::new(Vaults::default()));

        let block_hash = BlockHash::from_slice(&[0; 32]).unwrap();
        monitor
            .check_vault_transaction(&dummy_vault_id(), &dummy_tx(), block_hash)
            .await
            .unwrap();
    }
}
