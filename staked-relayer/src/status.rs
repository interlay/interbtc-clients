use super::Error;
use crate::utils;
use bitcoin::{BitcoinCoreApi, BlockHash, ConversionError as BitcoinConversionError, Error as BitcoinError, Hash};
use log::{error, info, warn};
use runtime::{
    pallets::{btc_relay::StoreMainChainHeaderEvent, staked_relayers::StatusUpdateSuggestedEvent},
    Error as RuntimeError, ErrorCode, H256Le, PolkaBtcProvider, PolkaBtcRuntime, StakedRelayerPallet, StatusCode,
    UtilFuncs,
};

type PolkaBtcStatusUpdateSuggestedEvent = StatusUpdateSuggestedEvent<PolkaBtcRuntime>;

pub struct StatusUpdateMonitor<B: BitcoinCoreApi + Clone, P: StakedRelayerPallet> {
    btc_rpc: B,
    polka_rpc: P,
}

impl<B: BitcoinCoreApi + Clone, P: StakedRelayerPallet + UtilFuncs> StatusUpdateMonitor<B, P> {
    pub fn new(btc_rpc: B, polka_rpc: P) -> Self {
        Self { btc_rpc, polka_rpc }
    }

    async fn on_status_update_suggested(&self, event: PolkaBtcStatusUpdateSuggestedEvent) -> Result<(), Error> {
        if !utils::is_active(&self.polka_rpc).await? {
            // not registered (active), ignore event
            return Ok(());
        }

        // we can only automate NO_DATA checks, all other suggestible
        // status updates can only be voted upon manually
        if let Some(ErrorCode::NoDataBTCRelay) = event.add_error {
            match self.btc_rpc.is_block_known(convert_block_hash(event.block_hash)?).await {
                Ok(true) => {
                    self.polka_rpc
                        .vote_on_status_update(event.status_update_id, false)
                        .await?;
                }
                Ok(false) => {
                    self.polka_rpc
                        .vote_on_status_update(event.status_update_id, true)
                        .await?;
                }
                Err(err) => error!("Error validating block: {}", err.to_string()),
            }
        }

        Ok(())
    }
}

pub async fn listen_for_status_updates<B: BitcoinCoreApi + Clone>(
    btc_rpc: B,
    polka_rpc: PolkaBtcProvider,
) -> Result<(), RuntimeError> {
    let monitor = &StatusUpdateMonitor::new(btc_rpc, polka_rpc.clone());

    let polka_rpc = &polka_rpc;
    polka_rpc
        .on_event::<PolkaBtcStatusUpdateSuggestedEvent, _, _, _>(
            |event| async move {
                if event.account_id == *polka_rpc.get_account_id() {
                    return; // ignore events we caused ourselves
                }

                info!("Status update {} suggested", event.status_update_id);
                if let Err(err) = monitor.on_status_update_suggested(event).await {
                    error!("Error: {}", err.to_string());
                }
            },
            |err| error!("Error (Status): {}", err.to_string()),
        )
        .await
}

pub struct RelayMonitor<B: BitcoinCoreApi + Clone, P: StakedRelayerPallet> {
    btc_rpc: B,
    polka_rpc: P,
    status_update_deposit: u128,
}

async fn report_no_data_btc_relay<P: StakedRelayerPallet>(
    rpc: &P,
    deposit: u128,
    block_hash: H256Le,
) -> Result<(), Error> {
    Ok(rpc
        .suggest_status_update(
            deposit,
            StatusCode::Error,
            Some(ErrorCode::NoDataBTCRelay),
            None,
            Some(block_hash),
            String::new(),
        )
        .await?)
}

impl<B: BitcoinCoreApi + Clone, P: StakedRelayerPallet> RelayMonitor<B, P> {
    pub fn new(btc_rpc: B, polka_rpc: P, status_update_deposit: u128) -> Self {
        Self {
            btc_rpc,
            polka_rpc,
            status_update_deposit,
        }
    }

    pub async fn on_store_block(&self, height: u32, parachain_block_hash: H256Le) -> Result<(), Error> {
        if !utils::is_active(&self.polka_rpc).await? {
            // not registered (active), ignore event
            return Ok(());
        }

        // TODO: check if user submitted
        info!("Block submission: {}", parachain_block_hash);
        match self.btc_rpc.get_block_hash(height).await {
            Ok(bitcoin_block_hash) => {
                if bitcoin_block_hash.into_inner() != parachain_block_hash.to_bytes_le() {
                    warn!("Block does not match at height {}", height);
                    report_no_data_btc_relay(&self.polka_rpc, self.status_update_deposit, parachain_block_hash).await?;
                }
            }
            Err(BitcoinError::InvalidBitcoinHeight) => {
                warn!("Block does not exist at height {}", height);
                report_no_data_btc_relay(&self.polka_rpc, self.status_update_deposit, parachain_block_hash).await?;
            }
            Err(e) => error!("Got error on get_block_hash({}): {}", height, e),
        }

        Ok(())
    }
}

pub async fn listen_for_blocks_stored<B: BitcoinCoreApi + Clone>(
    btc_rpc: B,
    polka_rpc: PolkaBtcProvider,
    status_update_deposit: u128,
) -> Result<(), RuntimeError> {
    let monitor = &RelayMonitor::new(btc_rpc, polka_rpc.clone(), status_update_deposit);
    polka_rpc
        .on_event::<StoreMainChainHeaderEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if let Err(err) = monitor
                    .on_store_block(event.block_height, event.block_header_hash)
                    .await
                {
                    error!("Error: {}", err.to_string());
                }
            },
            |err| error!("Error (Blocks): {}", err.to_string()),
        )
        .await
}

fn convert_block_hash(hash: Option<H256Le>) -> Result<BlockHash, Error> {
    if let Some(hash) = hash {
        return BlockHash::from_slice(&hash.to_bytes_le())
            .map_err(|_| Error::from(BitcoinError::from(BitcoinConversionError::BlockHashError)));
    }
    Err(Error::EventNoBlockHash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bitcoin::{
        Block, BlockHeader, GetBlockResult, LockedTransaction, PartialAddress, PrivateKey, Transaction,
        TransactionMetadata, Txid, PUBLIC_KEY_SIZE,
    };
    use runtime::{
        AccountId, Error as RuntimeError, ErrorCode, H256Le, PolkaBtcStatusUpdate, StatusCode, MINIMUM_STAKE,
    };
    use sp_core::H256;
    use sp_keyring::AccountKeyring;
    use std::time::Duration;

    macro_rules! assert_ok {
        ( $x:expr $(,)? ) => {
            let is = $x;
            match is {
                Ok(_) => (),
                _ => assert!(false, "Expected Ok(_). Got {:#?}", is),
            }
        };
        ( $x:expr, $y:expr $(,)? ) => {
            assert_eq!($x, Ok($y));
        };
    }

    macro_rules! assert_err {
        ($result:expr, $err:pat) => {{
            match $result {
                Err($err) => (),
                Ok(v) => panic!("assertion failed: Ok({:?})", v),
                _ => panic!("expected: Err($err)"),
            }
        }};
    }

    #[test]
    fn test_convert_block_hash() {
        assert_err!(convert_block_hash(None), Error::EventNoBlockHash);

        let block_hash = convert_block_hash(Some(H256Le::zero())).unwrap();
        assert_eq!(block_hash, BlockHash::from_slice(&[0; 32]).unwrap());
    }

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait UtilFuncs {
            async fn get_current_chain_height(&self) -> Result<u32, RuntimeError>;
            async fn get_blockchain_height_at(&self, parachain_height: u32) -> Result<u32, RuntimeError>;
            fn get_account_id(&self) -> &AccountId;
        }

        #[async_trait]
        trait StakedRelayerPallet {
            async fn get_active_stake(&self) -> Result<u128, RuntimeError>;
            async fn get_active_stake_by_id(&self, account_id: AccountId) -> Result<u128, RuntimeError>;
            async fn get_inactive_stake_by_id(&self, account_id: AccountId) -> Result<u128, RuntimeError>;
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
            async fn evaluate_status_update(&self, status_update_id: u64) -> Result<(), RuntimeError>;
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
            async fn wait_for_block(&self, height: u32, delay: Duration, num_confirmations: u32) -> Result<BlockHash, BitcoinError>;
            async fn get_block_count(&self) -> Result<u64, BitcoinError>;
            async fn get_raw_tx_for(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
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
                self: &'a Self,
            ) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send + 'a>, BitcoinError>;
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
                request_id: Option<H256>,
            ) -> Result<LockedTransaction, BitcoinError>;
            async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, BitcoinError>;
            async fn create_and_send_transaction<A: PartialAddress + Send + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: Option<H256>,
            ) -> Result<Txid, BitcoinError>;
            async fn send_to_address<A: PartialAddress + Send + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: Option<H256>,
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_wallet(&self, wallet: &str) -> Result<(), BitcoinError>;
            async fn wallet_has_public_key<P>(&self, public_key: P) -> Result<bool, BitcoinError>
                where
                    P: Into<[u8; PUBLIC_KEY_SIZE]> + From<[u8; PUBLIC_KEY_SIZE]> + Clone + PartialEq + Send + Sync + 'static;
            async fn import_private_key(&self, privkey: PrivateKey) -> Result<(), BitcoinError>;
        }
    }

    impl Clone for MockBitcoin {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    #[tokio::test]
    async fn test_on_store_block_exists() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_block_hash()
            .returning(|_| Ok(BlockHash::from_slice(&[1; 32]).unwrap()));
        let mut parachain = MockProvider::default();
        parachain
            .expect_suggest_status_update()
            .never()
            .returning(|_, _, _, _, _, _| Ok(()));
        parachain
            .expect_get_active_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = RelayMonitor::new(bitcoin, parachain, 100);
        assert_ok!(monitor.on_store_block(123, H256Le::from_bytes_le(&[1; 32])).await);
    }

    #[tokio::test]
    async fn test_on_store_block_not_exists() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_block_hash()
            .returning(|_| Err(BitcoinError::InvalidBitcoinHeight.into()));
        let mut parachain = MockProvider::default();
        parachain
            .expect_suggest_status_update()
            .once()
            .returning(|_, _, _, _, _, _| Ok(()));
        parachain
            .expect_get_active_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = RelayMonitor::new(bitcoin, parachain, 100);
        assert_ok!(monitor.on_store_block(123, H256Le::from_bytes_le(&[1; 32])).await);
    }

    #[tokio::test]
    async fn test_on_store_block_no_stake() {
        let bitcoin = MockBitcoin::default();
        let mut parachain = MockProvider::default();
        parachain
            .expect_get_active_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE - 1));

        let monitor = RelayMonitor::new(bitcoin, parachain, 100);
        assert_ok!(monitor.on_store_block(0, H256Le::zero()).await);
    }

    #[tokio::test]
    async fn test_on_status_update_suggested_ignore() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin.expect_is_block_known().never();
        let mut parachain = MockProvider::default();
        parachain.expect_vote_on_status_update().never();
        parachain
            .expect_get_active_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = StatusUpdateMonitor::new(bitcoin, parachain);
        assert_ok!(
            monitor
                .on_status_update_suggested(PolkaBtcStatusUpdateSuggestedEvent {
                    status_update_id: 0,
                    account_id: AccountKeyring::Bob.to_account_id(),
                    status_code: StatusCode::Running,
                    add_error: None,
                    remove_error: None,
                    block_hash: None,
                })
                .await
        );
    }

    #[tokio::test]
    async fn test_on_status_update_suggested_add_error_no_block_hash() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin.expect_is_block_known().never();
        let mut parachain = MockProvider::default();
        parachain.expect_vote_on_status_update().never();
        parachain
            .expect_get_active_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = StatusUpdateMonitor::new(bitcoin, parachain);
        assert_err!(
            monitor
                .on_status_update_suggested(PolkaBtcStatusUpdateSuggestedEvent {
                    status_update_id: 0,
                    account_id: AccountKeyring::Bob.to_account_id(),
                    status_code: StatusCode::Error,
                    add_error: Some(ErrorCode::NoDataBTCRelay),
                    remove_error: None,
                    block_hash: None,
                })
                .await,
            Error::EventNoBlockHash
        );
    }

    #[tokio::test]
    async fn test_on_status_update_suggested_add_error_block_unknown() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin.expect_is_block_known().once().returning(|_| Ok(false));
        let mut parachain = MockProvider::default();
        parachain
            .expect_vote_on_status_update()
            .withf(|_, approve| approve == &true)
            .once()
            .returning(|_, _| Ok(()));
        parachain
            .expect_get_active_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = StatusUpdateMonitor::new(bitcoin, parachain);
        assert_ok!(
            monitor
                .on_status_update_suggested(PolkaBtcStatusUpdateSuggestedEvent {
                    status_update_id: 0,
                    account_id: AccountKeyring::Bob.to_account_id(),
                    status_code: StatusCode::Error,
                    add_error: Some(ErrorCode::NoDataBTCRelay),
                    remove_error: None,
                    block_hash: Some(H256Le::zero()),
                })
                .await
        );
    }

    #[tokio::test]
    async fn test_on_status_update_suggested_add_error_block_known() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin.expect_is_block_known().once().returning(|_| Ok(true));
        let mut parachain = MockProvider::default();
        parachain
            .expect_vote_on_status_update()
            .withf(|_, approve| approve == &false)
            .once()
            .returning(|_, _| Ok(()));
        parachain
            .expect_get_active_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = StatusUpdateMonitor::new(bitcoin, parachain);
        assert_ok!(
            monitor
                .on_status_update_suggested(PolkaBtcStatusUpdateSuggestedEvent {
                    status_update_id: 0,
                    account_id: AccountKeyring::Bob.to_account_id(),
                    status_code: StatusCode::Error,
                    add_error: Some(ErrorCode::NoDataBTCRelay),
                    remove_error: None,
                    block_hash: Some(H256Le::zero()),
                })
                .await
        );
    }

    #[tokio::test]
    async fn test_on_status_update_suggested_no_stake() {
        let bitcoin = MockBitcoin::default();
        let mut parachain = MockProvider::default();
        parachain
            .expect_get_active_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE - 1));

        let monitor = StatusUpdateMonitor::new(bitcoin, parachain);
        assert_ok!(
            monitor
                .on_status_update_suggested(PolkaBtcStatusUpdateSuggestedEvent {
                    status_update_id: 0,
                    account_id: AccountKeyring::Bob.to_account_id(),
                    status_code: StatusCode::Running,
                    add_error: None,
                    remove_error: None,
                    block_hash: None,
                })
                .await
        );
    }
}
