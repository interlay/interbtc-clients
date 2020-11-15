use super::Error;
use crate::utils;
use bitcoin::{
    BitcoinCore, BitcoinCoreApi, BlockHash, ConversionError as BitcoinConversionError,
    Error as BitcoinError, Hash,
};
use log::{error, info};
use runtime::{
    pallets::{btc_relay::StoreMainChainHeaderEvent, staked_relayers::StatusUpdateSuggestedEvent},
    Error as RuntimeError, ErrorCode, H256Le, PolkaBtcProvider, PolkaBtcRuntime,
    StakedRelayerPallet, StatusCode,
};
use std::sync::Arc;

type PolkaBtcStatusUpdateSuggestedEvent = StatusUpdateSuggestedEvent<PolkaBtcRuntime>;

pub struct StatusUpdateMonitor<B: BitcoinCoreApi, P: StakedRelayerPallet> {
    btc_rpc: Arc<B>,
    polka_rpc: Arc<P>,
}

impl<B: BitcoinCoreApi, P: StakedRelayerPallet> StatusUpdateMonitor<B, P> {
    pub fn new(btc_rpc: Arc<B>, polka_rpc: Arc<P>) -> Self {
        Self { btc_rpc, polka_rpc }
    }

    async fn on_status_update_suggested(
        &self,
        event: PolkaBtcStatusUpdateSuggestedEvent,
    ) -> Result<(), Error> {
        if !utils::is_registered(&self.polka_rpc).await {
            return Ok(());
        }
        // TODO: ignore self submitted

        // we can only automate NO_DATA checks, all other suggestible
        // status updates can only be voted upon manually
        if let Some(ErrorCode::NoDataBTCRelay) = event.add_error {
            // TODO: check status_code?
            match self
                .btc_rpc
                .is_block_known(convert_block_hash(event.block_hash)?)
            {
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

pub async fn listen_for_status_updates(
    btc_rpc: Arc<BitcoinCore>,
    polka_rpc: Arc<PolkaBtcProvider>,
) -> Result<(), RuntimeError> {
    let monitor = &StatusUpdateMonitor::new(btc_rpc, polka_rpc.clone());
    polka_rpc
        .on_event::<PolkaBtcStatusUpdateSuggestedEvent, _, _, _>(
            |event| async move {
                info!("Status update {} suggested", event.status_update_id);
                if let Err(err) = monitor.on_status_update_suggested(event).await {
                    error!("Error: {}", err.to_string());
                }
            },
            |err| error!("Error (Status): {}", err.to_string()),
        )
        .await
}

pub struct RelayMonitor<B: BitcoinCoreApi, P: StakedRelayerPallet> {
    btc_rpc: Arc<B>,
    polka_rpc: Arc<P>,
    status_update_deposit: u128,
}

impl<B: BitcoinCoreApi, P: StakedRelayerPallet> RelayMonitor<B, P> {
    pub fn new(btc_rpc: Arc<B>, polka_rpc: Arc<P>, status_update_deposit: u128) -> Self {
        Self {
            btc_rpc,
            polka_rpc,
            status_update_deposit,
        }
    }

    pub async fn on_store_block(&self, height: u32, hash: H256Le) -> Result<(), Error> {
        if !utils::is_registered(&self.polka_rpc).await {
            return Ok(());
        }
        info!("Block submission: {}", hash);

        // TODO: check if user submitted
        match self.btc_rpc.get_block_hash_for(height) {
            Ok(_) => info!("Block exists"),
            Err(_) => {
                self.polka_rpc
                    .suggest_status_update(
                        self.status_update_deposit,
                        StatusCode::Error,
                        Some(ErrorCode::NoDataBTCRelay),
                        None,
                        Some(hash),
                        String::new(),
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

pub async fn listen_for_blocks_stored(
    btc_rpc: Arc<BitcoinCore>,
    polka_rpc: Arc<PolkaBtcProvider>,
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
    use bitcoin::{GetRawTransactionResult, TransactionMetadata, Txid};
    use runtime::PolkaBtcStatusUpdate;
    use runtime::{AccountId, Error as RuntimeError, ErrorCode, H256Le, StatusCode, MINIMUM_STAKE};
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

            fn get_block_count(&self) -> Result<u64, BitcoinError>;

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
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
        }
    }

    #[tokio::test]
    async fn test_on_store_block_exists() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_block_hash_for()
            .returning(|_| Ok(BlockHash::from_slice(&[1; 32]).unwrap()));
        let mut parachain = MockProvider::default();
        parachain
            .expect_suggest_status_update()
            .never()
            .returning(|_, _, _, _, _, _| Ok(()));
        parachain
            .expect_get_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = RelayMonitor::new(Arc::new(bitcoin), Arc::new(parachain), 100);
        assert_ok!(
            monitor
                .on_store_block(123, H256Le::from_bytes_le(&[1; 32]))
                .await
        );
    }

    #[tokio::test]
    async fn test_on_store_block_not_exists() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_block_hash_for()
            .returning(|_| Err(BitcoinConversionError::BlockHashError.into()));
        let mut parachain = MockProvider::default();
        parachain
            .expect_suggest_status_update()
            .once()
            .returning(|_, _, _, _, _, _| Ok(()));
        parachain
            .expect_get_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = RelayMonitor::new(Arc::new(bitcoin), Arc::new(parachain), 100);
        assert_ok!(
            monitor
                .on_store_block(123, H256Le::from_bytes_le(&[1; 32]))
                .await
        );
    }

    #[tokio::test]
    async fn test_on_store_block_no_stake() {
        let bitcoin = MockBitcoin::default();
        let mut parachain = MockProvider::default();
        parachain
            .expect_get_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE - 1));

        let monitor = RelayMonitor::new(Arc::new(bitcoin), Arc::new(parachain), 100);
        assert_ok!(monitor.on_store_block(0, H256Le::zero()).await);
    }

    #[tokio::test]
    async fn test_on_status_update_suggested_ignore() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin.expect_is_block_known().never();
        let mut parachain = MockProvider::default();
        parachain.expect_vote_on_status_update().never();
        parachain
            .expect_get_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = StatusUpdateMonitor::new(Arc::new(bitcoin), Arc::new(parachain));
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
            .expect_get_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = StatusUpdateMonitor::new(Arc::new(bitcoin), Arc::new(parachain));
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
        bitcoin
            .expect_is_block_known()
            .once()
            .returning(|_| Ok(false));
        let mut parachain = MockProvider::default();
        parachain
            .expect_vote_on_status_update()
            .withf(|_, approve| approve == &true)
            .once()
            .returning(|_, _| Ok(()));
        parachain
            .expect_get_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = StatusUpdateMonitor::new(Arc::new(bitcoin), Arc::new(parachain));
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
        bitcoin
            .expect_is_block_known()
            .once()
            .returning(|_| Ok(true));
        let mut parachain = MockProvider::default();
        parachain
            .expect_vote_on_status_update()
            .withf(|_, approve| approve == &false)
            .once()
            .returning(|_, _| Ok(()));
        parachain
            .expect_get_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        let monitor = StatusUpdateMonitor::new(Arc::new(bitcoin), Arc::new(parachain));
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
            .expect_get_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE - 1));

        let monitor = StatusUpdateMonitor::new(Arc::new(bitcoin), Arc::new(parachain));
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
