use crate::constants::*;
use crate::error::Error;
use crate::issue::{process_issue_requests, IssueIds};
use backoff::{future::FutureOperation as _, ExponentialBackoff};
use bitcoin::Network;
use bitcoin::{BitcoinCoreApi, PartialAddress, Transaction, TransactionExt, TransactionMetadata};
use log::*;
use runtime::{
    pallets::{redeem::RequestRedeemEvent, replace::AcceptReplaceEvent},
    BtcAddress, H256Le, PolkaBtcProvider, PolkaBtcRedeemRequest, PolkaBtcReplaceRequest,
    PolkaBtcRuntime, RedeemPallet, ReplacePallet, UtilFuncs,
};
use sp_core::H256;
use std::{collections::HashMap, sync::Arc, time::Duration};

#[derive(Debug, Clone)]
pub struct Request {
    hash: H256,
    open_time: Option<u32>,
    amount: u128,
    btc_address: BtcAddress,
    request_type: RequestType,
}

#[derive(Debug, Copy, Clone)]
pub enum RequestType {
    Redeem,
    Replace,
}

impl Request {
    /// Constructs a Request for the given PolkaBtcRedeemRequest
    fn from_redeem_request(hash: H256, request: PolkaBtcRedeemRequest) -> Request {
        Request {
            hash,
            open_time: Some(request.opentime),
            amount: request.amount_polka_btc,
            btc_address: request.btc_address,
            request_type: RequestType::Redeem,
        }
    }
    /// Constructs a Request for the given PolkaBtcReplaceRequest
    fn from_replace_request(hash: H256, request: PolkaBtcReplaceRequest) -> Request {
        Request {
            hash,
            open_time: Some(request.open_time),
            amount: request.amount,
            btc_address: request.btc_address,
            request_type: RequestType::Replace,
        }
    }
    /// Constructs a Request for the given AcceptReplaceEvent
    pub fn from_replace_request_event(
        request: &AcceptReplaceEvent<PolkaBtcRuntime>,
        btc_address: BtcAddress,
    ) -> Request {
        Request {
            btc_address,
            amount: request.btc_amount,
            hash: request.replace_id,
            open_time: None,
            request_type: RequestType::Replace,
        }
    }
    /// Constructs a Request for the given RequestRedeemEvent
    pub fn from_redeem_request_event(request: &RequestRedeemEvent<PolkaBtcRuntime>) -> Request {
        Request {
            btc_address: request.btc_address,
            amount: request.amount_polka_btc,
            hash: request.redeem_id,
            open_time: None,
            request_type: RequestType::Redeem,
        }
    }

    /// Makes the bitcoin transfer and executes the request
    pub async fn pay_and_execute<B: BitcoinCoreApi, P: ReplacePallet + RedeemPallet>(
        &self,
        provider: Arc<P>,
        btc_rpc: Arc<B>,
        num_confirmations: u32,
        network: Network,
    ) -> Result<(), Error> {
        let tx_metadata = self
            .transfer_btc(btc_rpc, num_confirmations, network)
            .await?;
        self.execute(provider, tx_metadata).await
    }

    /// Make a bitcoin transfer to fulfil the request
    async fn transfer_btc<B: BitcoinCoreApi>(
        &self,
        btc_rpc: Arc<B>,
        num_confirmations: u32,
        network: Network,
    ) -> Result<TransactionMetadata, Error> {
        let address = self
            .btc_address
            .encode_str(network)
            .map_err(|e| -> bitcoin::Error { e.into() })?;

        info!("Sending bitcoin to {}", self.btc_address);

        // make bitcoin transfer. Note: do not retry this call;
        // the call could fail to get the metadata even if the transaction
        // itself was successful
        let tx_metadata = btc_rpc
            .send_to_address::<BtcAddress>(
                address,
                self.amount as u64,
                &self.hash.to_fixed_bytes(),
                BITCOIN_MAX_RETRYING_TIME,
                num_confirmations,
            )
            .await?;

        info!("Bitcoin successfully sent to {}", self.btc_address);
        Ok(tx_metadata)
    }

    /// Executes the request. Upon failure it will retry
    async fn execute<P: ReplacePallet + RedeemPallet>(
        &self,
        provider: Arc<P>,
        tx_metadata: TransactionMetadata,
    ) -> Result<(), Error> {
        // select the execute function based on request_type
        let execute = match self.request_type {
            RequestType::Redeem => RedeemPallet::execute_redeem,
            RequestType::Replace => ReplacePallet::execute_replace,
        };

        // Retry until success or timeout
        (|| async {
            // call the selected function
            (execute)(
                &*provider,
                self.hash,
                H256Le::from_bytes_le(tx_metadata.txid.as_ref()),
                tx_metadata.proof.clone(),
                tx_metadata.raw_tx.clone(),
            )
            .await
            .map_err(|x| x.into())
        })
        .retry_notify(get_retry_policy(), |e, dur: Duration| {
            warn!(
                "{:?} execution of request {} failed: {} - next retry in {:.3} s",
                self.request_type,
                self.hash,
                e,
                dur.as_secs_f64()
            )
        })
        .await?;

        Ok(())
    }
}

/// Queries the parachain for open requests/replaces and executes them. It checks the
/// bitcoin blockchain to see if a payment has already been made.
pub async fn execute_open_requests<B: BitcoinCoreApi + Send + Sync + 'static>(
    provider: Arc<PolkaBtcProvider>,
    btc_rpc: Arc<B>,
    num_confirmations: u32,
    network: Network,
) -> Result<(), Error> {
    let vault_id = provider.get_account_id().clone();
    // get all open redeem/replaces and map them to the shared Request type
    let open_redeems = provider
        .clone()
        .get_vault_redeem_requests(vault_id.clone())
        .await?
        .into_iter()
        .filter(|(_, request)| !request.completed)
        .map(|(hash, request)| Request::from_redeem_request(hash, request));
    let open_replaces = provider
        .get_old_vault_replace_requests(vault_id)
        .await?
        .into_iter()
        .filter(|(_, request)| !request.completed)
        .map(|(hash, request)| Request::from_replace_request(hash, request));

    // Place all redeems&replaces into a hashmap, indexed by their redeemid/replaceid
    let mut hash_map = open_redeems
        .chain(open_replaces)
        .map(|x| (x.hash, x))
        .collect::<HashMap<_, _>>();

    // find the height of bitcoin chain corresponding to the earliest open_time
    let btc_start_height = match hash_map
        .iter()
        .map(|(_, request)| request.open_time.unwrap_or(u32::MAX))
        .min()
    {
        Some(x) => provider.clone().get_blockchain_height_at(x).await?,
        None => return Ok(()), // the iterator is empty so we have nothing to do
    };

    // iterate through transactions..
    for x in bitcoin::get_transactions(btc_rpc.clone(), btc_start_height)? {
        let tx = x?;

        // get the request this transaction corresponds to, if any
        if let Some(request) = get_request_for_btc_tx(&tx, &hash_map) {
            // remove request from the hashmap
            hash_map.retain(|&key, _| key != request.hash);

            info!(
                "{:?} request #{} has valid bitcoin payment - processing...",
                request.request_type, request.hash
            );

            // start a new task to (potentially) await confirmation and to execute on the parachain
            // make copies of the variables we move into the task
            let provider = provider.clone();
            let btc_rpc = btc_rpc.clone();
            tokio::spawn(async move {
                // Payment has been made, but it might not have been confirmed enough times yet
                let tx_metadata = btc_rpc
                    .clone()
                    .wait_for_transaction_metadata(
                        tx.txid(),
                        BITCOIN_MAX_RETRYING_TIME,
                        num_confirmations,
                    )
                    .await;

                match tx_metadata {
                    Ok(tx_metadata) => match request.execute(provider.clone(), tx_metadata).await {
                        Ok(_) => {
                            info!("Executed request #{}", request.hash);
                        }
                        Err(e) => error!("Failed to execute request #{}: {}", request.hash, e),
                    },
                    Err(e) => error!(
                        "Failed to confirm bitcoin transaction for request {}: {}",
                        request.hash, e
                    ),
                }
            });
        }
    }

    // All requests remaining in the hashmap did not have a bitcoin payment yet, so pay
    // and execute all of these
    for (_, request) in hash_map {
        // there are potentially a large number of open requests - pay and execute each
        // in a separate task to ensure that awaiting confirmations does not significantly
        // delay other requests
        // make copies of the variables we move into the task
        let provider = provider.clone();
        let btc_rpc = btc_rpc.clone();
        tokio::spawn(async move {
            info!(
                "{:?} request #{} found without bitcoin payment - processing...",
                request.request_type, request.hash
            );

            match request
                .pay_and_execute(provider, btc_rpc, num_confirmations, network)
                .await
            {
                Ok(_) => info!(
                    "{:?} request #{} successfully executed",
                    request.request_type, request.hash
                ),
                Err(e) => info!(
                    "{:?} request #{} failed to process: {}",
                    request.request_type, request.hash, e
                ),
            }
        });
    }

    Ok(())
}

/// Execute open issue requests, retry if stream ends early.
pub async fn execute_open_issue_requests<B: BitcoinCoreApi + Send + Sync + 'static>(
    provider: Arc<PolkaBtcProvider>,
    btc_rpc: Arc<B>,
    issue_set: Arc<IssueIds>,
    num_confirmations: u32,
) -> Result<(), Error> {
    (|| async {
        process_issue_requests(&provider, &btc_rpc, &issue_set, num_confirmations).await?;
        Ok(())
    })
    .retry(ExponentialBackoff {
        max_elapsed_time: None,
        ..get_retry_policy()
    })
    .await?;
    Ok(())
}

/// Get the Request from the hashmap that the given Transaction satisfies, based
/// on the OP_RETURN and the amount of btc that is transfered to the address
fn get_request_for_btc_tx(tx: &Transaction, hash_map: &HashMap<H256, Request>) -> Option<Request> {
    let hash = tx.get_op_return()?;
    let request = hash_map.get(&hash)?;
    let paid_amount = tx.get_payment_amount_to(request.btc_address)?;
    if paid_amount as u128 >= request.amount {
        Some(request.clone())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bitcoin::{
        Block, BlockHash, Error as BitcoinError, GetBlockResult, GetRawTransactionResult, Network,
        Transaction, TransactionMetadata, Txid,
    };
    use runtime::{AccountId, Error as RuntimeError};
    use sp_core::H160;

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

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait RedeemPallet {
            async fn get_redeem_request(&self, redeem_id: H256) -> Result<PolkaBtcRedeemRequest, RuntimeError>;
            async fn request_redeem(
                &self,
                amount_polka_btc: u128,
                btc_address: BtcAddress,
                vault_id: AccountId,
            ) -> Result<H256, RuntimeError>;
            async fn execute_redeem(
                &self,
                redeem_id: H256,
                tx_id: H256Le,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn cancel_redeem(&self, redeem_id: H256, reimburse: bool) -> Result<(), RuntimeError>;
            async fn get_vault_redeem_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcRedeemRequest)>, RuntimeError>;
            async fn set_redeem_period(&self, period: u32) -> Result<(), RuntimeError>;
        }
        #[async_trait]
        pub trait ReplacePallet {
            async fn request_replace(&self, amount: u128, griefing_collateral: u128)
                -> Result<H256, RuntimeError>;
            async fn withdraw_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn accept_replace(&self, replace_id: H256, collateral: u128) -> Result<(), RuntimeError>;
            async fn auction_replace(
                &self,
                old_vault: AccountId,
                btc_amount: u128,
                collateral: u128,
            ) -> Result<(), RuntimeError>;
            async fn execute_replace(
                &self,
                replace_id: H256,
                tx_id: H256Le,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn cancel_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn get_new_vault_replace_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, RuntimeError>;
            async fn get_old_vault_replace_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, RuntimeError>;
            async fn get_replace_period(&self) -> Result<u32, RuntimeError>;
            async fn set_replace_period(&self, period: u32) -> Result<(), RuntimeError>;
            async fn get_replace_request(&self, replace_id: H256) -> Result<PolkaBtcReplaceRequest, RuntimeError>;
        }
    }

    mockall::mock! {
        Bitcoin {}

        #[async_trait]
        pub trait BitcoinCoreApi {
            async fn wait_for_block(&self, height: u32, delay: Duration) -> Result<BlockHash, BitcoinError>;
            fn get_block_count(&self) -> Result<u64, BitcoinError>;
            fn get_block_transactions(
                &self,
                hash: &BlockHash,
            ) -> Result<Vec<Option<GetRawTransactionResult>>, BitcoinError>;
            fn get_raw_tx_for(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, BitcoinError>;
            fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, BitcoinError>;
            fn get_new_address<A: PartialAddress + 'static>(&self) -> Result<A, BitcoinError>;
            fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinError>;
            fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinError>;
            fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, BitcoinError>;
            fn get_mempool_transactions<'a>(
                self: Arc<Self>,
            ) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + 'a>, BitcoinError>;
            async fn wait_for_transaction_metadata(
                &self,
                txid: Txid,
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
            async fn send_transaction<A: PartialAddress + 'static>(
                &self,
                address: String,
                sat: u64,
                redeem_id: &[u8; 32],
            ) -> Result<Txid, BitcoinError>;
            async fn send_to_address<A: PartialAddress + 'static>(
                &self,
                address: String,
                sat: u64,
                redeem_id: &[u8; 32],
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
            fn create_wallet(&self, wallet: &str) -> Result<(), BitcoinError>;
        }
    }

    fn dummy_transaction_metadata() -> TransactionMetadata {
        TransactionMetadata {
            block_hash: Default::default(),
            block_height: Default::default(),
            proof: Default::default(),
            raw_tx: Default::default(),
            txid: Default::default(),
        }
    }
    #[tokio::test]
    async fn test_pay_and_execute_redeem_succeeds() {
        let mut provider = MockProvider::default();
        let mut btc_rpc = MockBitcoin::default();
        btc_rpc
            .expect_send_to_address::<BtcAddress>()
            .times(1) // checks that this function is not retried
            .returning(|_, _, _, _, _| Ok(dummy_transaction_metadata()));

        provider
            .expect_execute_redeem()
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let request = Request {
            amount: 100,
            btc_address: BtcAddress::P2SH(H160::from_slice(&[1; 20])),
            hash: H256::from_slice(&[1; 32]),
            open_time: None,
            request_type: RequestType::Redeem,
        };

        assert_ok!(
            request
                .pay_and_execute(Arc::new(provider), Arc::new(btc_rpc), 6, Network::Regtest)
                .await
        );
    }

    #[tokio::test]
    async fn test_pay_and_execute_replace_succeeds() {
        let mut provider = MockProvider::default();
        let mut btc_rpc = MockBitcoin::default();
        btc_rpc
            .expect_send_to_address::<BtcAddress>()
            .times(1) // checks that this function is not retried
            .returning(|_, _, _, _, _| Ok(dummy_transaction_metadata()));

        provider
            .expect_execute_replace()
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let request = Request {
            amount: 100,
            btc_address: BtcAddress::P2SH(H160::from_slice(&[1; 20])),
            hash: H256::from_slice(&[1; 32]),
            open_time: None,
            request_type: RequestType::Replace,
        };

        assert_ok!(
            request
                .pay_and_execute(Arc::new(provider), Arc::new(btc_rpc), 6, Network::Regtest)
                .await
        );
    }

    #[tokio::test]
    async fn test_pay_and_execute_no_bitcoin_retry() {
        let provider = MockProvider::default();
        let mut btc_rpc = MockBitcoin::default();
        btc_rpc
            .expect_send_to_address::<BtcAddress>()
            .times(1) // checks that this function is not retried
            .returning(|_, _, _, _, _| Err(BitcoinError::ConfirmationError));

        let request = Request {
            amount: 100,
            btc_address: BtcAddress::P2SH(H160::from_slice(&[1; 20])),
            hash: H256::from_slice(&[1; 32]),
            open_time: None,
            request_type: RequestType::Replace,
        };

        assert_err!(
            request
                .pay_and_execute(Arc::new(provider), Arc::new(btc_rpc), 6, Network::Regtest)
                .await,
            Error::BitcoinError(BitcoinError::ConfirmationError)
        );
    }
}