use crate::{error::Error, retry::*, BITCOIN_MAX_RETRYING_TIME};
use bitcoin::{BitcoinCoreApi, Transaction, TransactionExt, TransactionMetadata};
use futures::{future, stream::StreamExt};
use runtime::{
    pallets::{
        redeem::RequestRedeemEvent,
        refund::RequestRefundEvent,
        replace::{AcceptReplaceEvent, AuctionReplaceEvent},
    },
    BtcAddress, BtcRelayPallet, Error as RuntimeError, H256Le, PolkaBtcProvider, PolkaBtcRedeemRequest,
    PolkaBtcRefundRequest, PolkaBtcReplaceRequest, PolkaBtcRuntime, RedeemPallet, RedeemRequestStatus, RefundPallet,
    ReplacePallet, ReplaceRequestStatus, UtilFuncs, VaultRegistryPallet,
};
use sp_core::H256;
use std::collections::HashMap;

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
    Refund,
}

impl Request {
    /// Constructs a Request for the given PolkaBtcRedeemRequest
    fn from_redeem_request(hash: H256, request: PolkaBtcRedeemRequest) -> Request {
        Request {
            hash,
            open_time: Some(request.opentime),
            amount: request.amount_btc,
            btc_address: request.btc_address,
            request_type: RequestType::Redeem,
        }
    }

    /// Constructs a Request for the given PolkaBtcReplaceRequest
    fn from_replace_request(hash: H256, request: PolkaBtcReplaceRequest) -> Request {
        Request {
            hash,
            open_time: Some(request.accept_time),
            amount: request.amount,
            btc_address: request.btc_address,
            request_type: RequestType::Replace,
        }
    }

    /// Constructs a Request for the given PolkaBtcRefundRequest
    fn from_refund_request(hash: H256, request: PolkaBtcRefundRequest) -> Request {
        Request {
            hash,
            open_time: None,
            amount: request.amount_btc,
            btc_address: request.btc_address,
            request_type: RequestType::Refund,
        }
    }

    /// Constructs a Request for the given RequestRefundEvent
    pub fn from_refund_request_event(request: &RequestRefundEvent<PolkaBtcRuntime>) -> Request {
        Request {
            btc_address: request.btc_address,
            amount: request.amount_polka_btc,
            hash: request.refund_id,
            open_time: None,
            request_type: RequestType::Refund,
        }
    }

    /// Constructs a Request for the given AcceptReplaceEvent
    pub fn from_accept_replace_event(request: &AcceptReplaceEvent<PolkaBtcRuntime>) -> Request {
        Request {
            btc_address: request.btc_address,
            amount: request.amount_btc,
            hash: request.replace_id,
            open_time: None,
            request_type: RequestType::Replace,
        }
    }

    /// Constructs a Request for the given AuctionReplaceEvent
    pub fn from_auction_replace_event(request: &AuctionReplaceEvent<PolkaBtcRuntime>) -> Request {
        Request {
            btc_address: request.btc_address,
            amount: request.btc_amount,
            hash: request.replace_id,
            open_time: None,
            request_type: RequestType::Replace,
        }
    }

    /// Constructs a Request for the given RequestRedeemEvent
    pub fn from_redeem_request_event(request: &RequestRedeemEvent<PolkaBtcRuntime>) -> Request {
        Request {
            btc_address: request.user_btc_address,
            amount: request.amount_polka_btc,
            hash: request.redeem_id,
            open_time: None,
            request_type: RequestType::Redeem,
        }
    }

    /// Makes the bitcoin transfer and executes the request
    pub async fn pay_and_execute<
        B: BitcoinCoreApi + Clone,
        P: ReplacePallet + RefundPallet + RedeemPallet + VaultRegistryPallet + UtilFuncs + Clone + Send + Sync,
    >(
        &self,
        provider: P,
        btc_rpc: B,
        num_confirmations: u32,
    ) -> Result<(), Error> {
        let tx_metadata = self.transfer_btc(&provider, btc_rpc, num_confirmations).await?;
        self.execute(provider, tx_metadata).await
    }

    /// Make a bitcoin transfer to fulfil the request
    async fn transfer_btc<B: BitcoinCoreApi + Clone, P: VaultRegistryPallet + UtilFuncs + Clone + Send + Sync>(
        &self,
        provider: &P,
        btc_rpc: B,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error> {
        tracing::info!("Sending bitcoin to {}", self.btc_address);

        let tx = btc_rpc
            .create_transaction(self.btc_address, self.amount as u64, Some(self.hash))
            .await?;

        let return_to_self_addresses = tx
            .transaction
            .extract_output_addresses()
            .into_iter()
            .filter(|x| x != &self.btc_address)
            .collect::<Vec<_>>();

        // register return-to-self address if it exists
        match return_to_self_addresses.as_slice() {
            [] => {} // no return-to-self
            [address] => {
                // one return-to-self address, make sure it is registered
                let vault_id = provider.get_account_id().clone();
                let wallet = provider.get_vault(vault_id).await?.wallet;
                if !wallet.has_btc_address(&address) {
                    tracing::info!("Registering address {}", address);
                    // retry address registration if tx was outdated
                    notify_retry(
                        || provider.register_address(*address),
                        |result| match result {
                            Ok(ok) => Ok(ok),
                            Err(err @ RuntimeError::OutdatedTransaction) => Err(RetryPolicy::Skip(err)),
                            Err(err) => Err(RetryPolicy::Throw(err)),
                        },
                    )
                    .await?;
                }
            }
            _ => return Err(Error::TooManyReturnToSelfAddresses),
        };

        let txid = btc_rpc.send_transaction(tx).await?;
        let tx_metadata = btc_rpc
            .wait_for_transaction_metadata(txid, BITCOIN_MAX_RETRYING_TIME, num_confirmations)
            .await?;

        tracing::info!("Bitcoin successfully sent to {}", self.btc_address);
        Ok(tx_metadata)
    }

    /// Executes the request. Upon failure it will retry
    async fn execute<P: ReplacePallet + RedeemPallet + RefundPallet>(
        &self,
        provider: P,
        tx_metadata: TransactionMetadata,
    ) -> Result<(), Error> {
        // select the execute function based on request_type
        let execute = match self.request_type {
            RequestType::Redeem => RedeemPallet::execute_redeem,
            RequestType::Replace => ReplacePallet::execute_replace,
            RequestType::Refund => RefundPallet::execute_refund,
        };

        // Retry until success or timeout
        notify_retry_all(|| {
            (execute)(
                &provider,
                self.hash,
                tx_metadata.proof.clone(),
                tx_metadata.raw_tx.clone(),
            )
        })
        .await?;

        Ok(())
    }
}

/// Queries the parachain for open requests and executes them. It checks the
/// bitcoin blockchain to see if a payment has already been made.
pub async fn execute_open_requests<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    provider: PolkaBtcProvider,
    btc_rpc: B,
    num_confirmations: u32,
) -> Result<(), Error> {
    let vault_id = provider.get_account_id().clone();

    // get all redeem, replace and refund requests
    let (redeem_requests, replace_requests, refund_requests) = future::try_join3(
        provider.get_vault_redeem_requests(vault_id.clone()),
        provider.get_old_vault_replace_requests(vault_id.clone()),
        provider.get_vault_refund_requests(vault_id),
    )
    .await?;

    let open_redeems = redeem_requests
        .into_iter()
        .filter(|(_, request)| request.status == RedeemRequestStatus::Pending)
        .map(|(hash, request)| Request::from_redeem_request(hash, request));

    let open_replaces = replace_requests
        .into_iter()
        .filter(|(_, request)| request.status == ReplaceRequestStatus::Pending)
        .map(|(hash, request)| Request::from_replace_request(hash, request));

    let open_refunds = refund_requests
        .into_iter()
        .filter(|(_, request)| !request.completed)
        .map(|(hash, request)| Request::from_refund_request(hash, request));

    // collect all requests into a hashmap, indexed by their id
    let mut open_requests = open_redeems
        .chain(open_replaces)
        .chain(open_refunds)
        .map(|x| (x.hash, x))
        .collect::<HashMap<_, _>>();

    // find the height of bitcoin chain corresponding to the earliest open_time
    let btc_start_height = match open_requests
        .iter()
        .map(|(_, request)| request.open_time.unwrap_or(u32::MAX))
        .min()
    {
        Some(x) => provider.get_blockchain_height_at(x).await?,
        None => return Ok(()), // the iterator is empty so we have nothing to do
    };

    // iterate through transactions in reverse order, starting from those in the mempool
    let mut transaction_stream = bitcoin::reverse_stream_transactions(&btc_rpc, btc_start_height).await?;
    while let Some(result) = transaction_stream.next().await {
        let tx = result?;

        // get the request this transaction corresponds to, if any
        if let Some(request) = get_request_for_btc_tx(&tx, &open_requests) {
            // remove request from the hashmap
            open_requests.retain(|&key, _| key != request.hash);

            tracing::info!(
                "{:?} request #{} has valid bitcoin payment - processing...",
                request.request_type,
                request.hash
            );

            // start a new task to (potentially) await confirmation and to execute on the parachain
            // make copies of the variables we move into the task
            let provider = provider.clone();
            let btc_rpc = btc_rpc.clone();
            tokio::spawn(async move {
                // Payment has been made, but it might not have been confirmed enough times yet
                let tx_metadata = btc_rpc
                    .clone()
                    .wait_for_transaction_metadata(tx.txid(), BITCOIN_MAX_RETRYING_TIME, num_confirmations)
                    .await;

                match tx_metadata {
                    Ok(tx_metadata) => {
                        // we have enough btc confirmations, now make sure they have been relayed before we continue
                        if let Err(e) = provider
                            .wait_for_block_in_relay(
                                H256Le::from_bytes_le(&tx_metadata.block_hash.to_vec()),
                                Some(num_confirmations),
                            )
                            .await
                        {
                            tracing::error!(
                                "Error while waiting for block inclusion for request #{}: {}",
                                request.hash,
                                e
                            );
                            // continue; try to execute anyway
                        }

                        match request.execute(provider.clone(), tx_metadata).await {
                            Ok(_) => {
                                tracing::info!("Executed request #{}", request.hash);
                            }
                            Err(e) => tracing::error!("Failed to execute request #{}: {}", request.hash, e),
                        }
                    }
                    Err(e) => tracing::error!(
                        "Failed to confirm bitcoin transaction for request {}: {}",
                        request.hash,
                        e
                    ),
                }
            });
        }
    }

    // All requests remaining in the hashmap did not have a bitcoin payment yet, so pay
    // and execute all of these
    for (_, request) in open_requests {
        // there are potentially a large number of open requests - pay and execute each
        // in a separate task to ensure that awaiting confirmations does not significantly
        // delay other requests
        // make copies of the variables we move into the task
        let provider = provider.clone();
        let btc_rpc = btc_rpc.clone();
        tokio::spawn(async move {
            tracing::info!(
                "{:?} request #{} found without bitcoin payment - processing...",
                request.request_type,
                request.hash
            );

            match request.pay_and_execute(provider, btc_rpc, num_confirmations).await {
                Ok(_) => tracing::info!(
                    "{:?} request #{} successfully executed",
                    request.request_type,
                    request.hash
                ),
                Err(e) => tracing::info!(
                    "{:?} request #{} failed to process: {}",
                    request.request_type,
                    request.hash,
                    e
                ),
            }
        });
    }

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
        Block, BlockHash, BlockHeader, Error as BitcoinError, GetBlockResult, LockedTransaction, PartialAddress,
        PrivateKey, Transaction, TransactionMetadata, Txid, PUBLIC_KEY_SIZE,
    };
    use runtime::{AccountId, BlockNumber, BtcPublicKey, Error as RuntimeError, PolkaBtcVault};
    use sp_core::H160;
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

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait UtilFuncs {
            async fn get_current_chain_height(&self) -> Result<u32, RuntimeError>;
            async fn get_blockchain_height_at(&self, parachain_height: u32) -> Result<u32, RuntimeError>;
            fn get_account_id(&self) -> &AccountId;
        }

        #[async_trait]
        pub trait VaultRegistryPallet {
            async fn get_vault(&self, vault_id: AccountId) -> Result<PolkaBtcVault, RuntimeError>;
            async fn get_all_vaults(&self) -> Result<Vec<PolkaBtcVault>, RuntimeError>;
            async fn register_vault(&self, collateral: u128, public_key: BtcPublicKey) -> Result<(), RuntimeError>;
            async fn lock_additional_collateral(&self, amount: u128) -> Result<(), RuntimeError>;
            async fn withdraw_collateral(&self, amount: u128) -> Result<(), RuntimeError>;
            async fn update_public_key(&self, public_key: BtcPublicKey) -> Result<(), RuntimeError>;
            async fn register_address(&self, btc_address: BtcAddress) -> Result<(), RuntimeError>;
            async fn get_required_collateral_for_polkabtc(&self, amount_btc: u128) -> Result<u128, RuntimeError>;
            async fn get_required_collateral_for_vault(&self, vault_id: AccountId) -> Result<u128, RuntimeError>;
            async fn is_vault_below_auction_threshold(&self, vault_id: AccountId) -> Result<bool, RuntimeError>;
        }

        #[async_trait]
        pub trait RedeemPallet {
            async fn request_redeem(
                &self,
                amount_polka_btc: u128,
                btc_address: BtcAddress,
                vault_id: AccountId,
            ) -> Result<H256, RuntimeError>;
            async fn execute_redeem(
                &self,
                redeem_id: H256,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn cancel_redeem(&self, redeem_id: H256, reimburse: bool) -> Result<(), RuntimeError>;
            async fn get_redeem_request(&self, redeem_id: H256) -> Result<PolkaBtcRedeemRequest, RuntimeError>;
            async fn get_vault_redeem_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcRedeemRequest)>, RuntimeError>;
            async fn get_redeem_period(&self) -> Result<BlockNumber, RuntimeError>;
            async fn set_redeem_period(&self, period: u32) -> Result<(), RuntimeError>;
        }

        #[async_trait]
        pub trait ReplacePallet {
            async fn request_replace(&self, amount: u128, griefing_collateral: u128) -> Result<(), RuntimeError>;
            async fn withdraw_replace(&self, amount: u128) -> Result<(), RuntimeError>;
            async fn accept_replace(
                &self,
                old_vault: AccountId,
                amount_btc: u128,
                collateral: u128,
                btc_address: BtcAddress,
            ) -> Result<(), RuntimeError>;
            async fn auction_replace(
                &self,
                old_vault: AccountId,
                btc_amount: u128,
                collateral: u128,
                btc_address: BtcAddress,
            ) -> Result<(), RuntimeError>;
            async fn execute_replace(
                &self,
                replace_id: H256,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn cancel_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn get_replace_request(&self, replace_id: H256) -> Result<PolkaBtcReplaceRequest, RuntimeError>;
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
            async fn get_replace_dust_amount(&self) -> Result<u128, RuntimeError>;
        }

        #[async_trait]
        pub trait RefundPallet {
            async fn execute_refund(
                &self,
                refund_id: H256,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn get_vault_refund_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcRefundRequest)>, RuntimeError>;
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
            async fn wait_for_block(&self, height: u32, num_confirmations: u32) -> Result<Block, BitcoinError>;
            async fn get_block_count(&self) -> Result<u64, BitcoinError>;
            async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
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
            async fn create_or_load_wallet(&self) -> Result<(), BitcoinError>;
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
    async fn should_pay_and_execute_redeem() {
        let mut provider = MockProvider::default();
        provider.expect_execute_redeem().times(1).returning(|_, _, _| Ok(()));

        let mut btc_rpc = MockBitcoin::default();
        btc_rpc.expect_create_transaction::<BtcAddress>().returning(|_, _, _| {
            Ok(LockedTransaction::new(
                Transaction {
                    version: 0,
                    lock_time: 0,
                    input: vec![],
                    output: vec![],
                },
                None,
            ))
        });

        btc_rpc.expect_send_transaction().returning(|_| Ok(Txid::default()));

        btc_rpc.expect_wait_for_transaction_metadata().returning(|_, _, _| {
            Ok(TransactionMetadata {
                txid: Txid::default(),
                proof: vec![],
                raw_tx: vec![],
                block_height: 0,
                block_hash: BlockHash::default(),
            })
        });

        let request = Request {
            amount: 100,
            btc_address: BtcAddress::P2SH(H160::from_slice(&[1; 20])),
            hash: H256::from_slice(&[1; 32]),
            open_time: None,
            request_type: RequestType::Redeem,
        };

        assert_ok!(request.pay_and_execute(provider, btc_rpc, 6).await);
    }

    #[tokio::test]
    async fn should_pay_and_execute_replace() {
        let mut provider = MockProvider::default();
        provider.expect_execute_replace().times(1).returning(|_, _, _| Ok(()));

        let mut btc_rpc = MockBitcoin::default();
        btc_rpc.expect_create_transaction::<BtcAddress>().returning(|_, _, _| {
            Ok(LockedTransaction::new(
                Transaction {
                    version: 0,
                    lock_time: 0,
                    input: vec![],
                    output: vec![],
                },
                None,
            ))
        });

        btc_rpc.expect_send_transaction().returning(|_| Ok(Txid::default()));

        btc_rpc.expect_wait_for_transaction_metadata().returning(|_, _, _| {
            Ok(TransactionMetadata {
                txid: Txid::default(),
                proof: vec![],
                raw_tx: vec![],
                block_height: 0,
                block_hash: BlockHash::default(),
            })
        });

        let request = Request {
            amount: 100,
            btc_address: BtcAddress::P2SH(H160::from_slice(&[1; 20])),
            hash: H256::from_slice(&[1; 32]),
            open_time: None,
            request_type: RequestType::Replace,
        };

        assert_ok!(request.pay_and_execute(provider, btc_rpc, 6).await);
    }
}
