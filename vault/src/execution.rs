use crate::{error::Error, metrics::update_bitcoin_metrics, system::VaultData, VaultIdManager};
use bitcoin::{
    BitcoinCoreApi, PartialAddress, Transaction, TransactionExt, TransactionMetadata,
    BLOCK_INTERVAL as BITCOIN_BLOCK_INTERVAL,
};
use futures::{
    stream::{self, StreamExt},
    try_join, TryStreamExt,
};
use runtime::{
    BtcAddress, BtcRelayPallet, H256Le, InterBtcParachain, InterBtcRedeemRequest, InterBtcRefundRequest,
    InterBtcReplaceRequest, IssuePallet, PrettyPrint, RedeemPallet, RedeemRequestStatus, RefundPallet, ReplacePallet,
    ReplaceRequestStatus, RequestRefundEvent, SecurityPallet, UtilFuncs, VaultId, VaultRegistryPallet, H256,
};
use service::{spawn_cancelable, ShutdownSender};
use std::{collections::HashMap, convert::TryInto, time::Duration};
use tokio::time::sleep;

const ON_FORK_RETRY_DELAY: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq)]
struct Deadline {
    parachain: u32,
    bitcoin: u32,
}

#[derive(Debug, Clone)]
pub struct Request {
    hash: H256,
    btc_height: Option<u32>,
    /// Deadline (unit: active block number) after which payments will no longer be attempted.
    deadline: Option<Deadline>,
    amount: u128,
    btc_address: BtcAddress,
    request_type: RequestType,
    vault_id: VaultId,
    fee_budget: Option<u128>,
}

pub fn parachain_blocks_to_bitcoin_blocks_rounded_up(parachain_blocks: u32) -> Result<u32, Error> {
    let millis = (parachain_blocks as u64)
        .checked_mul(runtime::MILLISECS_PER_BLOCK)
        .ok_or(Error::ArithmeticOverflow)?;

    let denominator = BITCOIN_BLOCK_INTERVAL.as_millis();

    // do -num_bitcoin_blocks = ceil(millis / demoninator)
    let num_bitcoin_blocks = (millis as u128)
        .checked_add(denominator)
        .ok_or(Error::ArithmeticOverflow)?
        .checked_sub(1)
        .ok_or(Error::ArithmeticUnderflow)?
        .checked_div(denominator)
        .ok_or(Error::ArithmeticUnderflow)?;

    Ok(num_bitcoin_blocks.try_into()?)
}

#[derive(Debug, Copy, Clone)]
pub enum RequestType {
    Redeem,
    Replace,
    Refund,
}

impl Request {
    fn duration_to_parachain_blocks(duration: Duration) -> Result<u32, Error> {
        let num_blocks = duration.as_millis() / (runtime::MILLISECS_PER_BLOCK as u128);
        Ok(num_blocks.try_into()?)
    }

    fn calculate_deadline(
        opentime: u32,
        btc_start_height: u32,
        period: u32,
        payment_margin: Duration,
    ) -> Result<Deadline, Error> {
        let margin_parachain_blocks = Self::duration_to_parachain_blocks(payment_margin)?;
        // if margin > period, we allow deadline to be before opentime. The rest of the code
        // can deal with the expired deadline as normal.
        let parachain_deadline = opentime
            .checked_add(period)
            .ok_or(Error::ArithmeticOverflow)?
            .checked_sub(margin_parachain_blocks)
            .ok_or(Error::ArithmeticUnderflow)?;

        let bitcoin_deadline = btc_start_height
            .checked_add(parachain_blocks_to_bitcoin_blocks_rounded_up(period)?)
            .ok_or(Error::ArithmeticOverflow)?
            .checked_sub(parachain_blocks_to_bitcoin_blocks_rounded_up(margin_parachain_blocks)?)
            .ok_or(Error::ArithmeticUnderflow)?;

        Ok(Deadline {
            bitcoin: bitcoin_deadline,
            parachain: parachain_deadline,
        })
    }

    /// Constructs a Request for the given InterBtcRedeemRequest
    pub fn from_redeem_request(
        hash: H256,
        request: InterBtcRedeemRequest,
        payment_margin: Duration,
    ) -> Result<Request, Error> {
        Ok(Request {
            hash,
            deadline: Some(Self::calculate_deadline(
                request.opentime,
                request.btc_height,
                request.period,
                payment_margin,
            )?),
            btc_height: Some(request.btc_height),
            amount: request.amount_btc,
            btc_address: request.btc_address,
            request_type: RequestType::Redeem,
            vault_id: request.vault,
            fee_budget: Some(request.transfer_fee_btc),
        })
    }

    /// Constructs a Request for the given InterBtcReplaceRequest
    pub fn from_replace_request(
        hash: H256,
        request: InterBtcReplaceRequest,
        payment_margin: Duration,
    ) -> Result<Request, Error> {
        Ok(Request {
            hash,
            deadline: Some(Self::calculate_deadline(
                request.accept_time,
                request.btc_height,
                request.period,
                payment_margin,
            )?),
            btc_height: Some(request.btc_height),
            amount: request.amount,
            btc_address: request.btc_address,
            request_type: RequestType::Replace,
            vault_id: request.old_vault,
            fee_budget: None,
        })
    }

    /// Constructs a Request for the given InterBtcRefundRequest
    fn from_refund_request(hash: H256, request: InterBtcRefundRequest, btc_height: u32) -> Request {
        Request {
            hash,
            deadline: None,
            btc_height: Some(btc_height),
            amount: request.amount_btc,
            btc_address: request.btc_address,
            request_type: RequestType::Refund,
            vault_id: request.vault,
            fee_budget: Some(request.transfer_fee_btc),
        }
    }

    /// Constructs a Request for the given RequestRefundEvent
    pub fn from_refund_request_event(request: &RequestRefundEvent) -> Request {
        Request {
            btc_address: request.btc_address,
            amount: request.amount,
            hash: request.refund_id,
            btc_height: None,
            deadline: None,
            request_type: RequestType::Refund,
            vault_id: request.vault_id.clone(),
            fee_budget: None,
        }
    }

    /// Makes the bitcoin transfer and executes the request
    pub async fn pay_and_execute<
        B: BitcoinCoreApi + Clone + Send + Sync + 'static,
        P: ReplacePallet
            + RefundPallet
            + BtcRelayPallet
            + RedeemPallet
            + SecurityPallet
            + VaultRegistryPallet
            + UtilFuncs
            + Clone
            + Send
            + Sync,
    >(
        &self,
        parachain_rpc: P,
        vault: VaultData<B>,
        num_confirmations: u32,
    ) -> Result<(), Error> {
        // ensure the deadline has not expired yet
        if let Some(ref deadline) = self.deadline {
            if parachain_rpc.get_current_active_block_number().await? >= deadline.parachain
                && vault.btc_rpc.get_block_count().await? >= deadline.bitcoin as u64
            {
                return Err(Error::DeadlineExpired);
            }
        }

        let tx_metadata = self
            .transfer_btc(&parachain_rpc, &vault.btc_rpc, num_confirmations, self.vault_id.clone())
            .await?;
        let _ = update_bitcoin_metrics(&vault, tx_metadata.fee, self.fee_budget).await;
        self.execute(parachain_rpc, tx_metadata).await
    }

    /// Make a bitcoin transfer to fulfil the request
    #[tracing::instrument(
        name = "transfer_btc",
        skip(self, parachain_rpc, btc_rpc),
        fields(
            request_type = ?self.request_type,
            request_id = ?self.hash,
        )
    )]
    async fn transfer_btc<
        B: BitcoinCoreApi + Clone,
        P: BtcRelayPallet + VaultRegistryPallet + UtilFuncs + Clone + Send + Sync,
    >(
        &self,
        parachain_rpc: &P,
        btc_rpc: &B,
        num_confirmations: u32,
        vault_id: VaultId,
    ) -> Result<TransactionMetadata, Error> {
        let tx = btc_rpc
            .create_transaction(self.btc_address, self.amount as u64, Some(self.hash))
            .await?;
        let recipient = tx.recipient.clone();
        tracing::info!("Sending bitcoin to {}", recipient);

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
                let wallet = parachain_rpc.get_vault(&vault_id).await?.wallet;
                if !wallet.addresses.contains(address) {
                    let readable_address = address
                        .encode_str(btc_rpc.network())
                        .unwrap_or(format!("{:?}", address));
                    tracing::info!("Registering address {:?}", readable_address);
                    parachain_rpc.register_address(&vault_id, *address).await?;
                    tracing::debug!("Successfully registered address {:?}", readable_address);
                }
            }
            _ => return Err(Error::TooManyReturnToSelfAddresses),
        };

        let txid = btc_rpc.send_transaction(tx).await?;

        loop {
            let tx_metadata = btc_rpc.wait_for_transaction_metadata(txid, num_confirmations).await?;

            tracing::info!("Awaiting parachain confirmations...");

            match parachain_rpc
                .wait_for_block_in_relay(H256Le::from_bytes_le(&tx_metadata.block_hash), Some(num_confirmations))
                .await
            {
                Ok(_) => {
                    tracing::info!("Bitcoin successfully sent and relayed");
                    return Ok(tx_metadata);
                }
                Err(e) if e.is_invalid_chain_id() => {
                    // small delay to prevent spamming
                    sleep(ON_FORK_RETRY_DELAY).await;
                    // re-fetch the metadata - it might be in a different block now
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Executes the request. Upon failure it will retry
    async fn execute<P: ReplacePallet + RedeemPallet + RefundPallet>(
        &self,
        parachain_rpc: P,
        tx_metadata: TransactionMetadata,
    ) -> Result<(), Error> {
        // select the execute function based on request_type
        let execute = match self.request_type {
            RequestType::Redeem => RedeemPallet::execute_redeem,
            RequestType::Replace => ReplacePallet::execute_replace,
            RequestType::Refund => RefundPallet::execute_refund,
        };

        match (self.fee_budget, tx_metadata.fee.map(|x| x.abs().as_sat() as u128)) {
            (Some(budget), Some(actual)) if budget < actual => {
                tracing::warn!(
                    "Spent more on bitcoin inclusion fee than budgeted: spent {} satoshi; budget was {}",
                    actual,
                    budget
                );
            }
            _ => {}
        }

        // Retry until success or timeout, explicitly handle the cases
        // where the redeem has expired or the rpc has disconnected
        runtime::notify_retry(
            || (execute)(&parachain_rpc, self.hash, &tx_metadata.proof, &tx_metadata.raw_tx),
            |result| async {
                match result {
                    Ok(ok) => Ok(ok),
                    Err(err) if err.is_rpc_disconnect_error() => Err(runtime::RetryPolicy::Throw(err)),
                    Err(err) if err.is_invalid_chain_id() => Err(runtime::RetryPolicy::Throw(err)),
                    Err(err) => Err(runtime::RetryPolicy::Skip(err)),
                }
            },
        )
        .await?;

        Ok(())
    }
}

/// Queries the parachain for open requests and executes them. It checks the
/// bitcoin blockchain to see if a payment has already been made.
pub async fn execute_open_requests<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    shutdown_tx: ShutdownSender,
    parachain_rpc: InterBtcParachain,
    vault_id_manager: VaultIdManager<B>,
    read_only_btc_rpc: B,
    num_confirmations: u32,
    payment_margin: Duration,
    process_refunds: bool,
) -> Result<(), Error> {
    let parachain_rpc = &parachain_rpc;
    let vault_id = parachain_rpc.get_account_id().clone();

    // get all redeem, replace and refund requests
    let (redeem_requests, replace_requests, refund_requests) = try_join!(
        parachain_rpc.get_vault_redeem_requests(vault_id.clone()),
        parachain_rpc.get_old_vault_replace_requests(vault_id.clone()),
        async {
            if process_refunds {
                // for refunds, we use the btc_height of the issue
                let refunds = parachain_rpc.get_vault_refund_requests(vault_id).await?;
                stream::iter(refunds)
                    .then(|(refund_id, refund)| async move {
                        Ok((
                            refund_id,
                            refund.clone(),
                            parachain_rpc.get_issue_request(refund.issue_id).await?.btc_height,
                        ))
                    })
                    .try_collect()
                    .await
            } else {
                Ok(Vec::new())
            }
        },
    )?;

    let open_redeems = redeem_requests
        .into_iter()
        .filter(|(_, request)| request.status == RedeemRequestStatus::Pending)
        .filter_map(|(hash, request)| Request::from_redeem_request(hash, request, payment_margin).ok());

    let open_replaces = replace_requests
        .into_iter()
        .filter(|(_, request)| request.status == ReplaceRequestStatus::Pending)
        .filter_map(|(hash, request)| Request::from_replace_request(hash, request, payment_margin).ok());

    let open_refunds = refund_requests
        .into_iter()
        .filter(|(_, request, _)| !request.completed)
        .map(|(hash, request, btc_height)| Request::from_refund_request(hash, request, btc_height));

    // collect all requests into a hashmap, indexed by their id
    let mut open_requests = open_redeems
        .chain(open_replaces)
        .chain(open_refunds)
        .map(|x| (x.hash, x))
        .collect::<HashMap<_, _>>();

    // find the height of bitcoin chain corresponding to the earliest btc_height
    let btc_start_height = match open_requests
        .iter()
        .map(|(_, request)| request.btc_height.unwrap_or(u32::MAX))
        .min()
    {
        Some(x) => x,
        None => return Ok(()), // the iterator is empty so we have nothing to do
    };

    // iterate through transactions in reverse order, starting from those in the mempool
    let mut transaction_stream = bitcoin::reverse_stream_transactions(&read_only_btc_rpc, btc_start_height).await?;
    while let Some(result) = transaction_stream.next().await {
        let tx = match result {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("Failed to process transaction: {}", e);
                continue;
            }
        };

        // get the request this transaction corresponds to, if any
        if let Some(request) = get_request_for_btc_tx(&tx, &open_requests) {
            // remove request from the hashmap
            open_requests.retain(|&key, _| key != request.hash);

            tracing::info!(
                "{:?} request #{:?} has valid bitcoin payment - processing...",
                request.request_type,
                request.hash
            );

            // start a new task to (potentially) await confirmation and to execute on the parachain
            // make copies of the variables we move into the task
            let parachain_rpc = parachain_rpc.clone();
            let btc_rpc = vault_id_manager.clone();
            spawn_cancelable(shutdown_tx.subscribe(), async move {
                let btc_rpc = match btc_rpc.get_bitcoin_rpc(&request.vault_id).await {
                    Some(x) => x,
                    None => {
                        tracing::error!(
                            "Failed to fetch bitcoin rpc for vault {}",
                            request.vault_id.pretty_print()
                        );
                        return; // nothing we can do - bail
                    }
                };

                // Payment has been made, but it might not have been confirmed enough times yet
                let tx_metadata = btc_rpc
                    .clone()
                    .wait_for_transaction_metadata(tx.txid(), num_confirmations)
                    .await;

                match tx_metadata {
                    Ok(tx_metadata) => {
                        // we have enough btc confirmations, now make sure they have been relayed before we continue
                        if let Err(e) = parachain_rpc
                            .wait_for_block_in_relay(
                                H256Le::from_bytes_le(&tx_metadata.block_hash),
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

                        match request.execute(parachain_rpc.clone(), tx_metadata).await {
                            Ok(_) => {
                                tracing::info!("Executed request #{:?}", request.hash);
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
        let parachain_rpc = parachain_rpc.clone();
        let vault_id_manager = vault_id_manager.clone();
        spawn_cancelable(shutdown_tx.subscribe(), async move {
            let vault = match vault_id_manager.get_vault(&request.vault_id).await {
                Some(x) => x,
                None => {
                    tracing::error!(
                        "Failed to fetch bitcoin rpc for vault {}",
                        request.vault_id.pretty_print()
                    );
                    return; // nothing we can do - bail
                }
            };

            tracing::info!(
                "{:?} request #{:?} found without bitcoin payment - processing...",
                request.request_type,
                request.hash
            );

            match request.pay_and_execute(parachain_rpc, vault, num_confirmations).await {
                Ok(_) => tracing::info!(
                    "{:?} request #{:?} successfully executed",
                    request.request_type,
                    request.hash
                ),
                Err(e) => tracing::info!(
                    "{:?} request #{:?} failed to process: {}",
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

#[cfg(all(test, feature = "standalone-metadata"))]
mod tests {
    use crate::metrics::PerCurrencyMetrics;

    use super::*;
    use async_trait::async_trait;
    use bitcoin::{
        json, Amount, Block, BlockHash, BlockHeader, Error as BitcoinError, GetBlockResult, LockedTransaction, Network,
        PartialAddress, PrivateKey, Transaction, TransactionMetadata, Txid, PUBLIC_KEY_SIZE,
    };
    use jsonrpc_core::serde_json::{Map, Value};
    use runtime::{
        AccountId, BlockNumber, BtcPublicKey, CurrencyId, Error as RuntimeError, ErrorCode, InterBtcRichBlockHeader,
        InterBtcVault, StatusCode, Token, DOT, IBTC,
    };
    use sp_core::H160;
    use std::collections::BTreeSet;

    macro_rules! assert_ok {
        ( $x:expr $(,)? ) => {
            let is = $x;
            match is {
                Ok(_) => (),
                _ => assert!(false, "Expected Ok(_). Got {:#?}", is),
            }
        };
        ( $x:expr, $y:expr $(,)? ) => {
            assert_eq!($x.unwrap(), $y);
        };
    }

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait UtilFuncs {
            async fn get_current_chain_height(&self) -> Result<u32, RuntimeError>;
            async fn get_rpc_properties(&self) -> Result<Map<String, Value>, RuntimeError>;
            fn get_native_currency_id(&self) -> CurrencyId;
            fn get_account_id(&self) -> &AccountId;
            fn is_this_vault(&self, vault_id: &VaultId) -> bool;
        }
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
            async fn get_required_collateral_for_wrapped(&self, amount_btc: u128, collateral_currency: CurrencyId) -> Result<u128, RuntimeError>;
            async fn get_required_collateral_for_vault(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
            async fn get_vault_total_collateral(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
            async fn get_collateralization_from_vault(&self, vault_id: VaultId, only_issued: bool) -> Result<u128, RuntimeError>;
        }

        #[async_trait]
        pub trait RedeemPallet {
            async fn request_redeem(&self, amount: u128, btc_address: BtcAddress, vault_id: &VaultId) -> Result<H256, RuntimeError>;
            async fn execute_redeem(&self, redeem_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), RuntimeError>;
            async fn cancel_redeem(&self, redeem_id: H256, reimburse: bool) -> Result<(), RuntimeError>;
            async fn get_redeem_request(&self, redeem_id: H256) -> Result<InterBtcRedeemRequest, RuntimeError>;
            async fn get_vault_redeem_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcRedeemRequest)>, RuntimeError>;
            async fn get_redeem_period(&self) -> Result<BlockNumber, RuntimeError>;
        }

        #[async_trait]
        pub trait ReplacePallet {
            async fn request_replace(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
            async fn withdraw_replace(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
            async fn accept_replace(&self, new_vault: &VaultId, old_vault: &VaultId, amount_btc: u128, collateral: u128, btc_address: BtcAddress) -> Result<(), RuntimeError>;
            async fn execute_replace(&self, replace_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), RuntimeError>;
            async fn cancel_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn get_new_vault_replace_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcReplaceRequest)>, RuntimeError>;
            async fn get_old_vault_replace_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcReplaceRequest)>, RuntimeError>;
            async fn get_replace_period(&self) -> Result<u32, RuntimeError>;
            async fn get_replace_request(&self, replace_id: H256) -> Result<InterBtcReplaceRequest, RuntimeError>;
            async fn get_replace_dust_amount(&self) -> Result<u128, RuntimeError>;
        }


        #[async_trait]
        pub trait RefundPallet {
            async fn execute_refund(&self, refund_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), RuntimeError>;
            async fn get_refund_request(&self, refund_id: H256) -> Result<InterBtcRefundRequest, RuntimeError>;
            async fn get_vault_refund_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcRefundRequest)>, RuntimeError>;
        }

        #[async_trait]
        pub trait BtcRelayPallet {
            async fn get_best_block(&self) -> Result<H256Le, RuntimeError>;
            async fn get_best_block_height(&self) -> Result<u32, RuntimeError>;
            async fn get_block_hash(&self, height: u32) -> Result<H256Le, RuntimeError>;
            async fn get_block_header(&self, hash: H256Le) -> Result<InterBtcRichBlockHeader, RuntimeError>;
            async fn get_bitcoin_confirmations(&self) -> Result<u32, RuntimeError>;
            async fn get_parachain_confirmations(&self) -> Result<BlockNumber, RuntimeError>;
            async fn wait_for_block_in_relay(&self, block_hash: H256Le, btc_confirmations: Option<BlockNumber>) -> Result<(), RuntimeError>;
            async fn verify_block_header_inclusion(&self, block_hash: H256Le) -> Result<(), RuntimeError>;
        }

        #[async_trait]
        pub trait SecurityPallet {
            async fn get_parachain_status(&self) -> Result<StatusCode, RuntimeError>;
            async fn get_error_codes(&self) -> Result<BTreeSet<ErrorCode>, RuntimeError>;
            async fn get_current_active_block_number(&self) -> Result<u32, RuntimeError>;
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
            async fn add_new_deposit_key<P: Into<[u8; PUBLIC_KEY_SIZE]> + Send + Sync + 'static>(&self, public_key: P, secret_key: Vec<u8>) -> Result<(), BitcoinError>;
            async fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinError>;
            async fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinError>;
            async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, BitcoinError>;
            async fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, BitcoinError>;
            async fn get_mempool_transactions<'a>(&'a self) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send + 'a>, BitcoinError>;
            async fn wait_for_transaction_metadata(&self, txid: Txid, num_confirmations: u32) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_transaction<A: PartialAddress + Send + Sync + 'static>(&self, address: A, sat: u64, request_id: Option<H256>) -> Result<LockedTransaction, BitcoinError>;
            async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, BitcoinError>;
            async fn create_and_send_transaction<A: PartialAddress + Send + Sync + 'static>(&self, address: A, sat: u64, request_id: Option<H256>) -> Result<Txid, BitcoinError>;
            async fn send_to_address<A: PartialAddress + Send + Sync + 'static>(&self, address: A, sat: u64, request_id: Option<H256>, num_confirmations: u32) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_or_load_wallet(&self) -> Result<(), BitcoinError>;
            async fn wallet_has_public_key<P>(&self, public_key: P) -> Result<bool, BitcoinError> where P: Into<[u8; PUBLIC_KEY_SIZE]> + From<[u8; PUBLIC_KEY_SIZE]> + Clone + PartialEq + Send + Sync + 'static;
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

    macro_rules! assert_err {
        ($result:expr, $err:pat) => {{
            match $result {
                Err($err) => (),
                Ok(v) => panic!("assertion failed: Ok({:?})", v),
                _ => panic!("expected: Err($err)"),
            }
        }};
    }

    fn dummy_vault_id() -> VaultId {
        VaultId::new(AccountId::new([1u8; 32]), Token(DOT), Token(IBTC))
    }

    #[test]
    fn calculate_deadline_behavior() {
        let margin = Duration::from_secs(60 * 60); // 1 hour
        let parachain_blocks = margin.as_millis() as u32 / (runtime::MILLISECS_PER_BLOCK as u32);
        let bitcoin_blocks = parachain_blocks / 50;

        assert_ok!(
            Request::calculate_deadline(0, 0, 3 * parachain_blocks, margin),
            Deadline {
                parachain: 2 * parachain_blocks,
                bitcoin: 2 * bitcoin_blocks
            }
        );

        assert_ok!(
            Request::calculate_deadline(100, 50, 3 * parachain_blocks, margin),
            Deadline {
                parachain: 100 + 2 * parachain_blocks,
                bitcoin: 50 + 2 * bitcoin_blocks
            }
        );

        // if margin > period, deadline will be before opentime. The rest of the code will deal with the expired
        // deadline as normal.
        assert_ok!(
            Request::calculate_deadline(10_000, 10_000, 0, margin),
            Deadline {
                parachain: 10_000 - parachain_blocks,
                bitcoin: 10_000 - bitcoin_blocks
            }
        );

        // if margin > period + opentime, the result would be negative, so we expect an error.
        assert_err!(Request::calculate_deadline(0, 0, 0, margin), Error::ArithmeticUnderflow);
    }

    mod pay_and_execute_redeem_tests {
        use crate::metrics::PerCurrencyMetrics;

        use super::*;

        fn should_pay_and_execute_with_deadlines(
            parachain_deadline: u32,
            current_parachain_height: u32,
            bitcoin_deadline: u32,
            current_bitcoin_height: u32,
        ) -> (Request, MockProvider, VaultData<MockBitcoin>) {
            let mut parachain_rpc = MockProvider::default();
            parachain_rpc
                .expect_get_current_active_block_number()
                .returning(move || Ok(current_parachain_height));
            parachain_rpc.expect_execute_redeem().returning(|_, _, _| Ok(()));
            parachain_rpc.expect_wait_for_block_in_relay().returning(|_, _| Ok(()));

            let mut btc_rpc = MockBitcoin::default();

            btc_rpc
                .expect_get_block_count()
                .returning(move || Ok(current_bitcoin_height as u64));

            btc_rpc.expect_create_transaction::<BtcAddress>().returning(|_, _, _| {
                Ok(LockedTransaction::new(
                    Transaction {
                        version: 0,
                        lock_time: 0,
                        input: vec![],
                        output: vec![],
                    },
                    Default::default(),
                    None,
                ))
            });

            btc_rpc.expect_send_transaction().returning(|_| Ok(Txid::default()));

            btc_rpc.expect_wait_for_transaction_metadata().returning(|_, _| {
                Ok(TransactionMetadata {
                    txid: Txid::default(),
                    proof: vec![],
                    raw_tx: vec![],
                    block_height: 0,
                    block_hash: BlockHash::default(),
                    fee: None,
                })
            });

            btc_rpc.expect_list_transactions().returning(|_| Ok(vec![]));
            btc_rpc.expect_get_balance().returning(|_| Ok(Amount::ZERO));

            let request = Request {
                amount: 100,
                deadline: Some(Deadline {
                    parachain: parachain_deadline,
                    bitcoin: bitcoin_deadline,
                }),
                btc_address: BtcAddress::P2SH(H160::from_slice(&[1; 20])),
                hash: H256::from_slice(&[1; 32]),
                btc_height: None,
                request_type: RequestType::Redeem,
                vault_id: dummy_vault_id(),
                fee_budget: None,
            };

            let vault_data = VaultData {
                vault_id: dummy_vault_id(),
                btc_rpc,
                metrics: PerCurrencyMetrics::dummy(),
            };

            (request, parachain_rpc, vault_data)
        }

        #[tokio::test]
        async fn should_pay_and_execute_redeem_if_neither_parachain_nor_bitcoin_deadlines_expired() {
            let (request, parachain_rpc, btc_rpc) = should_pay_and_execute_with_deadlines(100, 50, 100, 50);

            assert_ok!(request.pay_and_execute(parachain_rpc, btc_rpc, 6).await);
        }

        #[tokio::test]
        async fn should_pay_and_execute_redeem_if_only_parachain_deadline_expired() {
            let (request, parachain_rpc, btc_rpc) = should_pay_and_execute_with_deadlines(100, 101, 100, 50);

            assert_ok!(request.pay_and_execute(parachain_rpc, btc_rpc, 6).await);
        }

        #[tokio::test]
        async fn should_pay_and_execute_redeem_if_only_bitcoin_deadline_expired() {
            let (request, parachain_rpc, btc_rpc) = should_pay_and_execute_with_deadlines(100, 50, 100, 101);

            assert_ok!(request.pay_and_execute(parachain_rpc, btc_rpc, 6).await);
        }

        #[tokio::test]
        async fn should_not_pay_and_execute_redeem_if_both_deadlines_expired() {
            let (request, parachain_rpc, btc_rpc) = should_pay_and_execute_with_deadlines(100, 101, 100, 101);

            assert_err!(
                request.pay_and_execute(parachain_rpc, btc_rpc, 6).await,
                Error::DeadlineExpired
            );
        }
    }

    #[tokio::test]
    async fn should_not_pay_after_expiry() {
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc
            .expect_get_current_active_block_number()
            .times(1)
            .returning(|| Ok(110));
        let mut btc_rpc = MockBitcoin::default();
        btc_rpc.expect_get_block_count().times(1).returning(|| Ok(110));
        // omitting other mocks to test that they do not get called

        let request = Request {
            amount: 100,
            deadline: Some(Deadline {
                parachain: 100,
                bitcoin: 100,
            }),
            btc_address: BtcAddress::P2SH(H160::from_slice(&[1; 20])),
            hash: H256::from_slice(&[1; 32]),
            btc_height: None,
            request_type: RequestType::Redeem,
            vault_id: dummy_vault_id(),
            fee_budget: None,
        };

        let vault_data = VaultData {
            vault_id: dummy_vault_id(),
            btc_rpc,
            metrics: PerCurrencyMetrics::dummy(),
        };

        assert_err!(
            request.pay_and_execute(parachain_rpc, vault_data, 6).await,
            Error::DeadlineExpired
        );
    }

    #[tokio::test]
    async fn should_pay_and_execute_replace() {
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc
            .expect_get_current_active_block_number()
            .times(1)
            .returning(|| Ok(50));
        parachain_rpc
            .expect_execute_replace()
            .times(1)
            .returning(|_, _, _| Ok(()));
        parachain_rpc
            .expect_wait_for_block_in_relay()
            .times(1)
            .returning(|_, _| Ok(()));

        let mut btc_rpc = MockBitcoin::default();
        btc_rpc.expect_create_transaction::<BtcAddress>().returning(|_, _, _| {
            Ok(LockedTransaction::new(
                Transaction {
                    version: 0,
                    lock_time: 0,
                    input: vec![],
                    output: vec![],
                },
                Default::default(),
                None,
            ))
        });

        btc_rpc.expect_send_transaction().returning(|_| Ok(Txid::default()));

        btc_rpc.expect_wait_for_transaction_metadata().returning(|_, _| {
            Ok(TransactionMetadata {
                txid: Txid::default(),
                proof: vec![],
                raw_tx: vec![],
                block_height: 0,
                block_hash: BlockHash::default(),
                fee: None,
            })
        });

        btc_rpc.expect_get_balance().returning(|_| Ok(Amount::ZERO));

        let request = Request {
            amount: 100,
            deadline: Some(Deadline {
                parachain: 100,
                bitcoin: 100,
            }),
            btc_address: BtcAddress::P2SH(H160::from_slice(&[1; 20])),
            hash: H256::from_slice(&[1; 32]),
            btc_height: None,
            request_type: RequestType::Replace,
            vault_id: dummy_vault_id(),
            fee_budget: None,
        };

        let vault_data = VaultData {
            vault_id: dummy_vault_id(),
            btc_rpc,
            metrics: PerCurrencyMetrics::dummy(),
        };

        assert_ok!(request.pay_and_execute(parachain_rpc, vault_data, 6).await);
    }
}
