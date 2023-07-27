use crate::{
    error::Error,
    metrics::update_bitcoin_metrics,
    services::{spawn_cancelable, DynBitcoinCoreApi, Error as ServiceError, ShutdownSender},
    system::VaultData,
    VaultIdManager, YIELD_RATE,
};
use bitcoin::{
    Error as BitcoinError, Hash, SatPerVbyte, Transaction, TransactionExt, TransactionMetadata, Txid,
    BLOCK_INTERVAL as BITCOIN_BLOCK_INTERVAL,
};
use futures::{future::Either, stream::StreamExt, try_join, TryStreamExt};
use governor::RateLimiter;
use runtime::{
    BtcAddress, BtcRelayPallet, Error as RuntimeError, FixedPointNumber, FixedU128, H256Le, InterBtcParachain,
    InterBtcRedeemRequest, InterBtcReplaceRequest, OraclePallet, PartialAddress, PrettyPrint, RedeemPallet,
    RedeemRequestStatus, ReplacePallet, ReplaceRequestStatus, SecurityPallet, UtilFuncs, VaultId, VaultRegistryPallet,
    H256,
};
use std::{collections::HashMap, convert::TryInto, time::Duration};
use tokio::time::sleep;
use tokio_stream::wrappers::BroadcastStream;

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

    // do -num_bitcoin_blocks = ceil(millis / denominator)
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
            btc_address: *request.btc_address,
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
            btc_address: *request.btc_address,
            request_type: RequestType::Replace,
            vault_id: request.old_vault,
            fee_budget: None,
        })
    }

    /// returns the fee rate in sat/vByte
    async fn get_fee_rate<P: OraclePallet + Send + Sync>(&self, parachain_rpc: &P) -> Result<SatPerVbyte, Error> {
        let fee_rate: FixedU128 = parachain_rpc.get_bitcoin_fees().await?;
        let rate = fee_rate
            .into_inner()
            .checked_div(FixedU128::accuracy())
            .ok_or(Error::ArithmeticUnderflow)?
            .try_into()?;
        Ok(SatPerVbyte(rate))
    }

    /// Makes the bitcoin transfer and executes the request
    pub async fn pay_and_execute<
        P: ReplacePallet
            + BtcRelayPallet
            + RedeemPallet
            + SecurityPallet
            + VaultRegistryPallet
            + OraclePallet
            + UtilFuncs
            + Clone
            + Send
            + Sync,
    >(
        &self,
        parachain_rpc: P,
        vault: VaultData,
        num_confirmations: u32,
        auto_rbf: bool,
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
            .transfer_btc(
                &parachain_rpc,
                &vault.btc_rpc,
                num_confirmations,
                self.vault_id.clone(),
                auto_rbf,
            )
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
    async fn transfer_btc<P: OraclePallet + BtcRelayPallet + VaultRegistryPallet + UtilFuncs + Clone + Send + Sync>(
        &self,
        parachain_rpc: &P,
        btc_rpc: &DynBitcoinCoreApi,
        num_confirmations: u32,
        vault_id: VaultId,
        auto_rbf: bool,
    ) -> Result<TransactionMetadata, Error> {
        let fee_rate = self.get_fee_rate(parachain_rpc).await?;

        tracing::debug!("Using fee_rate = {} sat/vByte", fee_rate.0);

        let txid = btc_rpc
            .create_and_send_transaction(
                self.btc_address
                    .to_address(btc_rpc.network())
                    .map_err(BitcoinError::ConversionError)?,
                self.amount as u64,
                fee_rate,
                Some(self.hash),
            )
            .await?;

        self.wait_for_inclusion(parachain_rpc, btc_rpc, num_confirmations, txid, auto_rbf)
            .await
    }

    #[tracing::instrument(
    name = "wait_for_inclusion",
    skip(self, parachain_rpc, btc_rpc),
    fields(
    request_type = ?self.request_type,
    request_id = ?self.hash,
    )
    )]
    async fn wait_for_inclusion<
        P: OraclePallet + BtcRelayPallet + VaultRegistryPallet + UtilFuncs + Clone + Send + Sync,
    >(
        &self,
        parachain_rpc: &P,
        btc_rpc: &DynBitcoinCoreApi,
        num_confirmations: u32,
        mut txid: Txid,
        auto_rbf: bool,
    ) -> Result<TransactionMetadata, Error> {
        'outer: loop {
            tracing::info!("Awaiting bitcoin confirmations for {txid}");

            let txid_copy = txid; // we get borrow check error if we don't use a copy

            let fee_rate_subscription = parachain_rpc.on_fee_rate_change();
            let fee_rate_subscription = BroadcastStream::new(fee_rate_subscription);
            let subscription = fee_rate_subscription
                .map_err(Into::<Error>::into)
                .and_then(|x| {
                    tracing::debug!("Received new inclusion fee estimate {}...", x);

                    let ret: Result<SatPerVbyte, _> = x
                        .into_inner()
                        .checked_div(FixedU128::accuracy())
                        .ok_or(Error::ArithmeticUnderflow)
                        .and_then(|x| x.try_into().map(SatPerVbyte).map_err(Into::<Error>::into));
                    futures::future::ready(ret)
                })
                .filter(|_| futures::future::ready(auto_rbf)) // if auto-rbf is disabled, don't propagate the events
                .try_filter_map(|x| async move {
                    match btc_rpc.fee_rate(txid).await {
                        Ok(current_fee) => {
                            if x > current_fee {
                                Ok(Some((current_fee, x)))
                            } else {
                                Ok(None)
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to get fee_rate: {}", e);
                            Ok(None)
                        }
                    }
                })
                .filter_map(|x| async {
                    match btc_rpc.is_in_mempool(txid_copy).await {
                        Ok(false) => {
                            // if not in mempool anymore, don't propagate the event (even if it is an error)
                            tracing::debug!("Txid not in mempool anymore...");
                            None
                        }
                        Ok(true) => {
                            tracing::debug!("Txid is still in mempool...");
                            Some(x)
                        }
                        Err(e) => {
                            tracing::warn!("Unexpected bitcoin error: {}", e);
                            Some(Err(e.into()))
                        }
                    }
                });

            let wait_for_transaction_metadata = btc_rpc.wait_for_transaction_metadata(txid, num_confirmations);
            futures::pin_mut!(subscription);

            let mut metadata_fut = wait_for_transaction_metadata;

            // The code below looks a little bit complicated but the idea is simple:
            // we keep waiting for inclusion until it's either included in the bitcoin chain,
            // or we successfully bump fees
            let tx_metadata = loop {
                match futures::future::select(metadata_fut, subscription.next()).await {
                    Either::Left((result, _)) => break result?,
                    Either::Right((None, _)) => return Err(Error::RuntimeError(RuntimeError::ChannelClosed)),
                    Either::Right((Some(Err(x)), continuation)) => {
                        tracing::warn!("Received an error from the fee rate subscription: {x}");
                        // continue with the unchanged fee rate
                        metadata_fut = continuation;
                    }
                    Either::Right((Some(Ok((old_fee, new_fee))), continuation)) => {
                        tracing::debug!("Attempting to bump fee rate from {} to {}...", old_fee.0, new_fee.0);
                        match btc_rpc
                            .bump_fee(
                                &txid,
                                self.btc_address
                                    .to_address(btc_rpc.network())
                                    .map_err(BitcoinError::ConversionError)?,
                                new_fee,
                            )
                            .await
                        {
                            Ok(new_txid) => {
                                tracing::info!("Bumped fee rate. Old txid = {txid}, new txid = {new_txid}");
                                txid = new_txid;
                                continue 'outer;
                            }
                            Err(x) if x.rejected_by_network_rules() => {
                                // bump not big enough. This is not unexpected, so only debug print
                                tracing::debug!("Failed to bump fees: {:?}", x);
                            }
                            Err(x) if x.could_be_insufficient_funds() => {
                                // Unexpected: likely (but no certainly) there are insufficient
                                // funds in the wallet to pay the increased fee.
                                tracing::warn!("Failed to bump fees - likely due to insufficient funds: {:?}", x);
                            }
                            Err(x) => {
                                // unexpected error. Just continue waiting for the original tx
                                tracing::warn!("Failed to bump fees due to unexpected reasons: {:?}", x);
                            }
                        };
                        metadata_fut = continuation;
                    }
                }
            };

            tracing::info!("Awaiting parachain confirmations...");

            match parachain_rpc
                .wait_for_block_in_relay(
                    H256Le::from_bytes_le(tx_metadata.block_hash.as_byte_array()),
                    Some(num_confirmations),
                )
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
    async fn execute<P: ReplacePallet + RedeemPallet>(
        &self,
        parachain_rpc: P,
        tx_metadata: TransactionMetadata,
    ) -> Result<(), Error> {
        // select the execute function based on request_type
        let execute = match self.request_type {
            RequestType::Redeem => RedeemPallet::execute_redeem,
            RequestType::Replace => ReplacePallet::execute_replace,
        };

        match (self.fee_budget, tx_metadata.fee.map(|x| x.abs().to_sat() as u128)) {
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
            || (execute)(&parachain_rpc, self.hash, &tx_metadata.proof),
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

        tracing::info!("Executed request #{:?}", self.hash);

        Ok(())
    }
}

fn create_payment_worker(
    shutdown_tx: ShutdownSender,
    parachain_rpc: InterBtcParachain,
    vault_id_manager: VaultIdManager,
    request: Request,
    txid: Txid,
    num_confirmations: u32,
    auto_rbf: bool,
) {
    tracing::info!(
        "{:?} request #{:?} has valid bitcoin payment - processing...",
        request.request_type,
        request.hash
    );
    spawn_cancelable(shutdown_tx.subscribe(), async move {
        let btc_rpc = match vault_id_manager.get_bitcoin_rpc(&request.vault_id).await {
            Some(x) => x,
            None => {
                tracing::error!(
                    "Failed to fetch bitcoin rpc for vault {}",
                    request.vault_id.pretty_print()
                );
                return; // nothing we can do - bail
            }
        };

        match request
            .wait_for_inclusion(&parachain_rpc, &btc_rpc, num_confirmations, txid, auto_rbf)
            .await
        {
            Ok(tx_metadata) => {
                if let Err(e) = request.execute(parachain_rpc.clone(), tx_metadata).await {
                    tracing::error!("Failed to execute request #{}: {}", request.hash, e);
                }
            }
            Err(e) => {
                tracing::error!("Error while waiting for inclusion for request #{}: {}", request.hash, e);
            }
        }
    });
}

/// Queries the parachain for open requests and executes them. It checks the
/// bitcoin blockchain to see if a payment has already been made.
#[allow(clippy::too_many_arguments)]
pub async fn execute_open_requests(
    shutdown_tx: ShutdownSender,
    parachain_rpc: InterBtcParachain,
    vault_id_manager: VaultIdManager,
    read_only_btc_rpc: DynBitcoinCoreApi,
    num_confirmations: u32,
    payment_margin: Duration,
    auto_rbf: bool,
) -> Result<(), ServiceError<Error>> {
    let parachain_rpc = &parachain_rpc;
    let vault_id = parachain_rpc.get_account_id().clone();

    // get all redeem and replace requests
    let (redeem_requests, replace_requests) = try_join!(
        parachain_rpc.get_vault_redeem_requests(vault_id.clone()),
        parachain_rpc.get_old_vault_replace_requests(vault_id.clone()),
    )?;

    let open_redeems = redeem_requests
        .into_iter()
        .filter(|(_, request)| request.status == RedeemRequestStatus::Pending)
        .filter_map(|(hash, request)| Request::from_redeem_request(hash, request, payment_margin).ok());

    let open_replaces = replace_requests
        .into_iter()
        .filter(|(_, request)| request.status == ReplaceRequestStatus::Pending)
        .filter_map(|(hash, request)| Request::from_replace_request(hash, request, payment_margin).ok());

    // collect all requests into a hashmap, indexed by their id
    let mut open_requests = open_redeems
        .chain(open_replaces)
        .map(|x| (x.hash, x))
        .collect::<HashMap<_, _>>();

    // find the height of bitcoin chain corresponding to the earliest btc_height
    let btc_start_height = match open_requests
        .values()
        .map(|request| request.btc_height.unwrap_or(u32::MAX))
        .min()
    {
        Some(x) => x,
        None => return Ok(()), // the iterator is empty so we have nothing to do
    };

    // NOTE: block iteration is expensive so only use a full node
    // direct lookup is possible with the light client
    if read_only_btc_rpc.is_full_node() {
        let rate_limiter = RateLimiter::direct(YIELD_RATE);
        // iterate through transactions in reverse order, starting from those in the mempool, and
        // gracefully fail on encountering a pruned blockchain
        let mut transaction_stream = bitcoin::reverse_stream_transactions(&read_only_btc_rpc, btc_start_height).await?;
        while let Some(result) = transaction_stream.next().await {
            if rate_limiter.check().is_ok() {
                // give the outer `select` a chance to check the shutdown signal
                tokio::task::yield_now().await;
            }

            // When there is an error, we have to make a choice. Either we restart or
            // continue processing. Both options have their risks: if we restart, it's
            // possible that the vault will never manage to start up, causing us to
            // fail to process requests. On the other hand, if we ignore transactions,
            // we risk double paying. We choose to restart only for network errors,
            // since these are not expected to be persistent. Other errors could be
            // persistent, so we keep going.
            let tx = match result {
                Ok(x) => x,
                Err(e) if e.is_transport_error() => {
                    return Err(e.into());
                }
                Err(e) => {
                    tracing::warn!("Failed to process transaction: {}", e);
                    continue;
                }
            };

            // get the request this transaction corresponds to, if any
            if let Some(request) = get_request_for_btc_tx(&tx, &open_requests) {
                // remove request from the hashmap
                open_requests.retain(|&key, _| key != request.hash);

                // start a new task to (potentially) await confirmation and to execute on the parachain
                // make copies of the variables we move into the task
                create_payment_worker(
                    shutdown_tx.clone(),
                    parachain_rpc.clone(),
                    vault_id_manager.clone(),
                    request,
                    tx.txid(),
                    num_confirmations,
                    auto_rbf,
                );
            }
        }
    }

    // All requests remaining in the hashmap did not have a bitcoin payment yet
    // or were not found in the stream, check if we can fetch by id directly
    // or just pay and execute all requests individually
    for (id, request) in open_requests {
        // try finding transaction directly (if supported)
        match read_only_btc_rpc
            .get_tx_for_op_return(
                request
                    .btc_address
                    .to_address(read_only_btc_rpc.network())
                    .map_err(BitcoinError::ConversionError)?,
                request.amount,
                id,
            )
            .await
        {
            Ok(Some(txid)) => {
                create_payment_worker(
                    shutdown_tx.clone(),
                    parachain_rpc.clone(),
                    vault_id_manager.clone(),
                    request,
                    txid,
                    num_confirmations,
                    auto_rbf,
                );
                // task will handling execution
                continue;
            }
            Ok(None) => {} // make payment
            Err(err) => {
                tracing::error!("Failed to fetch tx for OP_RETURN {}", err);
                // TODO: can we handle this error and still make the payment?
                continue;
            }
        }

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

            match request
                .pay_and_execute(parachain_rpc, vault, num_confirmations, auto_rbf)
                .await
            {
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
/// on the OP_RETURN and the amount of btc that is transferred to the address
fn get_request_for_btc_tx(tx: &Transaction, hash_map: &HashMap<H256, Request>) -> Option<Request> {
    let hash = tx.get_op_return()?;
    let request = hash_map.get(&hash)?;
    let paid_amount = tx.get_payment_amount_to(request.btc_address.to_payload().ok()?)?;
    if paid_amount as u128 >= request.amount {
        Some(request.clone())
    } else {
        None
    }
}

#[cfg(all(test, feature = "parachain-metadata-kintsugi"))]
mod tests {
    use super::*;
    use crate::metrics::PerCurrencyMetrics;
    use async_trait::async_trait;
    use bitcoin::{
        json, Address, Amount, BitcoinCoreApi, Block, BlockHash, BlockHeader, Error as BitcoinError, Hash, Network,
        PrivateKey, PublicKey, RawTransactionProof, Transaction, TransactionMetadata, Txid,
    };
    use jsonrpc_core::serde_json::{Map, Value};
    use runtime::{
        sp_core::H160, AccountId, AssetMetadata, BitcoinBlockHeight, BlockNumber, BtcPublicKey, CurrencyId,
        Error as RuntimeError, FeeRateUpdateReceiver, InterBtcRichBlockHeader, InterBtcVault, OracleKey,
        RawBlockHeader, Token, DOT, IBTC,
    };
    use std::sync::Arc;

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
            async fn get_foreign_assets_metadata(&self) -> Result<Vec<(u32, AssetMetadata)>, RuntimeError>;
            async fn get_foreign_asset_metadata(&self, id: u32) -> Result<AssetMetadata, RuntimeError>;
            async fn get_lend_tokens(&self) -> Result<Vec<(CurrencyId, CurrencyId)>, RuntimeError>;
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
            async fn get_required_collateral_for_wrapped(&self, amount_btc: u128, collateral_currency: CurrencyId) -> Result<u128, RuntimeError>;
            async fn get_required_collateral_for_vault(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
            async fn get_vault_total_collateral(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
            async fn get_collateralization_from_vault(&self, vault_id: VaultId, only_issued: bool) -> Result<u128, RuntimeError>;
            async fn set_current_client_release(&self, uri: &[u8], code_hash: &H256) -> Result<(), RuntimeError>;
            async fn set_pending_client_release(&self, uri: &[u8], code_hash: &H256) -> Result<(), RuntimeError>;
        }

        #[async_trait]
        pub trait RedeemPallet {
            async fn request_redeem(&self, amount: u128, btc_address: BtcAddress, vault_id: &VaultId) -> Result<H256, RuntimeError>;
            async fn execute_redeem(&self, redeem_id: H256, raw_proof: &RawTransactionProof) -> Result<(), RuntimeError>;
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
            async fn execute_replace(&self, replace_id: H256, raw_proof: &RawTransactionProof) -> Result<(), RuntimeError>;
            async fn cancel_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn get_new_vault_replace_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcReplaceRequest)>, RuntimeError>;
            async fn get_old_vault_replace_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcReplaceRequest)>, RuntimeError>;
            async fn get_replace_period(&self) -> Result<u32, RuntimeError>;
            async fn get_replace_request(&self, replace_id: H256) -> Result<InterBtcReplaceRequest, RuntimeError>;
            async fn get_replace_dust_amount(&self) -> Result<u128, RuntimeError>;
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
            async fn initialize_btc_relay(&self, header: RawBlockHeader, height: BitcoinBlockHeight) -> Result<(), RuntimeError>;
            async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), RuntimeError>;
            async fn store_block_headers(&self, headers: Vec<RawBlockHeader>) -> Result<(), RuntimeError>;
        }

        #[async_trait]
        pub trait SecurityPallet {
            async fn get_current_active_block_number(&self) -> Result<u32, RuntimeError>;
        }

        #[async_trait]
        pub trait OraclePallet {
            async fn get_exchange_rate(&self, currency_id: CurrencyId) -> Result<FixedU128, RuntimeError>;
            async fn feed_values(&self, values: Vec<(OracleKey, FixedU128)>) -> Result<(), RuntimeError>;
            async fn set_bitcoin_fees(&self, value: FixedU128) -> Result<(), RuntimeError>;
            async fn get_bitcoin_fees(&self) -> Result<FixedU128, RuntimeError>;
            async fn wrapped_to_collateral(&self, amount: u128, currency_id: CurrencyId) -> Result<u128, RuntimeError>;
            async fn collateral_to_wrapped(&self, amount: u128, currency_id: CurrencyId) -> Result<u128, RuntimeError>;
            async fn has_updated(&self, key: &OracleKey) -> Result<bool, RuntimeError>;
            fn on_fee_rate_change(&self) -> FeeRateUpdateReceiver;
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
            fn is_full_node(&self) -> bool;
            fn network(&self) -> Network;
            async fn wait_for_block(&self, height: u32, num_confirmations: u32) -> Result<Block, BitcoinError>;
            fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, BitcoinError>;
            fn list_transactions(&self, max_count: Option<usize>) -> Result<Vec<json::ListTransactionResult>, BitcoinError>;
            fn list_addresses(&self) -> Result<Vec<Address>, BitcoinError>;
            async fn get_block_count(&self) -> Result<u64, BitcoinError>;
            async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_transaction(&self, txid: &Txid, block_hash: Option<BlockHash>) -> Result<Transaction, BitcoinError>;
            async fn get_proof(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_block_hash(&self, height: u32) -> Result<BlockHash, BitcoinError>;
            async fn get_pruned_height(&self) -> Result<u64, BitcoinError>;
            async fn get_new_address(&self) -> Result<Address, BitcoinError>;
            async fn get_new_public_key(&self) -> Result<PublicKey, BitcoinError>;
            fn dump_private_key(&self, address: &Address) -> Result<PrivateKey, BitcoinError>;
            fn import_private_key(&self, private_key: &PrivateKey, is_derivation_key: bool) -> Result<(), BitcoinError>;
            async fn add_new_deposit_key(&self, public_key: PublicKey, secret_key: Vec<u8>) -> Result<(), BitcoinError>;
            async fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinError>;
            async fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinError>;
            async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, BitcoinError>;
            async fn get_mempool_transactions<'a>(&'a self) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send + 'a>, BitcoinError>;
            async fn wait_for_transaction_metadata(&self, txid: Txid, num_confirmations: u32) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_and_send_transaction(&self, address: Address, sat: u64, fee_rate: SatPerVbyte, request_id: Option<H256>) -> Result<Txid, BitcoinError>;
            async fn send_to_address(&self, address: Address, sat: u64, request_id: Option<H256>, fee_rate: SatPerVbyte, num_confirmations: u32) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_or_load_wallet(&self) -> Result<(), BitcoinError>;
            async fn rescan_blockchain(&self, start_height: usize, end_height: usize) -> Result<(), BitcoinError>;
            async fn rescan_electrs_for_addresses(&self, addresses: Vec<Address>) -> Result<(), BitcoinError>;
            fn get_utxo_count(&self) -> Result<usize, BitcoinError>;
            async fn bump_fee(
                &self,
                txid: &Txid,
                address: Address,
                fee_rate: SatPerVbyte,
            ) -> Result<Txid, BitcoinError>;
            async fn is_in_mempool(&self, txid: Txid) -> Result<bool, BitcoinError>;
            async fn fee_rate(&self, txid: Txid) -> Result<SatPerVbyte, BitcoinError>;
            async fn get_tx_for_op_return(&self, address: Address, amount: u128, data: H256) -> Result<Option<Txid>, BitcoinError>;
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
        use bitcoin::Hash;

        use crate::metrics::PerCurrencyMetrics;

        use super::*;

        fn should_pay_and_execute_with_deadlines(
            parachain_deadline: u32,
            current_parachain_height: u32,
            bitcoin_deadline: u32,
            current_bitcoin_height: u32,
        ) -> (Request, MockProvider, VaultData) {
            let mut parachain_rpc = MockProvider::default();
            parachain_rpc
                .expect_get_bitcoin_fees()
                .returning(move || Ok(FixedU128::from(1000)));

            parachain_rpc
                .expect_get_current_active_block_number()
                .returning(move || Ok(current_parachain_height));
            parachain_rpc.expect_execute_redeem().returning(|_, _| Ok(()));
            parachain_rpc.expect_wait_for_block_in_relay().returning(|_, _| Ok(()));

            parachain_rpc
                .expect_on_fee_rate_change()
                .returning(|| tokio::sync::broadcast::channel(2).1);

            let mut mock_bitcoin = MockBitcoin::default();
            mock_bitcoin.expect_network().returning(|| Network::Regtest);
            mock_bitcoin
                .expect_get_block_count()
                .returning(move || Ok(current_bitcoin_height as u64));
            mock_bitcoin
                .expect_create_and_send_transaction()
                .returning(|_, _, _, _| Ok(Txid::all_zeros()));
            mock_bitcoin.expect_wait_for_transaction_metadata().returning(|_, _| {
                Ok(TransactionMetadata {
                    txid: Txid::all_zeros(),
                    proof: RawTransactionProof {
                        coinbase_tx_proof: vec![],
                        raw_coinbase_tx: vec![],
                        raw_user_tx: vec![],
                        user_tx_proof: vec![],
                    },
                    block_height: 0,
                    block_hash: BlockHash::all_zeros(),
                    fee: None,
                })
            });
            mock_bitcoin.expect_list_transactions().returning(|_| Ok(vec![]));
            mock_bitcoin.expect_get_balance().returning(|_| Ok(Amount::ZERO));
            let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin);

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

            assert_ok!(request.pay_and_execute(parachain_rpc, btc_rpc, 6, true).await);
        }

        #[tokio::test]
        async fn should_pay_and_execute_redeem_if_only_parachain_deadline_expired() {
            let (request, parachain_rpc, btc_rpc) = should_pay_and_execute_with_deadlines(100, 101, 100, 50);

            assert_ok!(request.pay_and_execute(parachain_rpc, btc_rpc, 6, true).await);
        }

        #[tokio::test]
        async fn should_pay_and_execute_redeem_if_only_bitcoin_deadline_expired() {
            let (request, parachain_rpc, btc_rpc) = should_pay_and_execute_with_deadlines(100, 50, 100, 101);

            assert_ok!(request.pay_and_execute(parachain_rpc, btc_rpc, 6, true).await);
        }

        #[tokio::test]
        async fn should_not_pay_and_execute_redeem_if_both_deadlines_expired() {
            let (request, parachain_rpc, btc_rpc) = should_pay_and_execute_with_deadlines(100, 101, 100, 101);

            assert_err!(
                request.pay_and_execute(parachain_rpc, btc_rpc, 6, true).await,
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
        let mut mock_bitcoin = MockBitcoin::default();
        mock_bitcoin.expect_get_block_count().times(1).returning(|| Ok(110));
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin);
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
            request.pay_and_execute(parachain_rpc, vault_data, 6, true).await,
            Error::DeadlineExpired
        );
    }

    #[tokio::test]
    async fn should_pay_and_execute_replace() {
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc
            .expect_get_bitcoin_fees()
            .returning(move || Ok(FixedU128::from(1000)));
        parachain_rpc
            .expect_get_current_active_block_number()
            .times(1)
            .returning(|| Ok(50));
        parachain_rpc.expect_execute_replace().times(1).returning(|_, _| Ok(()));
        parachain_rpc
            .expect_wait_for_block_in_relay()
            .times(1)
            .returning(|_, _| Ok(()));
        parachain_rpc
            .expect_on_fee_rate_change()
            .returning(|| tokio::sync::broadcast::channel(2).1);

        let mut mock_bitcoin = MockBitcoin::default();
        mock_bitcoin.expect_network().returning(|| Network::Regtest);
        mock_bitcoin
            .expect_create_and_send_transaction()
            .returning(|_, _, _, _| Ok(Txid::all_zeros()));
        mock_bitcoin.expect_wait_for_transaction_metadata().returning(|_, _| {
            Ok(TransactionMetadata {
                txid: Txid::all_zeros(),
                proof: RawTransactionProof {
                    coinbase_tx_proof: vec![],
                    raw_coinbase_tx: vec![],
                    raw_user_tx: vec![],
                    user_tx_proof: vec![],
                },
                block_height: 0,
                block_hash: BlockHash::all_zeros(),
                fee: None,
            })
        });
        mock_bitcoin.expect_get_balance().returning(|_| Ok(Amount::ZERO));
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin);

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

        assert_ok!(request.pay_and_execute(parachain_rpc, vault_data, 6, true).await);
    }
}
