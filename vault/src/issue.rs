use crate::{Error, IssueRequests, RequestEvent};
use bitcoin::{BitcoinCoreApi, BlockHash, Transaction, TransactionExt};
use futures::{channel::mpsc::Sender, future, SinkExt, StreamExt};
use log::*;
use runtime::{
    pallets::issue::{CancelIssueEvent, ExecuteIssueEvent, RequestIssueEvent},
    substrate_subxt::{Error as SubxtError, ModuleError as SubxtModuleError, RuntimeError as SubxtRuntimeError},
    BtcAddress, BtcPublicKey, BtcRelayPallet, Error as RuntimeError, H256Le, IssuePallet, PolkaBtcProvider,
    PolkaBtcRuntime, UtilFuncs, ISSUE_COMPLETED_ERROR, ISSUE_MODULE,
};
use sha2::{Digest, Sha256};
use sp_core::H256;
use std::sync::Arc;

// initialize `issue_set` with currently open issues, and return the block height
// from which to start watching the bitcoin chain
async fn initialize_issue_set<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    provider: &PolkaBtcProvider,
    btc_rpc: &B,
    issue_set: &Arc<IssueRequests>,
) -> Result<u32, Error> {
    let (mut issue_set, requests) = future::join(issue_set.lock(), provider.get_all_active_issues()).await;
    let requests = requests?;

    // find the height of bitcoin chain corresponding to the earliest open_time
    let btc_start_height = match requests.iter().map(|(_, request)| request.opentime).min() {
        Some(x) => provider.clone().get_blockchain_height_at(x).await?,
        None => btc_rpc.get_block_count().await? as u32, // no open issues, start at current height
    };

    for (issue_id, request) in requests.into_iter() {
        issue_set.insert(issue_id, request.btc_address);
    }

    Ok(btc_start_height)
}

/// execute issue requests on best-effort (i.e. don't retry on error),
/// returns `NoIncomingBlocks` if stream ends, otherwise runs forever
pub async fn process_issue_requests<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    provider: &PolkaBtcProvider,
    btc_rpc: &B,
    issue_set: &Arc<IssueRequests>,
    num_confirmations: u32,
) -> Result<(), Error> {
    let btc_start_height = initialize_issue_set(provider, btc_rpc, issue_set).await?;

    let mut stream = bitcoin::stream_in_chain_transactions(btc_rpc.clone(), btc_start_height, num_confirmations).await;

    while let Some(Ok((block_hash, transaction))) = stream.next().await {
        if let Err(e) = process_transaction_and_execute_issue(
            provider,
            btc_rpc,
            issue_set,
            num_confirmations,
            block_hash,
            transaction,
        )
        .await
        {
            error!("Error executing issue request: {}", e.to_string());
        }
    }

    Err(Error::NoIncomingBlocks)
}

pub async fn add_keys_from_past_issue_request<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    provider: &PolkaBtcProvider,
    btc_rpc: &B,
) -> Result<(), Error> {
    for (issue_id, request) in provider
        .get_vault_issue_requests(provider.get_account_id().clone())
        .await?
        .into_iter()
    {
        if let Err(e) = add_new_deposit_key(btc_rpc, issue_id, request.btc_public_key).await {
            error!("Failed to add deposit key #{}: {}", issue_id, e.to_string());
        }
    }
    Ok(())
}

/// execute issue requests with a matching Bitcoin payment
async fn process_transaction_and_execute_issue<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    provider: &PolkaBtcProvider,
    btc_rpc: &B,
    issue_set: &Arc<IssueRequests>,
    num_confirmations: u32,
    block_hash: BlockHash,
    transaction: Transaction,
) -> Result<(), Error> {
    let addresses = transaction.extract_output_addresses::<BtcAddress>();
    let mut issue_requests = issue_set.lock().await;
    if let Some((issue_id, address)) = addresses.iter().find_map(|address| {
        let issue_id = issue_requests.get_key_for_value(address)?;
        Some((issue_id.clone(), address.clone()))
    }) {
        let issue = provider.get_issue_request(issue_id).await?;
        // tx has output to address
        match transaction.get_payment_amount_to(address) {
            None => {
                // this should never happen, so use WARN
                warn!(
                    "Could not extract payment amount for transaction {}",
                    transaction.txid()
                );
                return Ok(());
            }
            Some(transferred) => {
                let transferred = transferred as u128;
                if transferred == issue.amount {
                    info!("Found tx for issue with id {}", issue_id);
                } else {
                    info!(
                        "Found tx for issue with id {}. Expected amount = {}, got {}",
                        issue_id, issue.amount, transferred
                    );
                }

                if transferred < issue.amount {
                    // insufficient amount, don't execute
                    return Ok(());
                }

                issue_requests.remove_value(&address);

                // at this point we know that the transaction has `num_confirmations` on the bitcoin chain,
                // but the relay can introduce a delay, so wait until the relay also confirms the transaction.
                provider
                    .wait_for_block_in_relay(H256Le::from_bytes_le(&block_hash.to_vec()), num_confirmations)
                    .await?;

                // found tx, submit proof
                let txid = transaction.txid();

                // bitcoin core is currently blocking, no need to try_join
                let raw_tx = btc_rpc.get_raw_tx_for(&txid, &block_hash).await?;
                let proof = btc_rpc.get_proof_for(txid.clone(), &block_hash).await?;

                info!("Executing issue with id {}", issue_id);
                match provider
                    .execute_issue(issue_id, H256Le::from_bytes_le(&txid.as_hash()), proof, raw_tx)
                    .await
                {
                    Ok(_) => (),
                    Err(RuntimeError::XtError(SubxtError::Runtime(SubxtRuntimeError::Module(SubxtModuleError {
                        ref module,
                        ref error,
                    }))))
                        if module == ISSUE_MODULE && error == ISSUE_COMPLETED_ERROR =>
                    {
                        info!("Issue {} has already been completed", issue_id);
                    }
                    Err(err) => return Err(err.into()),
                };
            }
        }
    }

    // no op_return or issue-id
    Ok(())
}

/// Import the deposit key using the on-chain key derivation scheme
async fn add_new_deposit_key<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    btc_rpc: &B,
    secure_id: H256,
    public_key: BtcPublicKey,
) -> Result<(), Error> {
    let mut hasher = Sha256::default();
    // input compressed public key
    hasher.input(public_key.0.to_vec());
    // input issue id
    hasher.input(secure_id.as_bytes());
    btc_rpc
        .add_new_deposit_key(public_key, hasher.result().as_slice().to_vec())
        .await?;
    Ok(())
}

/// Listen for RequestIssueEvent directed at this vault. Schedules a cancellation of
/// the received issue
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `event_channel` - the channel over which to signal events
/// * `issue_set` - all issue ids observed since vault started
pub async fn listen_for_issue_requests<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    provider: PolkaBtcProvider,
    btc_rpc: B,
    event_channel: Sender<RequestEvent>,
    issue_set: Arc<IssueRequests>,
) -> Result<(), runtime::Error> {
    let event_channel = &event_channel;
    let issue_set = &issue_set;
    let provider = &provider;
    let btc_rpc = &btc_rpc;
    provider
        .on_event::<RequestIssueEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if &event.vault_id == provider.get_account_id() {
                    info!("Received request issue event: {:?}", event);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel.clone().send(RequestEvent::Opened).await;

                    if let Err(e) = add_new_deposit_key(btc_rpc, event.issue_id, event.vault_public_key).await {
                        error!("Failed to add new deposit key #{}: {}", event.issue_id, e.to_string());
                    }
                }

                trace!(
                    "watching issue #{} for payment to {}",
                    event.issue_id,
                    event.vault_btc_address
                );
                issue_set.insert(event.issue_id, event.vault_btc_address).await;
            },
            |error| error!("Error reading request issue event: {}", error.to_string()),
        )
        .await
}

/// Listen for ExecuteIssueEvent directed at this vault. Cancels the scheduled
/// cancel_issue
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `event_channel` - the channel over which to signal events
/// * `issue_set` - all issue ids observed since vault started
pub async fn listen_for_issue_executes(
    provider: PolkaBtcProvider,
    event_channel: Sender<RequestEvent>,
    issue_set: Arc<IssueRequests>,
) -> Result<(), runtime::Error> {
    let event_channel = &event_channel;
    let issue_set = &issue_set;
    let provider = &provider;
    provider
        .on_event::<ExecuteIssueEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if &event.vault_id == provider.get_account_id() {
                    info!("Received execute issue event: {:?}", event);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel.clone().send(RequestEvent::Executed(event.issue_id)).await;
                }

                trace!("issue #{} executed, no longer watching", event.issue_id);
                issue_set.remove(&event.issue_id).await;
            },
            |error| error!("Error reading execute issue event: {}", error.to_string()),
        )
        .await
}

/// Listen for all `CancelIssueEvent`s.
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `issue_set` - all issue ids observed since vault started
pub async fn listen_for_issue_cancels(
    provider: PolkaBtcProvider,
    issue_set: Arc<IssueRequests>,
) -> Result<(), runtime::Error> {
    let issue_set = &issue_set;
    provider
        .on_event::<CancelIssueEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                trace!("issue #{} cancelled, no longer watching", event.issue_id);
                issue_set.remove(&event.issue_id).await;
            },
            |error| error!("Error reading cancel issue event: {}", error.to_string()),
        )
        .await
}
