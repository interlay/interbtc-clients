use crate::{Error, Event, IssueRequests};
use bitcoin::{BitcoinCoreApi, BlockHash, Transaction, TransactionExt};
use futures::{channel::mpsc::Sender, future, SinkExt, StreamExt};
use runtime::{
    pallets::issue::{CancelIssueEvent, ExecuteIssueEvent, RequestIssueEvent},
    BtcAddress, BtcPublicKey, BtcRelayPallet, H256Le, InterBtcParachain, InterBtcRuntime, IssuePallet, UtilFuncs,
};
use service::Error as ServiceError;
use sha2::{Digest, Sha256};
use sp_core::H256;
use std::sync::Arc;

// initialize `issue_set` with currently open issues, and return the block height
// from which to start watching the bitcoin chain
pub(crate) async fn initialize_issue_set<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    bitcoin_core: &B,
    btc_parachain: &InterBtcParachain,
    issue_set: &Arc<IssueRequests>,
) -> Result<u32, Error> {
    let (mut issue_set, requests) = future::join(issue_set.lock(), btc_parachain.get_all_active_issues()).await;
    let requests = requests?;

    // find the height of bitcoin chain corresponding to the earliest open_time
    let btc_start_height = match requests.iter().map(|(_, request)| request.btc_height).min() {
        Some(x) => x,
        None => bitcoin_core.get_block_count().await? as u32, // no open issues, start at current height
    };

    for (issue_id, request) in requests.into_iter() {
        issue_set.insert(issue_id, request.btc_address);
    }

    Ok(btc_start_height)
}

/// execute issue requests on best-effort (i.e. don't retry on error),
/// returns an error if stream ends, otherwise runs forever
pub async fn process_issue_requests<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    bitcoin_core: B,
    btc_parachain: InterBtcParachain,
    issue_set: Arc<IssueRequests>,
    btc_start_height: u32,
    num_confirmations: u32,
) -> Result<(), ServiceError> {
    let mut stream =
        bitcoin::stream_in_chain_transactions(bitcoin_core.clone(), btc_start_height, num_confirmations).await;

    while let Some(Ok((block_hash, transaction))) = stream.next().await {
        if let Err(e) = process_transaction_and_execute_issue(
            &bitcoin_core,
            &btc_parachain,
            &issue_set,
            num_confirmations,
            block_hash,
            transaction,
        )
        .await
        {
            tracing::warn!("Failed to execute issue request: {}", e.to_string());
        }
    }

    // stream closed, restart client
    Err(ServiceError::ClientShutdown)
}

pub async fn add_keys_from_past_issue_request<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    bitcoin_core: &B,
    btc_parachain: &InterBtcParachain,
) -> Result<(), Error> {
    let issue_requests = btc_parachain
        .get_vault_issue_requests(btc_parachain.get_account_id().clone())
        .await?;

    let btc_start_height = match issue_requests.iter().map(|(_, request)| request.btc_height).min() {
        Some(x) => x as usize,
        None => return Ok(()), // the iterator is empty so we have nothing to do
    };

    for (issue_id, request) in issue_requests.into_iter() {
        if let Err(e) = add_new_deposit_key(bitcoin_core, issue_id, request.btc_public_key).await {
            tracing::error!("Failed to add deposit key #{}: {}", issue_id, e.to_string());
        }
    }

    tracing::info!("Rescanning bitcoin chain from height {}...", btc_start_height);
    if let Err(err) = bitcoin_core.rescan_blockchain(btc_start_height).await {
        // invalid start height or other
        tracing::error!("Unable to rescan blockchain: {}", err);
    }

    Ok(())
}

/// execute issue requests with a matching Bitcoin payment
async fn process_transaction_and_execute_issue<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    bitcoin_core: &B,
    btc_parachain: &InterBtcParachain,
    issue_set: &Arc<IssueRequests>,
    num_confirmations: u32,
    block_hash: BlockHash,
    transaction: Transaction,
) -> Result<(), Error> {
    let addresses = transaction.extract_output_addresses::<BtcAddress>();
    let mut issue_requests = issue_set.lock().await;
    if let Some((issue_id, address)) = addresses.iter().find_map(|address| {
        let issue_id = issue_requests.get_key_for_value(address)?;
        Some((*issue_id, *address))
    }) {
        let issue = btc_parachain.get_issue_request(issue_id).await?;
        // tx has output to address
        match transaction.get_payment_amount_to(address) {
            None => {
                // this should never happen, so use WARN
                tracing::warn!(
                    "Could not extract payment amount for transaction {}",
                    transaction.txid()
                );
                return Ok(());
            }
            Some(transferred) => {
                let transferred = transferred as u128;
                if transferred == issue.amount + issue.fee {
                    tracing::info!("Found tx for issue with id {:?}", issue_id);
                } else {
                    tracing::info!(
                        "Found tx for issue with id {}. Expected amount = {}, got {}",
                        issue_id,
                        issue.amount,
                        transferred
                    );
                }

                if transferred < issue.amount + issue.fee {
                    // insufficient amount, don't execute
                    return Ok(());
                }

                issue_requests.remove_value(&address);

                // at this point we know that the transaction has `num_confirmations` on the bitcoin chain,
                // but the relay can introduce a delay, so wait until the relay also confirms the transaction.
                btc_parachain
                    .wait_for_block_in_relay(H256Le::from_bytes_le(&block_hash.to_vec()), Some(num_confirmations))
                    .await?;

                // found tx, submit proof
                let txid = transaction.txid();

                // bitcoin core is currently blocking, no need to try_join
                let raw_tx = bitcoin_core.get_raw_tx(&txid, &block_hash).await?;
                let proof = bitcoin_core.get_proof(txid, &block_hash).await?;

                tracing::info!("Executing issue #{:?}", issue_id);
                match btc_parachain.execute_issue(issue_id, &proof, &raw_tx).await {
                    Ok(_) => (),
                    Err(err) if err.is_issue_completed() => {
                        tracing::info!("Issue #{} has already been completed", issue_id);
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
    bitcoin_core: &B,
    secure_id: H256,
    public_key: BtcPublicKey,
) -> Result<(), Error> {
    let mut hasher = Sha256::default();
    // input compressed public key
    hasher.input(public_key.0.to_vec());
    // input issue id
    hasher.input(secure_id.as_bytes());
    bitcoin_core
        .add_new_deposit_key(public_key.0, hasher.result().as_slice().to_vec())
        .await?;
    Ok(())
}

/// Listen for RequestIssueEvent directed at this vault. Schedules a cancellation of
/// the received issue
///
/// # Arguments
///
/// * `bitcoin_core` - the bitcoin core RPC handle
/// * `btc_parachain` - the parachain RPC handle
/// * `event_channel` - the channel over which to signal events
/// * `issue_set` - all issue ids observed since vault started
pub async fn listen_for_issue_requests<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    bitcoin_core: B,
    btc_parachain: InterBtcParachain,
    event_channel: Sender<Event>,
    issue_set: Arc<IssueRequests>,
) -> Result<(), ServiceError> {
    let bitcoin_core = &bitcoin_core;
    let btc_parachain = &btc_parachain;
    let event_channel = &event_channel;
    let issue_set = &issue_set;
    btc_parachain
        .on_event::<RequestIssueEvent<InterBtcRuntime>, _, _, _>(
            |event| async move {
                if &event.vault_id.account_id == btc_parachain.get_account_id() {
                    tracing::info!("Received request issue event: {:?}", event);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel.clone().send(Event::Opened).await;

                    if let Err(e) = add_new_deposit_key(bitcoin_core, event.issue_id, event.vault_public_key).await {
                        tracing::error!("Failed to add new deposit key #{}: {}", event.issue_id, e.to_string());
                    }
                }

                tracing::trace!(
                    "watching issue #{} for payment to {:?}",
                    event.issue_id,
                    event.vault_btc_address
                );
                issue_set.insert(event.issue_id, event.vault_btc_address).await;
            },
            |error| tracing::error!("Error reading request issue event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}

/// Listen for ExecuteIssueEvent directed at this vault. Cancels the scheduled
/// cancel_issue
///
/// # Arguments
///
/// * `btc_parachain` - the parachain RPC handle
/// * `event_channel` - the channel over which to signal events
/// * `issue_set` - all issue ids observed since vault started
pub async fn listen_for_issue_executes(
    btc_parachain: InterBtcParachain,
    event_channel: Sender<Event>,
    issue_set: Arc<IssueRequests>,
) -> Result<(), ServiceError> {
    let btc_parachain = &btc_parachain;
    let event_channel = &event_channel;
    let issue_set = &issue_set;
    btc_parachain
        .on_event::<ExecuteIssueEvent<InterBtcRuntime>, _, _, _>(
            |event| async move {
                if &event.vault_id.account_id == btc_parachain.get_account_id() {
                    tracing::info!("Received execute issue event: {:?}", event);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel.clone().send(Event::Executed(event.issue_id)).await;
                }

                tracing::trace!("issue #{} executed, no longer watching", event.issue_id);
                issue_set.remove(&event.issue_id).await;
            },
            |error| tracing::error!("Error reading execute issue event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}

/// Listen for all `CancelIssueEvent`s.
///
/// # Arguments
///
/// * `btc_parachain` - the parachain RPC handle
/// * `issue_set` - all issue ids observed since vault started
pub async fn listen_for_issue_cancels(
    btc_parachain: InterBtcParachain,
    issue_set: Arc<IssueRequests>,
) -> Result<(), ServiceError> {
    let issue_set = &issue_set;
    btc_parachain
        .on_event::<CancelIssueEvent<InterBtcRuntime>, _, _, _>(
            |event| async move {
                tracing::trace!("issue #{} cancelled, no longer watching", event.issue_id);
                issue_set.remove(&event.issue_id).await;
            },
            |error| tracing::error!("Error reading cancel issue event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}
