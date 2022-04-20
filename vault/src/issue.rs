use crate::{metrics::publish_expected_bitcoin_balance, Error, Event, IssueRequests, VaultIdManager};
use bitcoin::{BitcoinCoreApi, BlockHash, Transaction, TransactionExt};
use futures::{channel::mpsc::Sender, future, SinkExt, StreamExt};
use runtime::{
    BtcAddress, BtcPublicKey, BtcRelayPallet, CancelIssueEvent, ExecuteIssueEvent, H256Le, InterBtcParachain,
    IssuePallet, PrettyPrint, RequestIssueEvent, UtilFuncs, H256,
};
use service::Error as ServiceError;
use sha2::{Digest, Sha256};
use std::sync::Arc;

// we have seen scanning rates as low as 61 blocks/s. Process 100 blocks per time so that we
// don't run into the 15 s timeout.
const SCAN_CHUNK_SIZE: usize = 100;

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

    // read height only _after_ the last add_new_deposit_height.If a new block arrives
    // while we rescan, bitcoin core will correctly recognize addressed associated with the
    // privkey
    let btc_end_height = bitcoin_core.get_block_count().await? as usize - 1;

    tracing::info!("Rescanning bitcoin chain from height {}...", btc_start_height);
    for (range_start, range_end) in chunks(btc_start_height, btc_end_height) {
        tracing::debug!("Scanning chain blocks {range_start}-{range_end}...");
        bitcoin_core.rescan_blockchain(range_start, range_end).await?;
    }

    Ok(())
}

/// Return the chunks of size SCAN_CHUNK_SIZE from first..last (including).
fn chunks(first: usize, last: usize) -> impl Iterator<Item = (usize, usize)> {
    (first..last)
        .step_by(SCAN_CHUNK_SIZE)
        .map(move |x| (x, usize::min(x + SCAN_CHUNK_SIZE - 1, last)))
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
                let expected = issue.amount + issue.fee;
                if transferred == expected {
                    tracing::info!("Found tx for issue with id {:?}", issue_id);
                } else {
                    tracing::info!(
                        "Found tx for issue with id {}. Expected amount = {}, got {}",
                        issue_id,
                        expected,
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

                tracing::info!(
                    "Executing issue #{:?} on behalf of user {:?} with vault {:?}",
                    issue_id,
                    issue.requester.pretty_print(),
                    issue.vault.pretty_print()
                );
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
    btc_rpc: VaultIdManager<B>,
    btc_parachain: InterBtcParachain,
    event_channel: Sender<Event>,
    issue_set: Arc<IssueRequests>,
) -> Result<(), ServiceError> {
    let btc_parachain = &btc_parachain;
    let event_channel = &event_channel;
    let issue_set = &issue_set;
    let btc_rpc = &btc_rpc;
    btc_parachain
        .on_event::<RequestIssueEvent, _, _, _>(
            |event| async move {
                if &event.vault_id.account_id == btc_parachain.get_account_id() {
                    let vault = match btc_rpc.get_vault(&event.vault_id).await {
                        Some(x) => x,
                        None => {
                            tracing::error!(
                                "No bitcoin_rpc found for vault with id {}",
                                event.vault_id.pretty_print()
                            );
                            return;
                        }
                    };
                    tracing::info!("Received request issue event: {:?}", event);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel.clone().send(Event::Opened).await;

                    publish_expected_bitcoin_balance(&vault, btc_parachain.clone()).await;

                    if let Err(e) = add_new_deposit_key(&vault.btc_rpc, event.issue_id, event.vault_public_key).await {
                        tracing::error!("Failed to add new deposit key #{}: {}", event.issue_id, e.to_string());
                    }
                }

                tracing::trace!(
                    "watching issue #{} for payment to {:?}",
                    event.issue_id,
                    event.vault_address
                );
                issue_set.insert(event.issue_id, event.vault_address).await;
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
        .on_event::<ExecuteIssueEvent, _, _, _>(
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
        .on_event::<CancelIssueEvent, _, _, _>(
            |event| async move {
                tracing::trace!("issue #{} cancelled, no longer watching", event.issue_id);
                issue_set.remove(&event.issue_id).await;
            },
            |error| tracing::error!("Error reading cancel issue event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunks() {
        let result: Vec<_> = chunks(50, 316).collect();
        assert_eq!(result, vec![(50, 149), (150, 249), (250, 316)]);
    }
}
