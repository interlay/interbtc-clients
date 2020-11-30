use crate::cancellation::ProcessEvent;
use crate::Error;
use bitcoin::{BitcoinCoreApi, BlockHash};
use futures::channel::mpsc::Sender;
use futures::{pin_mut, SinkExt, StreamExt};
use log::{error, info};
use runtime::{
    pallets::issue::{CancelIssueEvent, ExecuteIssueEvent, RequestIssueEvent},
    BtcRelayPallet, H256Le, IssuePallet, PolkaBtcProvider, PolkaBtcRuntime,
};
use sp_core::{crypto::AccountId32, H256};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct IssueIds(Mutex<HashSet<H256>>);

impl IssueIds {
    pub fn new() -> Self {
        // TODO: fetch active issue ids from storage
        IssueIds(Mutex::new(HashSet::new()))
    }
}

/// execute issue requests on best-effort (i.e. don't retry on error),
/// returns `NoIncomingBlocks` if stream ends, otherwise runs forever
pub async fn process_issue_requests<B: BitcoinCoreApi + Send + Sync + 'static>(
    provider: &Arc<PolkaBtcProvider>,
    btc_rpc: &Arc<B>,
    issue_set: &Arc<IssueIds>,
    num_confirmations: u32,
) -> Result<(), Error> {
    let stream = bitcoin::stream_blocks(btc_rpc.clone(), btc_rpc.get_block_count()? as u32);
    pin_mut!(stream);

    while let Some(Ok((block_hash, block_height))) = stream.next().await {
        if let Err(e) = process_block_issue_requests(
            provider,
            btc_rpc,
            issue_set,
            num_confirmations,
            block_hash,
            block_height,
        )
        .await
        {
            error!("Error executing issue request: {}", e.to_string());
        }
    }

    Err(Error::NoIncomingBlocks)
}

/// extract all op_return outputs and check corresponding issue ids
async fn process_block_issue_requests<B: BitcoinCoreApi + Send + Sync + 'static>(
    provider: &Arc<PolkaBtcProvider>,
    btc_rpc: &Arc<B>,
    issue_set: &Arc<IssueIds>,
    num_confirmations: u32,
    block_hash: BlockHash,
    block_height: u32,
) -> Result<(), Error> {
    // fetch all transactions in block
    for maybe_tx in btc_rpc.get_block_transactions(&block_hash)? {
        // TODO: use iterator
        if let Some(tx) = maybe_tx {
            for op_return in bitcoin::extract_op_returns(tx.clone()) {
                if op_return.len() != 32 {
                    continue;
                }

                // remove now since we don't retry
                if let Some(issue_id) = issue_set
                    .0
                    .lock()
                    .await
                    .take(&H256::from_slice(&op_return[..32]))
                {
                    info!("Executing issue with id {}", issue_id);

                    // make sure block is included in relay
                    provider
                        .wait_for_block_in_relay(
                            H256Le::from_bytes_le(&block_hash.to_vec()),
                            num_confirmations,
                        )
                        .await?;

                    // found tx, submit proof
                    let txid = tx.txid;
                    let raw_tx = btc_rpc.get_raw_tx_for(&txid, &block_hash)?;
                    let proof = btc_rpc.get_proof_for(txid.clone(), &block_hash)?;

                    // this will error if someone else executes the issue first
                    provider
                        .execute_issue(
                            issue_id,
                            H256Le::from_bytes_le(&txid.as_hash()),
                            block_height,
                            proof,
                            raw_tx,
                        )
                        .await?;
                }
            }
        }
    }

    Ok(())
}

/// Listen for RequestIssueEvent directed at this vault. Schedules a cancellation of
/// the received issue
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `vault_id` - the id of this vault
/// * `event_channel` - the channel over which to signal events
/// * `issue_set` - all issue ids observed since vault started
pub async fn listen_for_issue_requests(
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
    event_channel: Sender<ProcessEvent>,
    issue_set: Arc<IssueIds>,
) -> Result<(), runtime::Error> {
    let vault_id = &vault_id;
    let event_channel = &event_channel;
    let issue_set = &issue_set;
    let provider = &provider;
    provider
        .on_event::<RequestIssueEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if event.vault_id == vault_id.clone() {
                    info!("Received request issue event: {:?}", event);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel.clone().send(ProcessEvent::Opened).await;
                }

                issue_set.0.lock().await.insert(event.issue_id);
            },
            |error| error!("Error reading issue event: {}", error.to_string()),
        )
        .await
}

/// Listen for ExecuteIssueEvent directed at this vault. Cancels the scheduled
/// cancel_issue
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `vault_id` - the id of this vault
/// * `event_channel` - the channel over which to signal events
/// * `issue_set` - all issue ids observed since vault started
pub async fn listen_for_issue_executes(
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
    event_channel: Sender<ProcessEvent>,
    issue_set: Arc<IssueIds>,
) -> Result<(), runtime::Error> {
    let vault_id = &vault_id;
    let event_channel = &event_channel;
    let issue_set = &issue_set;
    provider
        .on_event::<ExecuteIssueEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if event.vault_id == vault_id.clone() {
                    info!("Received execute issue event: {:?}", event);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel
                        .clone()
                        .send(ProcessEvent::Executed(event.issue_id))
                        .await;
                }
                issue_set.0.lock().await.remove(&event.issue_id);
            },
            |error| error!("Error reading issue event: {}", error.to_string()),
        )
        .await
}

/// Listen for all `CancelIssueEvent`s.
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `vault_id` - the id of this vault
/// * `issue_set` - all issue ids observed since vault started
pub async fn listen_for_issue_cancels(
    provider: Arc<PolkaBtcProvider>,
    issue_set: Arc<IssueIds>,
) -> Result<(), runtime::Error> {
    let issue_set = &issue_set;
    provider
        .on_event::<CancelIssueEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                issue_set.0.lock().await.remove(&event.issue_id);
            },
            |error| error!("Error reading cancel event: {}", error.to_string()),
        )
        .await
}
