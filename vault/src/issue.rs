use crate::cancellation::RequestEvent;
use crate::Error;
use bitcoin::{BitcoinCoreApi, BlockHash, Transaction, TransactionExt};
use futures::channel::mpsc::Sender;
use futures::{SinkExt, StreamExt};
use log::{error, info};
use runtime::{
    pallets::issue::{CancelIssueEvent, ExecuteIssueEvent, RequestIssueEvent},
    BtcAddress, BtcPublicKey, BtcRelayPallet, H256Le, IssuePallet, PolkaBtcProvider,
    PolkaBtcRuntime, UtilFuncs,
};
use sha2::{Digest, Sha256};
use sp_core::H256;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::hash::Hash;
use std::borrow::Borrow;

#[derive(Debug, Default)]
pub struct ReversibleHashMap<K, V>((HashMap<K, V>, HashMap<V, K>));

impl<K, V> ReversibleHashMap<K, V> where
    K: Hash + Eq + Copy + Default,
    V: Hash + Eq + Copy + Default
{ 
    pub fn new() -> ReversibleHashMap<K, V> {
        Default::default()
    }

    pub fn insert(&mut self, k: K, v: V) -> (Option<K>, Option<V>) {
        let k1 = self.0.0.insert(k, v);
        let k2 = self.0.1.insert(v, k);
        (k2, k1)
    }

    /// Remove the from the reversible map by the key.
    pub fn remove_key<Q: ?Sized>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        if let Some(v) = self.0.0.remove(k) {
            self.0.1.remove(&v);
            Some(v)
        } else {
            None
        }
    }

    /// Remove the from the reversible map by the value.
    pub fn remove_value<Q: ?Sized>(&mut self, v: &Q) -> Option<K>
    where
        V: Borrow<Q>,
        Q: Hash + Eq,
    {
        if let Some(k) = self.0.1.remove(v) {
            self.0.0.remove(&k);
            Some(k)
        } else {
            None
        }
    }

    /// Search the reversible map by value.
    pub fn contains_value<Q: ?Sized>(&self, v: &Q) -> bool
    where
        V: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.0.1.contains_key(v)
    }
}

pub struct IssueRequests(Mutex<ReversibleHashMap<H256, BtcAddress>>);

impl IssueRequests {
    pub fn new() -> Self {
        // TODO: fetch active issue ids from storage
        IssueRequests(Mutex::new(ReversibleHashMap::new()))
    }
}

/// execute issue requests on best-effort (i.e. don't retry on error),
/// returns `NoIncomingBlocks` if stream ends, otherwise runs forever
pub async fn process_issue_requests<B: BitcoinCoreApi + Send + Sync + 'static>(
    provider: &Arc<PolkaBtcProvider>,
    btc_rpc: &Arc<B>,
    issue_set: &Arc<IssueRequests>,
    num_confirmations: u32,
) -> Result<(), Error> {
    let mut stream = bitcoin::stream_in_chain_transactions(
        btc_rpc.clone(),
        btc_rpc.get_block_count()? as u32,
        num_confirmations,
    );

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

/// extract op_return output and check corresponding issue ids
async fn process_transaction_and_execute_issue<B: BitcoinCoreApi + Send + Sync + 'static>(
    provider: &Arc<PolkaBtcProvider>,
    btc_rpc: &Arc<B>,
    issue_set: &Arc<IssueRequests>,
    num_confirmations: u32,
    block_hash: BlockHash,
    transaction: Transaction,
) -> Result<(), Error> {
    let addresses = transaction.extract_output_addresses::<BtcAddress>()?;
    let mut issue_requests = issue_set.0.lock().await;
    if let Some(address) = addresses.iter().find(|&vout| issue_requests.contains_value(vout)) {
        // tx has output to address
        if let Some(issue_id) = issue_requests.remove_value(address) {
            info!("Executing issue with id {}", issue_id);

            // at this point we know that the transaction has `num_confirmations` on the bitcoin chain,
            // but the relay can introduce a delay, so wait until the relay also confirms the transaction.
            provider
                .wait_for_block_in_relay(
                    H256Le::from_bytes_le(&block_hash.to_vec()),
                    num_confirmations,
                )
                .await?;

            // found tx, submit proof
            let txid = transaction.txid();
            let raw_tx = btc_rpc.get_raw_tx_for(&txid, &block_hash)?;
            let proof = btc_rpc.get_proof_for(txid.clone(), &block_hash)?;

            // this will error if someone else executes the issue first
            provider
                .execute_issue(
                    issue_id,
                    H256Le::from_bytes_le(&txid.as_hash()),
                    proof,
                    raw_tx,
                )
                .await?;
        }
    }

    // no op_return or issue-id
    Ok(())
}

/// Import the deposit key using the on-chain key derivation scheme
fn add_new_deposit_key<B: BitcoinCoreApi + Send + Sync + 'static>(
    btc_rpc: &Arc<B>,
    secure_id: H256,
    public_key: BtcPublicKey,
) -> Result<(), Error> {
    let mut hasher = Sha256::default();
    // input compressed public key
    hasher.input(public_key.0.to_vec());
    // input issue id
    hasher.input(secure_id.as_bytes());
    btc_rpc.add_new_deposit_key(public_key, hasher.result().as_slice().to_vec())?;
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
pub async fn listen_for_issue_requests<B: BitcoinCoreApi + Send + Sync + 'static>(
    provider: Arc<PolkaBtcProvider>,
    btc_rpc: Arc<B>,
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

                    if let Err(e) = add_new_deposit_key(btc_rpc, event.issue_id, event.public_key) {
                        error!(
                            "Failed to add new deposit key #{}: {}",
                            event.issue_id,
                            e.to_string()
                        );
                    }
                }

                issue_set.0.lock().await.insert(event.issue_id, event.btc_address);
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
/// * `event_channel` - the channel over which to signal events
/// * `issue_set` - all issue ids observed since vault started
pub async fn listen_for_issue_executes(
    provider: Arc<PolkaBtcProvider>,
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
                    let _ = event_channel
                        .clone()
                        .send(RequestEvent::Executed(event.issue_id))
                        .await;
                }
                issue_set.0.lock().await.remove_key(&event.issue_id);
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
/// * `issue_set` - all issue ids observed since vault started
pub async fn listen_for_issue_cancels(
    provider: Arc<PolkaBtcProvider>,
    issue_set: Arc<IssueRequests>,
) -> Result<(), runtime::Error> {
    let issue_set = &issue_set;
    provider
        .on_event::<CancelIssueEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                issue_set.0.lock().await.remove_key(&event.issue_id);
            },
            |error| error!("Error reading cancel event: {}", error.to_string()),
        )
        .await
}
