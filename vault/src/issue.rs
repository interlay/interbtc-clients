use crate::{
    delay::RandomDelay, metrics::publish_expected_bitcoin_balance, Error, Event, IssueRequests, VaultIdManager,
};
use bitcoin::{BlockHash, Error as BitcoinError, PublicKey, Transaction, TransactionExt};
use futures::{channel::mpsc::Sender, future, SinkExt, StreamExt, TryFutureExt};
use runtime::{
    BtcAddress, BtcPublicKey, BtcRelayPallet, CancelIssueEvent, ExecuteIssueEvent, H256Le, InterBtcIssueRequest,
    InterBtcParachain, IssuePallet, IssueRequestStatus, PartialAddress, PrettyPrint, RequestIssueEvent, UtilFuncs,
    VaultId, H256,
};
use service::{DynBitcoinCoreApi, Error as ServiceError};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

// initialize `issue_set` with currently open issues, and return the block height
// from which to start watching the bitcoin chain
pub(crate) async fn initialize_issue_set(
    bitcoin_core: &DynBitcoinCoreApi,
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
        issue_set.insert(issue_id, *request.btc_address);
    }

    Ok(btc_start_height)
}

/// execute issue requests on best-effort (i.e. don't retry on error),
/// returns an error if stream ends, otherwise runs forever
pub async fn process_issue_requests(
    bitcoin_core: DynBitcoinCoreApi,
    btc_parachain: InterBtcParachain,
    issue_set: Arc<IssueRequests>,
    btc_start_height: u32,
    num_confirmations: u32,
    random_delay: Arc<Box<dyn RandomDelay + Send + Sync>>,
) -> Result<(), ServiceError<Error>> {
    // NOTE: we should not stream transactions if using the light client
    // since it is quite expensive to fetch all transactions per block
    let mut stream =
        bitcoin::stream_in_chain_transactions(bitcoin_core.clone(), btc_start_height, num_confirmations).await;

    while let Some(result) = stream.next().await {
        match result {
            Ok((block_hash, transaction)) => tokio::spawn(
                process_transaction_and_execute_issue(
                    bitcoin_core.clone(),
                    btc_parachain.clone(),
                    issue_set.clone(),
                    num_confirmations,
                    block_hash,
                    transaction,
                    random_delay.clone(),
                )
                .map_err(|e| {
                    tracing::warn!("Failed to execute issue request: {}", e.to_string());
                }),
            ),
            Err(err) => return Err(err.into()),
        };
    }

    // stream closed, restart client
    Err(ServiceError::ClientShutdown)
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Default, PartialEq, Debug)]
struct RescanStatus {
    newest_issue_height: u32,
    queued_rescan_range: Option<(usize, usize)>, // start, end(including)
}
impl RescanStatus {
    // there was a bug pre-v2 that set rescanning status to an invalid range.
    // by changing the keyname we effectively force a reset
    const KEY: &str = "rescan-status-v2";
    fn update(&mut self, mut issues: Vec<InterBtcIssueRequest>, current_bitcoin_height: usize) {
        // Only look at issues that haven't been processed yet
        issues.retain(|issue| issue.opentime > self.newest_issue_height);

        for issue in issues {
            self.newest_issue_height = self.newest_issue_height.max(issue.opentime);
            let begin = match self.queued_rescan_range {
                Some((begin, _)) => begin.min(issue.btc_height as usize),
                None => issue.btc_height as usize,
            };
            // We used to have a bug with syncing that could result in `current_bitcoin_height`
            // being less than `begin`. Even though that issue has been fixed, for extra safety
            // we clip the end range. This way, if there is another syncing bug, we'd handle it
            // here correctly anyway, assuming that the unprocessed blocks will also scan for the
            // newly added addresses.
            let end = begin.max(current_bitcoin_height);
            self.queued_rescan_range = Some((begin, end));
        }
    }

    /// prune the scanning range: bitcoin can't scan before prune_height. This function
    /// modifies the range in self to be within scannable range, and returns the
    /// unscannable range
    fn prune(&mut self, btc_pruned_start_height: usize) -> Option<(usize, usize)> {
        if let Some((ref mut start, _)) = self.queued_rescan_range {
            if *start < btc_pruned_start_height {
                let ret = (*start, btc_pruned_start_height.saturating_sub(1));
                *start = btc_pruned_start_height;
                return Some(ret);
            }
        }
        None
    }

    /// updates self as if max_blocks were processed. Returns the chunk to rescan now.
    fn process_blocks(&mut self, max_blocks: usize) -> Option<(usize, usize)> {
        let (start, end) = self.queued_rescan_range?;
        let chunk_end = end.min(start.saturating_add(max_blocks).saturating_sub(1));

        if chunk_end == end {
            self.queued_rescan_range = None; // this will be the last chunk to scan
        } else {
            self.queued_rescan_range = Some((chunk_end + 1, end));
        }
        Some((start, chunk_end))
    }

    fn get(vault_id: &VaultId, db: &crate::system::DatabaseConfig) -> Result<Self, Error> {
        Ok(db.get(vault_id, Self::KEY)?.unwrap_or_default())
    }
    fn store(&self, vault_id: &VaultId, db: &crate::system::DatabaseConfig) -> Result<(), Error> {
        db.put(vault_id, Self::KEY, self)?;
        Ok(())
    }
}

pub async fn add_keys_from_past_issue_request(
    bitcoin_core: &DynBitcoinCoreApi,
    btc_parachain: &InterBtcParachain,
    vault_id: &VaultId,
    db: &crate::system::DatabaseConfig,
) -> Result<(), Error> {
    let mut scanning_status = RescanStatus::get(vault_id, db)?;
    tracing::info!("initial status: = {scanning_status:?}");

    // TODO: remove filter since we use a shared wallet
    let issue_requests: Vec<_> = btc_parachain
        .get_vault_issue_requests(btc_parachain.get_account_id().clone())
        .await?
        .into_iter()
        .filter(|(_, issue)| &issue.vault == vault_id)
        .collect();

    for (issue_id, request) in issue_requests.clone().into_iter() {
        if let Err(e) = add_new_deposit_key(bitcoin_core, issue_id, request.btc_public_key).await {
            tracing::error!("Failed to add deposit key #{}: {}", issue_id, e.to_string());
        }
    }

    // read height only _after_ the last add_new_deposit_key. If a new block arrives
    // while we rescan, bitcoin core will correctly recognize addressed associated with the
    // privkey
    let btc_end_height = bitcoin_core.get_block_count().await? as usize;
    let btc_pruned_start_height = bitcoin_core.get_pruned_height().await? as usize;

    let issues = issue_requests.clone().into_iter().map(|(_key, issue)| issue).collect();
    scanning_status.update(issues, btc_end_height);

    // use electrs to scan the portion that is not scannable by bitcoin core
    if let Some((start, end)) = scanning_status.prune(btc_pruned_start_height) {
        tracing::info!(
            "Also checking electrs for issue requests between {} and {}...",
            start,
            end
        );
        bitcoin_core
            .rescan_electrs_for_addresses(
                issue_requests
                    .into_iter()
                    .filter_map(|(_, request)| {
                        if (request.btc_height as usize) < btc_pruned_start_height {
                            Some(request.btc_address.to_address(bitcoin_core.network()).ok()?)
                        } else {
                            None
                        }
                    })
                    .collect(),
            )
            .await?;
    }

    // save progress s.t. we don't rescan pruned range again if we crash now
    scanning_status.store(vault_id, db)?;

    let mut chunk_size = 1;
    // rescan the blockchain in chunks, so that we can save progress. The code below
    // aims to have each chunk take about 10 seconds (arbitrarily chosen value).
    while let Some((chunk_start, chunk_end)) = scanning_status.process_blocks(chunk_size) {
        tracing::info!("Rescanning bitcoin chain from {} to {}...", chunk_start, chunk_end);

        let start_time = Instant::now();

        bitcoin_core.rescan_blockchain(chunk_start, chunk_end).await?;

        // with the code below the rescan time should remain between 5 and 20 seconds
        // after the first couple of rounds.
        if start_time.elapsed() < Duration::from_secs(10) {
            chunk_size = chunk_size.saturating_mul(2);
        } else {
            chunk_size = (chunk_size.checked_div(2).ok_or(Error::ArithmeticUnderflow)?).max(1);
        }

        scanning_status.store(vault_id, db)?;
    }

    Ok(())
}

/// execute issue requests with a matching Bitcoin payment
async fn process_transaction_and_execute_issue(
    bitcoin_core: DynBitcoinCoreApi,
    btc_parachain: InterBtcParachain,
    issue_set: Arc<IssueRequests>,
    num_confirmations: u32,
    block_hash: BlockHash,
    transaction: Transaction,
    random_delay: Arc<Box<dyn RandomDelay + Send + Sync>>,
) -> Result<(), Error> {
    let addresses: Vec<BtcAddress> = transaction
        .extract_output_addresses()
        .into_iter()
        .filter_map(|payload| BtcAddress::from_payload(payload).ok())
        .collect();
    let mut issue_requests = issue_set.lock().await;
    if let Some((issue_id, address)) = addresses.iter().find_map(|address| {
        let issue_id = issue_requests.get_key_for_value(address)?;
        Some((*issue_id, *address))
    }) {
        let issue = btc_parachain.get_issue_request(issue_id).await?;
        let payload = if let Ok(payload) = address.to_payload() {
            payload
        } else {
            return Ok(());
        };
        // tx has output to address
        match transaction.get_payment_amount_to(payload) {
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
                    .wait_for_block_in_relay(H256Le::from_bytes_le(&block_hash), Some(num_confirmations))
                    .await?;

                // wait a random amount of blocks, to avoid all vaults flooding the parachain with
                // this transaction
                (*random_delay).delay(&issue_id.to_fixed_bytes()).await?;
                let issue = btc_parachain.get_issue_request(issue_id).await?;
                if let IssueRequestStatus::Completed = issue.status {
                    tracing::info!("Issue {} has already been executed - doing nothing.", issue_id);
                    return Ok(());
                }

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
async fn add_new_deposit_key(
    bitcoin_core: &DynBitcoinCoreApi,
    secure_id: H256,
    public_key: BtcPublicKey,
) -> Result<(), Error> {
    let mut hasher = Sha256::default();
    // input compressed public key
    hasher.input(public_key.0);
    // input issue id
    hasher.input(secure_id.as_bytes());

    bitcoin_core
        .add_new_deposit_key(
            PublicKey::from_slice(&public_key.0).map_err(BitcoinError::KeyError)?,
            hasher.result().as_slice().to_vec(),
        )
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
pub async fn listen_for_issue_requests(
    btc_rpc: VaultIdManager,
    btc_parachain: InterBtcParachain,
    event_channel: Sender<Event>,
    issue_set: Arc<IssueRequests>,
) -> Result<(), ServiceError<Error>> {
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

                    let _ = publish_expected_bitcoin_balance(&vault, btc_parachain.clone()).await;

                    if let Err(e) = add_new_deposit_key(&vault.btc_rpc, *event.issue_id, event.vault_public_key).await {
                        tracing::error!("Failed to add new deposit key #{}: {}", *event.issue_id, e.to_string());
                    }
                }

                tracing::trace!(
                    "watching issue #{} for payment to {:?}",
                    *event.issue_id,
                    event.vault_address
                );
                issue_set.insert(*event.issue_id, *event.vault_address).await;
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
) -> Result<(), ServiceError<Error>> {
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
                    let _ = event_channel.clone().send(Event::Executed(*event.issue_id)).await;
                }

                tracing::trace!("issue #{} executed, no longer watching", *event.issue_id);
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
) -> Result<(), ServiceError<Error>> {
    let issue_set = &issue_set;
    btc_parachain
        .on_event::<CancelIssueEvent, _, _, _>(
            |event| async move {
                tracing::trace!("issue #{} cancelled, no longer watching", *event.issue_id);
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
    use runtime::{
        subxt::utils::Static,
        AccountId,
        CurrencyId::Token,
        TokenSymbol::{DOT, IBTC, INTR},
    };

    fn dummy_issues(heights: Vec<(u32, usize)>) -> Vec<InterBtcIssueRequest> {
        heights
            .into_iter()
            .map(|(opentime, btc_height)| InterBtcIssueRequest {
                opentime,
                btc_height: btc_height as u32,
                amount: Default::default(),
                btc_address: Static(Default::default()),
                fee: Default::default(),
                griefing_collateral: Default::default(),
                griefing_currency: Token(INTR),
                period: Default::default(),
                requester: AccountId::new([1u8; 32]),
                btc_public_key: BtcPublicKey { 0: [0; 33] },
                status: IssueRequestStatus::Pending,
                vault: VaultId::new(AccountId::new([1u8; 32]), Token(DOT), runtime::Token(IBTC)),
            })
            .collect()
    }

    #[test]
    fn test_rescan_status_update() {
        let mut status = RescanStatus::default();
        let current_height = 50;
        let issues = dummy_issues(vec![(2, 23), (4, 20), (3, 30)]);

        status.update(issues, current_height);

        assert_eq!(
            status,
            RescanStatus {
                newest_issue_height: 4,
                queued_rescan_range: Some((20, current_height))
            }
        );

        // check that status does not change if issues have already been registered
        let processed_issues = dummy_issues(vec![
            (2, current_height * 2),
            (4, current_height * 2),
            (3, current_height * 2),
        ]);
        status.update(processed_issues, current_height);
        assert_eq!(
            status,
            RescanStatus {
                newest_issue_height: 4,
                queued_rescan_range: Some((20, current_height))
            }
        );

        // check that status does not change if new issue doesn't expand current range
        let processed_issues = dummy_issues(vec![
            (2, current_height * 2),
            (5, 45), // new, but already included in the to-scan range
            (3, current_height * 2),
        ]);
        status.update(processed_issues.clone(), current_height);
        assert_eq!(
            status,
            RescanStatus {
                newest_issue_height: 5,
                queued_rescan_range: Some((20, current_height))
            }
        );

        // check that status decreases start of range if issue requires it
        let more_issues = dummy_issues(vec![
            (2, 41),
            (6, 15), // new this one has not been processed yet, and expands the range
            (3, 41),
        ]);
        status.update(more_issues, current_height);
        assert_eq!(
            status,
            RescanStatus {
                newest_issue_height: 6,
                queued_rescan_range: Some((15, current_height))
            }
        );

        // check that status end of range does not expand if there are no new issues
        status.update(processed_issues, current_height + 1);
        assert_eq!(
            status,
            RescanStatus {
                newest_issue_height: 6,
                queued_rescan_range: Some((15, current_height))
            }
        );

        // check that status end of range does expand if there are new issues
        let more_issues = dummy_issues(vec![
            (2, 41),
            (7, current_height + 2), // new this one has not been processed yet, and expands the range
            (3, 41),
        ]);
        status.update(more_issues, current_height + 2);
        assert_eq!(
            status,
            RescanStatus {
                newest_issue_height: 7,
                queued_rescan_range: Some((15, current_height + 2))
            }
        );
    }

    #[test]
    fn test_process_blocks() {
        let mut status = RescanStatus {
            newest_issue_height: 4,
            queued_rescan_range: Some((20, 40)),
        };

        assert_eq!(status.process_blocks(15), Some((20, 34)));
        assert_eq!(
            status,
            RescanStatus {
                newest_issue_height: 4,
                queued_rescan_range: Some((35, 40))
            }
        );

        assert_eq!(status.process_blocks(15), Some((35, 40)));
        assert_eq!(
            status,
            RescanStatus {
                newest_issue_height: 4,
                queued_rescan_range: None
            }
        );

        assert_eq!(status.process_blocks(15), None);
        assert_eq!(
            status,
            RescanStatus {
                newest_issue_height: 4,
                queued_rescan_range: None
            }
        );
    }

    #[test]
    fn test_process_blocks_boundary() {
        let mut status = RescanStatus {
            newest_issue_height: 4,
            queued_rescan_range: Some((20, 40)),
        };

        assert_eq!(status.process_blocks(21), Some((20, 40)));
        assert_eq!(
            status,
            RescanStatus {
                newest_issue_height: 4,
                queued_rescan_range: None
            }
        );

        assert_eq!(status.process_blocks(15), None);
    }
}
