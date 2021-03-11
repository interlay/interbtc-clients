use crate::cancellor::{CancellationScheduler, IssueCanceller, RequestEvent};
use crate::types::IssueRequests;
use crate::Error;
use async_channel as mpmc;
use async_trait::async_trait;
use bitcoin::{BitcoinCoreApi, BlockHash, Transaction, TransactionExt};
use futures::StreamExt;
use log::*;
use runtime::{
    pallets::issue::{CancelIssueEvent, ExecuteIssueEvent, RequestIssueEvent},
    BtcAddress, BtcPublicKey, BtcRelayPallet, Error as RuntimeError, H256Le, IssuePallet,
    PolkaBtcHeader, PolkaBtcProvider, PolkaBtcRuntime, Service, UtilFuncs,
};

use sha2::{Digest, Sha256};
use sp_core::H256;

#[derive(Clone)]
pub struct IssueServiceConfig<B> {
    /// the bitcoin RPC handle
    pub bitcoin_core: B,
}

pub struct IssueService<B> {
    btc_parachain: PolkaBtcProvider,
    bitcoin_core: B,
    /// all issue ids observed since vault started
    issue_set: IssueRequests,
    issue_event_tx: mpmc::Sender<RequestEvent>,
    issue_event_rx: mpmc::Receiver<RequestEvent>,
}

#[async_trait]
impl<B: BitcoinCoreApi + Send + Sync + 'static> Service<IssueServiceConfig<B>, PolkaBtcProvider>
    for IssueService<B>
{
    async fn connect(
        btc_parachain: PolkaBtcProvider,
        config: IssueServiceConfig<B>,
    ) -> Result<(), RuntimeError> {
        IssueService::new(btc_parachain, config)
            .run_service()
            .await
            .map_err(|_| RuntimeError::ChannelClosed)
    }
}

impl<B: BitcoinCoreApi + Send + Sync + 'static> IssueService<B> {
    pub fn new(btc_parachain: PolkaBtcProvider, config: IssueServiceConfig<B>) -> Self {
        let (issue_event_tx, issue_event_rx) = mpmc::bounded::<RequestEvent>(32);

        Self {
            btc_parachain,
            bitcoin_core: config.bitcoin_core,
            issue_event_tx,
            issue_event_rx,
            issue_set: IssueRequests::new(),
        }
    }

    async fn add_keys_from_past_issue_request(&self) -> Result<(), Error> {
        for (issue_id, request) in self
            .btc_parachain
            .get_vault_issue_requests(self.btc_parachain.get_account_id().clone())
            .await?
            .into_iter()
        {
            info!("Found issue with id {}", issue_id);
            if let Err(e) =
                add_new_deposit_key(&self.bitcoin_core, issue_id, request.btc_public_key).await
            {
                error!("Failed to add deposit key #{}: {}", issue_id, e.to_string());
            }
        }
        Ok(())
    }

    /// Listen for RequestIssueEvent directed at this vault. Schedules a cancellation of
    /// the received issue.
    async fn listen_for_issue_requests(&self) -> Result<(), RuntimeError> {
        self.btc_parachain
            .on_event::<RequestIssueEvent<PolkaBtcRuntime>, _, _, _>(
                |event| async move {
                    if &event.vault_id == self.btc_parachain.get_account_id() {
                        info!("Received request issue event: {:?}", event);
                        // try to send the event, but ignore the returned result since
                        // the only way it can fail is if the channel is closed
                        let _ = self.issue_event_tx.clone().send(RequestEvent::Opened).await;

                        if let Err(e) = add_new_deposit_key(
                            &self.bitcoin_core,
                            event.issue_id,
                            event.vault_public_key,
                        )
                        .await
                        {
                            error!(
                                "Failed to add new deposit key #{}: {}",
                                event.issue_id,
                                e.to_string()
                            );
                        }
                    }

                    trace!(
                        "watching issue #{} for payment to {}",
                        event.issue_id,
                        event.vault_btc_address
                    );
                    let mut issue_requests = self.issue_set.lock().await;
                    issue_requests.insert(event.issue_id, event.vault_btc_address);
                },
                |error| error!("Error reading request issue event: {}", error.to_string()),
            )
            .await
    }

    /// Listen for ExecuteIssueEvent directed at this vault. Cancels the scheduled
    /// cancel_issue
    async fn listen_for_issue_executes(&self) -> Result<(), RuntimeError> {
        self.btc_parachain
            .on_event::<ExecuteIssueEvent<PolkaBtcRuntime>, _, _, _>(
                |event| async move {
                    if &event.vault_id == self.btc_parachain.get_account_id() {
                        info!("Received execute issue event: {:?}", event);
                        // try to send the event, but ignore the returned result since
                        // the only way it can fail is if the channel is closed
                        let _ = self
                            .issue_event_tx
                            .clone()
                            .send(RequestEvent::Executed(event.issue_id))
                            .await;
                    }

                    trace!("issue #{} executed, no longer watching", event.issue_id);
                    self.issue_set.remove_issue(&event.issue_id).await;
                },
                |error| error!("Error reading execute issue event: {}", error.to_string()),
            )
            .await
    }

    /// Listens for `CancelIssueEvent`.
    async fn listen_for_issue_cancels(&self) -> Result<(), RuntimeError> {
        self.btc_parachain
            .on_event::<CancelIssueEvent<PolkaBtcRuntime>, _, _, _>(
                |event| async move {
                    trace!("issue #{} cancelled, no longer watching", event.issue_id);
                    self.issue_set.remove_issue(&event.issue_id).await;
                },
                |error| error!("Error reading cancel issue event: {}", error.to_string()),
            )
            .await
    }

    async fn listen_for_new_blocks(
        &self,
        issue_block_tx: &mpmc::Sender<PolkaBtcHeader>,
    ) -> Result<(), RuntimeError> {
        self.btc_parachain
            .on_block(move |header| async move {
                issue_block_tx
                    .clone()
                    .send(header.clone())
                    .await
                    .map_err(|_| RuntimeError::ChannelClosed)?;
                Ok(())
            })
            .await
    }

    async fn listen_for_cancelled_issues(&self) -> Result<(), RuntimeError> {
        let vault_id = self.btc_parachain.get_account_id().clone();
        let (block_tx, block_rx) = mpmc::bounded::<PolkaBtcHeader>(16);
        let block_listener = self.listen_for_new_blocks(&block_tx);
        let mut scheduler = CancellationScheduler::new(self.btc_parachain.clone(), vault_id);

        let _ = futures::future::join(
            Box::pin(block_listener),
            Box::pin(
                scheduler
                    .handle_cancellation::<IssueCanceller>(block_rx, self.issue_event_rx.clone()),
            ),
        )
        .await;
        Ok(())
    }

    async fn run_service(&mut self) -> Result<(), Error> {
        self.add_keys_from_past_issue_request().await?;

        let _ = futures::future::join4(
            Box::pin(self.listen_for_issue_requests()),
            Box::pin(self.listen_for_issue_executes()),
            Box::pin(self.listen_for_issue_cancels()),
            Box::pin(self.listen_for_cancelled_issues()),
        )
        .await;
        Ok(())
    }
}

/// Import the deposit key using the on-chain key derivation scheme
async fn add_new_deposit_key<B: BitcoinCoreApi + Send + Sync + 'static>(
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

#[derive(Clone)]
pub struct IssueExecutionServiceConfig<B> {
    /// the bitcoin RPC handle
    pub bitcoin_core: B,
    /// the number of bitcoin confirmation to await
    pub num_confirmations: u32,
}

pub struct IssueExecutionService<B> {
    btc_parachain: PolkaBtcProvider,
    bitcoin_core: B,
    issue_set: IssueRequests,
    num_confirmations: u32,
}

#[async_trait]
impl<B: BitcoinCoreApi + Clone + Send + Sync + 'static>
    Service<IssueExecutionServiceConfig<B>, PolkaBtcProvider> for IssueExecutionService<B>
{
    async fn connect(
        btc_parachain: PolkaBtcProvider,
        config: IssueExecutionServiceConfig<B>,
    ) -> Result<(), RuntimeError> {
        IssueExecutionService::new(btc_parachain, config)
            .run_service()
            .await
            .map_err(|_| RuntimeError::ChannelClosed)
    }
}

impl<B: BitcoinCoreApi + Clone + Send + Sync + 'static> IssueExecutionService<B> {
    pub fn new(btc_parachain: PolkaBtcProvider, config: IssueExecutionServiceConfig<B>) -> Self {
        Self {
            btc_parachain,
            bitcoin_core: config.bitcoin_core,
            issue_set: IssueRequests::new(),
            num_confirmations: config.num_confirmations,
        }
    }

    /// execute issue requests on best-effort (i.e. don't retry on error),
    /// returns `NoIncomingBlocks` if stream ends, otherwise runs forever
    async fn run_service(&mut self) -> Result<(), Error> {
        let btc_parachain = &self.btc_parachain;
        let bitcoin_core = &self.bitcoin_core;
        let issue_set = &self.issue_set;
        let num_confirmations = self.num_confirmations;

        let btc_start_height = initialize_issue_set(btc_parachain, bitcoin_core, issue_set).await?;

        let mut stream = bitcoin::stream_in_chain_transactions(
            self.bitcoin_core.clone(),
            btc_start_height,
            num_confirmations,
        )
        .await;

        while let Some(Ok((block_hash, transaction))) = stream.next().await {
            if let Err(e) = process_transaction_and_execute_issue(
                btc_parachain,
                bitcoin_core,
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
}

// initialize `issue_set` with currently open issues, and return the block height
// from which to start watching the bitcoin chain
async fn initialize_issue_set<B: BitcoinCoreApi + Send + Sync + 'static>(
    btc_parachain: &PolkaBtcProvider,
    bitcoin_core: &B,
    issue_set: &IssueRequests,
) -> Result<u32, Error> {
    let mut issue_set = issue_set.lock().await;

    let requests = btc_parachain.get_all_active_issues().await?;
    // find the height of bitcoin chain corresponding to the earliest open_time
    let btc_start_height = match requests.iter().map(|(_, request)| request.opentime).min() {
        Some(x) => btc_parachain.get_blockchain_height_at(x).await?,
        None => bitcoin_core.get_block_count().await? as u32, // no open issues, start at current height
    };

    for (issue_id, request) in requests.into_iter() {
        issue_set.insert(issue_id, request.btc_address);
    }

    Ok(btc_start_height)
}

/// execute issue requests with a matching Bitcoin payment
async fn process_transaction_and_execute_issue<B: BitcoinCoreApi + Send + Sync + 'static>(
    provider: &PolkaBtcProvider,
    btc_rpc: &B,
    issue_set: &IssueRequests,
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
                    .wait_for_block_in_relay(
                        H256Le::from_bytes_le(&block_hash.to_vec()),
                        num_confirmations,
                    )
                    .await?;

                // found tx, submit proof
                let txid = transaction.txid();
                let raw_tx = btc_rpc.get_raw_tx_for(&txid, &block_hash).await?;
                let proof = btc_rpc.get_proof_for(txid.clone(), &block_hash).await?;

                info!("Executing issue with id {}", issue_id);

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
    }

    // no op_return or issue-id
    Ok(())
}
