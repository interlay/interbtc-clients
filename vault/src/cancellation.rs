use super::Error;
use crate::execution::parachain_blocks_to_bitcoin_blocks_rounded_up;
use async_trait::async_trait;
use futures::{channel::mpsc::Receiver, *};
use runtime::{
    AccountId, BlockNumber, Error as RuntimeError, IssuePallet, IssueRequestStatus, ReplacePallet,
    ReplaceRequestStatus, SecurityPallet, UtilFuncs,
};
use std::marker::{Send, Sync};

use runtime::H256;

pub enum Event {
    /// new issue requested / replace accepted
    Opened,
    /// issue / replace successfully executed
    Executed(H256),
    /// new *active* parachain block
    ParachainBlock(BlockNumber),
    /// new bitcoin block included in relay
    BitcoinBlock(u32),
}

pub struct CancellationScheduler<P: IssuePallet + ReplacePallet + UtilFuncs + Clone> {
    parachain_rpc: P,
    vault_id: AccountId,
    parachain_height: BlockNumber,
    bitcoin_height: u32,
}

#[derive(Copy, Clone, Debug, PartialEq)]
struct ActiveRequest {
    id: H256,
    parachain_deadline_height: u32,
    bitcoin_deadline_height: u32,
}

pub struct UnconvertedOpenTime {
    id: H256,
    parachain_open_height: u32,
    bitcoin_open_height: u32,
    period: u32,
}

#[derive(PartialEq, Debug)]
enum ListState {
    Valid,
    Invalid,
}

/// Trait to abstract over issue & replace cancellation
#[async_trait]
pub trait Canceller<P> {
    /// either "replace" or "issue"; used for logging
    const TYPE_NAME: &'static str;

    /// Gets a list of open replace/issue requests
    async fn get_open_requests(parachain_rpc: &P, vault_id: AccountId) -> Result<Vec<UnconvertedOpenTime>, Error>
    where
        P: 'async_trait;

    /// Gets the timeout period in number of blocks
    async fn get_period(parachain_rpc: &P) -> Result<u32, Error>
    where
        P: 'async_trait;

    /// Cancels the issue/replace
    async fn cancel_request(parachain_rpc: &P, request_id: H256) -> Result<(), Error>
    where
        P: 'async_trait;
}

pub struct IssueCanceller;

#[async_trait]
impl<P: IssuePallet + ReplacePallet + Clone + Send + Sync> Canceller<P> for IssueCanceller {
    const TYPE_NAME: &'static str = "issue";

    async fn get_open_requests(parachain_rpc: &P, vault_id: AccountId) -> Result<Vec<UnconvertedOpenTime>, Error>
    where
        P: 'async_trait,
    {
        let ret = parachain_rpc
            .get_vault_issue_requests(vault_id)
            .await?
            .iter()
            .filter(|(_, issue)| issue.status == IssueRequestStatus::Pending)
            .map(|(id, issue)| UnconvertedOpenTime {
                id: *id,
                parachain_open_height: issue.opentime,
                bitcoin_open_height: issue.btc_height,
                period: issue.period,
            })
            .collect();
        Ok(ret)
    }

    async fn get_period(parachain_rpc: &P) -> Result<u32, Error>
    where
        P: 'async_trait,
    {
        Ok(parachain_rpc.get_issue_period().await?)
    }

    async fn cancel_request(parachain_rpc: &P, request_id: H256) -> Result<(), Error>
    where
        P: 'async_trait,
    {
        Ok(parachain_rpc.cancel_issue(request_id).await?)
    }
}

pub struct ReplaceCanceller;

#[async_trait]
impl<P: IssuePallet + ReplacePallet + Send + Sync> Canceller<P> for ReplaceCanceller {
    const TYPE_NAME: &'static str = "replace";

    async fn get_open_requests(parachain_rpc: &P, vault_id: AccountId) -> Result<Vec<UnconvertedOpenTime>, Error>
    where
        P: 'async_trait,
    {
        let ret = parachain_rpc
            .get_new_vault_replace_requests(vault_id)
            .await?
            .iter()
            .filter(|(_, replace)| replace.status == ReplaceRequestStatus::Pending)
            .map(|(id, replace)| UnconvertedOpenTime {
                id: *id,
                parachain_open_height: replace.accept_time,
                bitcoin_open_height: replace.btc_height,
                period: replace.period,
            })
            .collect();
        Ok(ret)
    }

    async fn get_period(parachain_rpc: &P) -> Result<u32, Error>
    where
        P: 'async_trait,
    {
        Ok(parachain_rpc.get_replace_period().await?)
    }

    async fn cancel_request(parachain_rpc: &P, request_id: H256) -> Result<(), Error>
    where
        P: 'async_trait,
    {
        Ok(parachain_rpc.cancel_replace(request_id).await?)
    }
}

// verbose drain_filter
fn drain_expired(requests: &mut Vec<ActiveRequest>, current_height: u32, bitcoin_height: u32) -> Vec<ActiveRequest> {
    let mut expired = Vec::new();
    let has_expired = |request: &ActiveRequest| {
        current_height > request.parachain_deadline_height && bitcoin_height > request.bitcoin_deadline_height
    };
    let mut i = 0;
    while i != requests.len() {
        if has_expired(&requests[i]) {
            let req = requests.remove(i);
            expired.push(req);
        } else {
            i += 1;
        }
    }
    expired
}

/// The actual cancellation scheduling and handling
impl<P: IssuePallet + ReplacePallet + UtilFuncs + SecurityPallet + Clone> CancellationScheduler<P> {
    pub fn new(
        parachain_rpc: P,
        parachain_height: BlockNumber,
        bitcoin_height: u32,
        vault_id: AccountId,
    ) -> CancellationScheduler<P> {
        CancellationScheduler {
            parachain_rpc,
            vault_id,
            bitcoin_height,
            parachain_height,
        }
    }

    /// Listens for issuing events (i.e. issue received/executed). When
    /// the issue period has expired without the issue having been executed,
    /// this function will attempt to call cancel_event to get the collateral back.
    /// On start, queries open issues and schedules cancellation for these as well.
    ///
    /// # Arguments
    ///
    /// *`event_listener`: channel that signals relevant events _for this vault_.
    pub async fn handle_cancellation<T: Canceller<P>>(
        mut self,
        mut event_listener: Receiver<Event>,
    ) -> Result<(), RuntimeError> {
        let mut list_state = ListState::Invalid;
        let mut active_requests: Vec<ActiveRequest> = vec![];

        loop {
            let event = event_listener.next().await.ok_or(RuntimeError::ChannelClosed)?;

            list_state = self.process_event::<T>(event, &mut active_requests, list_state).await?;
        }
    }

    async fn cancel_requests<T: Canceller<P>>(&self, active_requests: &mut Vec<ActiveRequest>) -> ListState {
        let cancellable_requests = drain_expired(active_requests, self.parachain_height, self.bitcoin_height);

        for request in cancellable_requests {
            match T::cancel_request(&self.parachain_rpc, request.id).await {
                Ok(_) => tracing::info!("Canceled {} #{:?}", T::TYPE_NAME, request.id),
                Err(e) => {
                    // failed to cancel; get up-to-date request list in next iteration
                    tracing::error!("Failed to cancel {}: {}", T::TYPE_NAME, e);
                    return ListState::Invalid;
                }
            }
        }
        ListState::Valid
    }

    /// Handles one timeout or event_listener event. This method is split from handle_cancellation for
    /// testing purposes
    async fn process_event<T: Canceller<P>>(
        &mut self,
        event: Event,
        active_requests: &mut Vec<ActiveRequest>,
        list_state: ListState,
    ) -> Result<ListState, RuntimeError> {
        // try to get an up-to-date list of requests if we don't have it yet
        if let ListState::Invalid = list_state {
            match self.get_open_requests::<T>().await {
                Ok(x) => {
                    *active_requests = x;
                }
                Err(e) => {
                    active_requests.clear();
                    tracing::error!("Failed to query open {}s: {}", T::TYPE_NAME, e);
                }
            }
        }

        match event {
            Event::ParachainBlock(height) => {
                tracing::trace!(
                    "Received parachain block at active height {} for {}",
                    height,
                    T::TYPE_NAME
                );
                self.parachain_height = height;
                Ok(self.cancel_requests::<T>(active_requests).await)
            }
            Event::BitcoinBlock(height) => {
                tracing::trace!("Received Bitcoin block at height {} for {}", height, T::TYPE_NAME);
                self.bitcoin_height = height;
                Ok(self.cancel_requests::<T>(active_requests).await)
            }
            Event::Executed(id) => {
                tracing::debug!("Received event: executed {} #{}", T::TYPE_NAME, id);
                active_requests.retain(|x| x.id != id);
                Ok(ListState::Valid)
            }
            Event::Opened => {
                tracing::debug!("Received event: opened {}", T::TYPE_NAME);
                Ok(ListState::Invalid)
            }
        }
    }

    /// Gets a list of requests that have been requested from this vault
    async fn get_open_requests<T: Canceller<P>>(&mut self) -> Result<Vec<ActiveRequest>, Error> {
        let open_requests = T::get_open_requests(&self.parachain_rpc, self.vault_id.clone()).await?;

        if open_requests.is_empty() {
            return Ok(vec![]);
        }

        // get current block height and request period
        let global_period = T::get_period(&self.parachain_rpc).await?;

        let ret = open_requests
            .iter()
            .map(
                |UnconvertedOpenTime {
                     id,
                     parachain_open_height,
                     bitcoin_open_height,
                     period: local_period,
                 }| {
                    let period = global_period.max(*local_period);

                    let parachain_deadline_height = parachain_open_height
                        .checked_add(period)
                        .ok_or(Error::ArithmeticOverflow)?;

                    let bitcoin_deadline_height = bitcoin_open_height
                        .checked_add(parachain_blocks_to_bitcoin_blocks_rounded_up(period)?)
                        .ok_or(Error::ArithmeticOverflow)?;

                    Ok(ActiveRequest {
                        id: *id,
                        parachain_deadline_height,
                        bitcoin_deadline_height,
                    })
                },
            )
            .collect::<Result<Vec<ActiveRequest>, Error>>()?;

        Ok(ret)
    }
}

#[cfg(all(test, feature = "parachain-metadata-kintsugi-testnet"))]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use futures::channel::mpsc;
    use jsonrpc_core::serde_json::{Map, Value};
    use runtime::{
        AccountId, AssetMetadata, BtcAddress, BtcPublicKey, CurrencyId, ErrorCode, InterBtcIssueRequest,
        InterBtcReplaceRequest, IssueRequestStatus, RequestIssueEvent, StatusCode, Token, VaultId, DOT, IBTC,
    };
    use std::collections::BTreeSet;

    macro_rules! assert_err {
        ($result:expr, $err:pat) => {{
            match $result {
                Err($err) => (),
                Ok(v) => panic!("assertion failed: Ok({:?})", v),
                _ => panic!("expected: Err($err)"),
            }
        }};
    }

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait IssuePallet {
            async fn request_issue(&self, amount: u128, vault_id: &VaultId) -> Result<RequestIssueEvent, RuntimeError>;
            async fn execute_issue(&self, issue_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), RuntimeError>;
            async fn cancel_issue(&self, issue_id: H256) -> Result<(), RuntimeError>;
            async fn get_issue_request(&self, issue_id: H256) -> Result<InterBtcIssueRequest, RuntimeError>;
            async fn get_vault_issue_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcIssueRequest)>, RuntimeError>;
            async fn get_issue_period(&self) -> Result<u32, RuntimeError>;
            async fn get_all_active_issues(&self) -> Result<Vec<(H256, InterBtcIssueRequest)>, RuntimeError>;
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

    fn default_issue_request() -> InterBtcIssueRequest {
        InterBtcIssueRequest {
            amount: Default::default(),
            btc_address: Default::default(),
            btc_height: Default::default(),
            fee: Default::default(),
            griefing_collateral: Default::default(),
            opentime: Default::default(),
            period: Default::default(),
            requester: AccountId::new([1u8; 32]),
            btc_public_key: BtcPublicKey { 0: [0; 33] },
            status: IssueRequestStatus::Pending,
            vault: VaultId::new(AccountId::new([1u8; 32]), Token(DOT), runtime::Token(IBTC)),
        }
    }

    #[tokio::test]
    async fn test_get_open_process_delays_succeeds() {
        // parachain_open_time = 9_500, btc_start_height=100  current_block = 10_000, period = 1_000
        // parachain_open_time = 1_000, btc_start_height=100  current_block = 10_000, period = 1_000
        // parachain_open_time = 8_500, btc_start_height=100  current_block = 10_000, period = 1_000
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc.expect_get_vault_issue_requests().times(1).returning(|_| {
            Ok(vec![
                (
                    H256::from_slice(&[1; 32]),
                    InterBtcIssueRequest {
                        opentime: 9_500,
                        btc_height: 100,
                        ..default_issue_request()
                    },
                ),
                (
                    H256::from_slice(&[2; 32]),
                    InterBtcIssueRequest {
                        opentime: 1_000,
                        btc_height: 100,
                        ..default_issue_request()
                    },
                ),
                (
                    H256::from_slice(&[3; 32]),
                    InterBtcIssueRequest {
                        opentime: 8_500,
                        btc_height: 100,
                        ..default_issue_request()
                    },
                ),
            ])
        });
        parachain_rpc.expect_get_issue_period().times(1).returning(|| Ok(1_000));

        let mut canceller = CancellationScheduler::new(parachain_rpc, 10_000, 150, AccountId::new([1u8; 32]));

        // checks that the delay is calculated correctly
        assert_eq!(
            canceller.get_open_requests::<IssueCanceller>().await.unwrap(),
            vec![
                ActiveRequest {
                    id: H256::from_slice(&[1; 32]),
                    parachain_deadline_height: 10_500,
                    bitcoin_deadline_height: 120,
                },
                ActiveRequest {
                    id: H256::from_slice(&[2; 32]),
                    parachain_deadline_height: 2_000,
                    bitcoin_deadline_height: 120,
                },
                ActiveRequest {
                    id: H256::from_slice(&[3; 32]),
                    parachain_deadline_height: 9_500,
                    bitcoin_deadline_height: 120,
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_process_event_succeeds() {
        // check that we actually cancel the issue when it expires
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc.expect_get_vault_issue_requests().returning(|_| {
            Ok(vec![(
                H256::from_slice(&[1; 32]),
                InterBtcIssueRequest {
                    opentime: 10_000,
                    ..default_issue_request()
                },
            )])
        });

        parachain_rpc.expect_get_issue_period().returning(|| Ok(100));

        // check that it cancels the issue
        parachain_rpc.expect_cancel_issue().returning(|_| Ok(()));

        let mut active_processes: Vec<ActiveRequest> = vec![];
        let mut cancellation_scheduler = CancellationScheduler::new(parachain_rpc, 0, 0, AccountId::new([1u8; 32]));

        assert_eq!(
            cancellation_scheduler
                .process_event::<IssueCanceller>(
                    Event::ParachainBlock(15000),
                    &mut active_processes,
                    ListState::Invalid,
                )
                .await
                .unwrap(),
            ListState::Valid
        );

        // not empty yet..
        assert!(!active_processes.is_empty());

        assert_eq!(
            cancellation_scheduler
                .process_event::<IssueCanceller>(Event::BitcoinBlock(4), &mut active_processes, ListState::Valid,)
                .await
                .unwrap(),
            ListState::Valid
        );

        // issue should have been removed from the list after it has been canceled
        assert!(active_processes.is_empty());
    }

    #[tokio::test]
    async fn test_process_event_only_removes_when_both_parachain_and_bitcoin_expired() {
        // check that we actually cancel the issue when it expires
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc.expect_get_vault_issue_requests().returning(|_| {
            Ok(vec![(
                H256::from_slice(&[1; 32]),
                InterBtcIssueRequest {
                    opentime: 10_000,
                    btc_height: 100,
                    ..default_issue_request()
                },
            )])
        });

        parachain_rpc.expect_get_issue_period().returning(|| Ok(1000));

        // check that it cancels the issue
        parachain_rpc.expect_cancel_issue().returning(|_| Ok(()));

        let mut active_processes: Vec<ActiveRequest> = vec![];
        let mut cancellation_scheduler =
            CancellationScheduler::new(parachain_rpc, 10_001, 101, AccountId::new([1u8; 32]));

        // deadline is at parachain_height = 11_000 and bitcoin_height = 120

        cancellation_scheduler
            .process_event::<IssueCanceller>(Event::ParachainBlock(10500), &mut active_processes, ListState::Invalid)
            .await
            .unwrap();
        assert!(!active_processes.is_empty());

        cancellation_scheduler
            .process_event::<IssueCanceller>(Event::BitcoinBlock(120), &mut active_processes, ListState::Valid)
            .await
            .unwrap();

        // not removed yet, both not yet expired
        assert!(!active_processes.is_empty());

        cancellation_scheduler
            .process_event::<IssueCanceller>(Event::ParachainBlock(11001), &mut active_processes, ListState::Valid)
            .await
            .unwrap();

        // not removed yet; bitcoin not expired
        assert!(!active_processes.is_empty());

        cancellation_scheduler
            .process_event::<IssueCanceller>(Event::ParachainBlock(11000), &mut active_processes, ListState::Valid)
            .await
            .unwrap();
        cancellation_scheduler
            .process_event::<IssueCanceller>(Event::BitcoinBlock(121), &mut active_processes, ListState::Valid)
            .await
            .unwrap();

        // not removed yet - parachain not expired
        assert!(!active_processes.is_empty());

        cancellation_scheduler
            .process_event::<IssueCanceller>(Event::ParachainBlock(11001), &mut active_processes, ListState::Valid)
            .await
            .unwrap();

        // both parachain and bitcoin expired, should be removed now
        assert!(active_processes.is_empty());
    }

    #[tokio::test]
    async fn test_process_event_remove_from_list() {
        // checks that we don't query for new issues, and that when the issue gets executed, it
        // is removed from the list
        let parachain_rpc = MockProvider::default();

        let mut active_processes: Vec<ActiveRequest> = vec![
            ActiveRequest {
                id: H256::from_slice(&[1; 32]),
                parachain_deadline_height: 0,
                bitcoin_deadline_height: 0,
            },
            ActiveRequest {
                id: H256::from_slice(&[2; 32]),
                parachain_deadline_height: 0,
                bitcoin_deadline_height: 0,
            },
            ActiveRequest {
                id: H256::from_slice(&[3; 32]),
                parachain_deadline_height: 0,
                bitcoin_deadline_height: 0,
            },
        ];

        let mut cancellation_scheduler = CancellationScheduler::new(parachain_rpc, 0, 0, AccountId::new([1u8; 32]));

        // simulate that the issue gets executed
        let event = Event::Executed(H256::from_slice(&[2; 32]));

        // simulate that the issue gets executed
        assert_eq!(
            cancellation_scheduler
                .process_event::<IssueCanceller>(event, &mut active_processes, ListState::Valid)
                .await
                .unwrap(),
            ListState::Valid
        );

        // check that the process with id 2 was removed
        assert_eq!(
            active_processes.into_iter().map(|x| x.id).collect::<Vec<H256>>(),
            vec![H256::from_slice(&[1; 32]), H256::from_slice(&[3; 32])]
        );
    }

    #[tokio::test]
    async fn test_process_event_get_new_list() {
        // checks that we query for new issues, and that when the issue gets executed, it
        // is removed from the list
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc.expect_get_vault_issue_requests().times(1).returning(|_| {
            Ok(vec![(
                H256::from_slice(&[1; 32]),
                InterBtcIssueRequest {
                    opentime: 10,
                    ..default_issue_request()
                },
            )])
        });
        parachain_rpc.expect_get_issue_period().returning(|| Ok(10));

        let mut active_processes: Vec<ActiveRequest> = vec![];
        let mut cancellation_scheduler = CancellationScheduler::new(parachain_rpc, 15, 0, AccountId::new([1u8; 32]));

        // simulate that the issue gets executed
        let event = Event::Executed(H256::from_slice(&[1; 32]));

        assert_eq!(
            cancellation_scheduler
                .process_event::<IssueCanceller>(event, &mut active_processes, ListState::Invalid)
                .await
                .unwrap(),
            ListState::Valid
        );

        // issue should have been removed from the list
        assert!(active_processes.is_empty());
    }

    #[tokio::test]
    async fn test_process_event_timeout() {
        // check that if we fail to get the issue list, we return Invalid, but not Err
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc
            .expect_get_vault_issue_requests()
            .times(1)
            .returning(|_| Err(RuntimeError::BlockNotFound));

        let mut active_processes: Vec<ActiveRequest> = vec![];
        let mut cancellation_scheduler = CancellationScheduler::new(parachain_rpc, 0, 0, AccountId::new([1u8; 32]));

        // simulate that we have a timeout (new issue request opened)
        let event = Event::Opened;

        // state should remain invalid
        assert_eq!(
            cancellation_scheduler
                .process_event::<IssueCanceller>(event, &mut active_processes, ListState::Invalid)
                .await
                .unwrap(),
            ListState::Invalid
        );
    }

    #[tokio::test]
    async fn test_process_event_shutdown() {
        // check that if the selector fails, the error is propagated
        let parachain_rpc = MockProvider::default();

        let cancellation_scheduler = CancellationScheduler::new(parachain_rpc, 0, 0, AccountId::new([1u8; 32]));

        // dropping the tx immediately - this effectively closes the channel
        let (_, replace_event_rx) = mpsc::channel::<Event>(16);

        assert_err!(
            cancellation_scheduler
                .handle_cancellation::<IssueCanceller>(replace_event_rx)
                .await,
            RuntimeError::ChannelClosed
        );
    }

    #[tokio::test]
    async fn test_period_increase() {
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc.expect_get_vault_issue_requests().returning(|_| {
            Ok(vec![(
                H256::from_slice(&[1; 32]),
                InterBtcIssueRequest {
                    opentime: 10_000,
                    btc_height: 100,
                    period: 1_000,
                    ..default_issue_request()
                },
            )])
        });

        // simulate the period increase: a cancel will return an error
        parachain_rpc.expect_get_issue_period().once().returning(|| Ok(1000));
        parachain_rpc.expect_get_issue_period().returning(|| Ok(2000));
        // normally cancelling prematurely would return issue.TimeNotExpired, but that is difficult to construct..
        parachain_rpc
            .expect_cancel_issue()
            .returning(|_| Err(RuntimeError::BlockNotFound));

        let mut active_processes: Vec<ActiveRequest> = vec![];
        let mut cancellation_scheduler =
            CancellationScheduler::new(parachain_rpc, 10_001, 200, AccountId::new([1u8; 32]));

        // deadline is at parachain_height = 11_000 and bitcoin_height = 120, so not yet expired..
        cancellation_scheduler
            .process_event::<IssueCanceller>(Event::ParachainBlock(10_500), &mut active_processes, ListState::Invalid)
            .await
            .unwrap();

        assert_eq!(
            active_processes,
            vec![ActiveRequest {
                id: H256::from_slice(&[1; 32]),
                parachain_deadline_height: 11_000,
                bitcoin_deadline_height: 120,
            }]
        );

        cancellation_scheduler
            .process_event::<IssueCanceller>(Event::ParachainBlock(11_500), &mut active_processes, ListState::Invalid)
            .await
            .unwrap();
        assert_eq!(
            active_processes,
            vec![ActiveRequest {
                id: H256::from_slice(&[1; 32]),
                parachain_deadline_height: 12_000,
                bitcoin_deadline_height: 140,
            }]
        );
    }

    #[tokio::test]
    async fn test_period_decreased() {
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc.expect_get_vault_issue_requests().returning(|_| {
            Ok(vec![(
                H256::from_slice(&[1; 32]),
                InterBtcIssueRequest {
                    opentime: 10_000,
                    btc_height: 100,
                    period: 1_000,
                    ..default_issue_request()
                },
            )])
        });

        parachain_rpc.expect_get_issue_period().once().returning(|| Ok(500));

        let mut active_processes: Vec<ActiveRequest> = vec![];
        let mut cancellation_scheduler =
            CancellationScheduler::new(parachain_rpc, 10_001, 200, AccountId::new([1u8; 32]));

        // deadline is at parachain_height = 11_000 and bitcoin_height = 120, so not yet expired..
        cancellation_scheduler
            .process_event::<IssueCanceller>(Event::ParachainBlock(10_500), &mut active_processes, ListState::Invalid)
            .await
            .unwrap();

        // check that the issue's period of 1000 is used rather than the global period of 500
        assert_eq!(
            active_processes,
            vec![ActiveRequest {
                id: H256::from_slice(&[1; 32]),
                parachain_deadline_height: 11_000,
                bitcoin_deadline_height: 120,
            }]
        );
    }
}
