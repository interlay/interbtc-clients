use super::Error;
use async_trait::async_trait;
use futures::channel::mpsc::Receiver;
use futures::*;
use log::*;
use runtime::{AccountId, IssuePallet, PolkaBtcHeader, ReplacePallet, UtilFuncs};
use sp_core::H256;
use std::marker::{Send, Sync};
use std::sync::Arc;

pub enum RequestEvent {
    /// new issue requested / replace accepted
    Opened,
    /// issue / replace successfully executed
    Executed(H256),
}

pub struct CancellationScheduler<P: IssuePallet + ReplacePallet + UtilFuncs> {
    provider: Arc<P>,
    vault_id: AccountId,
    period: Option<u32>,
}

#[derive(Copy, Clone, Debug, PartialEq)]
struct ActiveRequest {
    id: H256,
    end_time: u32,
}

pub struct UnconvertedOpenTime {
    id: H256,
    open_time: u32,
}

enum BlockOrEvent {
    Block(PolkaBtcHeader),
    Event(RequestEvent),
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
    async fn get_open_requests(
        provider: Arc<P>,
        vault_id: AccountId,
    ) -> Result<Vec<UnconvertedOpenTime>, Error>
    where
        P: 'async_trait;

    /// Gets the timeout period in number of blocks
    async fn get_period(provider: Arc<P>) -> Result<u32, Error>
    where
        P: 'async_trait;

    /// Cancels the issue/replace
    async fn cancel_request(provider: Arc<P>, request_id: H256) -> Result<(), Error>
    where
        P: 'async_trait;
}

pub struct IssueCanceller;

#[async_trait]
impl<P: IssuePallet + ReplacePallet + Send + Sync> Canceller<P> for IssueCanceller {
    const TYPE_NAME: &'static str = "issue";

    async fn get_open_requests(
        provider: Arc<P>,
        vault_id: AccountId,
    ) -> Result<Vec<UnconvertedOpenTime>, Error>
    where
        P: 'async_trait,
    {
        let ret = provider
            .get_vault_issue_requests(vault_id)
            .await?
            .iter()
            .filter(|(_, issue)| !issue.completed)
            .map(|(id, issue)| UnconvertedOpenTime {
                id: *id,
                open_time: issue.opentime,
            })
            .collect();
        Ok(ret)
    }

    async fn get_period(provider: Arc<P>) -> Result<u32, Error>
    where
        P: 'async_trait,
    {
        Ok(provider.get_issue_period().await?)
    }

    async fn cancel_request(provider: Arc<P>, request_id: H256) -> Result<(), Error>
    where
        P: 'async_trait,
    {
        Ok(provider.cancel_issue(request_id).await?)
    }
}

pub struct ReplaceCanceller;

#[async_trait]
impl<P: IssuePallet + ReplacePallet + Send + Sync> Canceller<P> for ReplaceCanceller {
    const TYPE_NAME: &'static str = "replace";

    async fn get_open_requests(
        provider: Arc<P>,
        vault_id: AccountId,
    ) -> Result<Vec<UnconvertedOpenTime>, Error>
    where
        P: 'async_trait,
    {
        let ret = provider
            .get_new_vault_replace_requests(vault_id)
            .await?
            .iter()
            .filter(|(_, replace)| !replace.completed)
            .map(|(id, replace)| UnconvertedOpenTime {
                id: *id,
                open_time: replace.open_time,
            })
            .collect();
        Ok(ret)
    }

    async fn get_period(provider: Arc<P>) -> Result<u32, Error>
    where
        P: 'async_trait,
    {
        Ok(provider.get_replace_period().await?)
    }

    async fn cancel_request(provider: Arc<P>, request_id: H256) -> Result<(), Error>
    where
        P: 'async_trait,
    {
        Ok(provider.cancel_replace(request_id).await?)
    }
}

/// Trait to allow us to mock the `select_events` function
#[async_trait]
trait EventSelector {
    /// Sleep until either the timeout has occurred or an event has been received, and return
    /// which event woke us up
    async fn select_event(
        self,
        block_listener: &mut Receiver<PolkaBtcHeader>,
        event_listener: &mut Receiver<RequestEvent>,
    ) -> Result<BlockOrEvent, Error>;
}

struct ProductionEventSelector;

#[async_trait]
impl EventSelector for ProductionEventSelector {
    async fn select_event(
        self,
        block_listener: &mut Receiver<PolkaBtcHeader>,
        event_listener: &mut Receiver<RequestEvent>,
    ) -> Result<BlockOrEvent, Error> {
        // fuse and pin the tasks, required for select! macro
        let task_block = block_listener.next().fuse();
        let task_event = event_listener.next().fuse();
        pin_mut!(task_block, task_event);

        select! {
            h = task_block => match h {
                Some(block) => Ok(BlockOrEvent::Block(block)),
                _ => Err(Error::ChannelClosed)
            },
            e = task_event => match e {
                Some(event) => Ok(BlockOrEvent::Event(event)),
                _ => Err(Error::ChannelClosed)
            }
        }
    }
}

// verbose drain_filter
fn drain_expired(requests: &mut Vec<ActiveRequest>, current_height: u32) -> Vec<ActiveRequest> {
    let mut expired = Vec::new();
    let has_expired = |request: &ActiveRequest| request.end_time < current_height;
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
impl<P: IssuePallet + ReplacePallet + UtilFuncs> CancellationScheduler<P> {
    pub fn new(provider: Arc<P>, vault_id: AccountId) -> CancellationScheduler<P> {
        CancellationScheduler {
            provider,
            vault_id,
            period: None,
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
        &mut self,
        mut block_listener: Receiver<PolkaBtcHeader>,
        mut event_listener: Receiver<RequestEvent>,
    ) -> Result<(), Error> {
        let mut list_state = ListState::Invalid;
        let mut active_requests: Vec<ActiveRequest> = vec![];

        loop {
            list_state = self
                .wait_for_event::<T, _>(
                    &mut block_listener,
                    &mut event_listener,
                    &mut active_requests,
                    list_state,
                    ProductionEventSelector,
                )
                .await?;
        }
    }

    /// Handles one timeout or event_listener event. This method is split from handle_cancellation for
    /// testing purposes
    async fn wait_for_event<T: Canceller<P>, U: EventSelector>(
        &mut self,
        block_listener: &mut Receiver<PolkaBtcHeader>,
        event_listener: &mut Receiver<RequestEvent>,
        active_requests: &mut Vec<ActiveRequest>,
        list_state: ListState,
        selector: U,
    ) -> Result<ListState, Error> {
        // try to get an up-to-date list of requests if we don't have it yet
        if let ListState::Invalid = list_state {
            match self.get_open_requests::<T>().await {
                Ok(x) => {
                    *active_requests = x;
                }
                Err(e) => {
                    active_requests.clear();
                    error!("Failed to query open {}s: {}", T::TYPE_NAME, e);
                }
            }
        }

        match selector
            .select_event(block_listener, event_listener)
            .await?
        {
            BlockOrEvent::Block(header) => {
                debug!(
                    "Received parachain block at height {} for {}",
                    header.number,
                    T::TYPE_NAME
                );

                let cancellable_requests = drain_expired(active_requests, header.number);

                for request in cancellable_requests {
                    match T::cancel_request(self.provider.clone(), request.id).await {
                        Ok(_) => info!("Canceled {} #{}", T::TYPE_NAME, request.id),
                        Err(e) => {
                            // failed to cancel; get up-to-date request list in next iteration
                            error!("Failed to cancel {}: {}", T::TYPE_NAME, e);
                            return Ok(ListState::Invalid);
                        }
                    }
                }

                Ok(ListState::Valid)
            }
            BlockOrEvent::Event(RequestEvent::Executed(id)) => {
                debug!("Received event: executed {} #{}", T::TYPE_NAME, id);
                active_requests.retain(|x| x.id != id);
                Ok(ListState::Valid)
            }
            BlockOrEvent::Event(RequestEvent::Opened) => {
                debug!("Received event: opened {}", T::TYPE_NAME);
                Ok(ListState::Invalid)
            }
        }
    }

    /// Gets a list of requests that have been requested from this vault
    async fn get_open_requests<T: Canceller<P>>(&mut self) -> Result<Vec<ActiveRequest>, Error> {
        let ret = self
            .get_open_requests_by_end::<T>()
            .await?
            .into_iter()
            .map(|(id, end_time)| ActiveRequest { id, end_time })
            .collect();
        Ok(ret)
    }

    /// Gets a list of issue that have been requested from this vault
    async fn get_open_requests_by_end<T: Canceller<P>>(
        &mut self,
    ) -> Result<Vec<(H256, u32)>, Error> {
        let open_requests =
            T::get_open_requests(self.provider.clone(), self.vault_id.clone()).await?;

        if open_requests.is_empty() {
            return Ok(vec![]);
        }

        // get current block height and request period
        let chain_height = self.provider.get_current_chain_height().await?;
        let period = self.get_cached_period::<T>().await?;

        let mut ret = open_requests
            .iter()
            .map(|UnconvertedOpenTime { id, open_time }| {
                // invalid open_time. Return an error so we will retry the operation later
                if *open_time > chain_height {
                    return Err(Error::InvalidOpenTime);
                }

                let deadline_block = open_time + period;

                let end_block = if chain_height < deadline_block {
                    deadline_block - chain_height
                } else {
                    // deadline has already passed, should cancel ASAP
                    // this branch can occur when e.g. the vault has been restarted
                    0
                };

                Ok((*id, end_block))
            })
            .collect::<Result<Vec<(H256, u32)>, Error>>()?;

        // sort by ascending duration
        ret.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        Ok(ret)
    }

    /// Cached function to get the issue/replace period, in number of blocks until
    /// it is allowed to be canceled
    async fn get_cached_period<T: Canceller<P>>(&mut self) -> Result<u32, Error> {
        match self.period {
            Some(x) => Ok(x),
            None => {
                let ret = T::get_period(self.provider.clone()).await?;
                self.period = Some(ret);
                Ok(ret)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use futures::channel::mpsc;
    use runtime::{
        sp_runtime::{
            generic::Digest,
            traits::{BlakeTwo256, Hash},
        },
        AccountId, Error as RuntimeError, H256Le, PolkaBtcIssueRequest, PolkaBtcReplaceRequest,
    };
    use sp_core::H256;

    macro_rules! assert_err {
        ($result:expr, $err:pat) => {{
            match $result {
                Err($err) => (),
                Ok(v) => panic!("assertion failed: Ok({:?})", v),
                _ => panic!("expected: Err($err)"),
            }
        }};
    }

    struct TestEventSelector<F>
    where
        F: Fn(
            &mut Receiver<PolkaBtcHeader>,
            &mut Receiver<RequestEvent>,
        ) -> Result<BlockOrEvent, Error>,
    {
        on_event: F,
    }

    #[async_trait]
    impl<F> EventSelector for TestEventSelector<F>
    where
        F: Fn(
                &mut Receiver<PolkaBtcHeader>,
                &mut Receiver<RequestEvent>,
            ) -> Result<BlockOrEvent, Error>
            + std::marker::Send,
    {
        /// Sleep until either the timeout has occured or an event has been received, and return
        /// which event woke us up
        async fn select_event(
            self,
            block_listener: &mut Receiver<PolkaBtcHeader>,
            event_listener: &mut Receiver<RequestEvent>,
        ) -> Result<BlockOrEvent, Error> {
            (self.on_event)(block_listener, event_listener)

            // Err(Error::ChannelClosed)
        }
    }

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait IssuePallet {
            async fn request_issue(
                &self,
                amount: u128,
                vault_id: AccountId,
                griefing_collateral: u128,
            ) -> Result<H256, RuntimeError>;
            async fn execute_issue(
                &self,
                issue_id: H256,
                tx_id: H256Le,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn cancel_issue(&self, issue_id: H256) -> Result<(), RuntimeError>;
            async fn get_vault_issue_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcIssueRequest)>, RuntimeError>;
            async fn get_issue_period(&self) -> Result<u32, RuntimeError>;
            async fn set_issue_period(&self, period: u32) -> Result<(), RuntimeError>;
        }
        #[async_trait]
        pub trait ReplacePallet {
            async fn request_replace(&self, amount: u128, griefing_collateral: u128)
                -> Result<H256, RuntimeError>;
            async fn withdraw_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn accept_replace(&self, replace_id: H256, collateral: u128) -> Result<(), RuntimeError>;
            async fn auction_replace(
                &self,
                old_vault: AccountId,
                btc_amount: u128,
                collateral: u128,
            ) -> Result<(), RuntimeError>;
            async fn execute_replace(
                &self,
                replace_id: H256,
                tx_id: H256Le,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn cancel_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn get_new_vault_replace_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, RuntimeError>;
            async fn get_old_vault_replace_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, RuntimeError>;
            async fn get_replace_period(&self) -> Result<u32, RuntimeError>;
            async fn set_replace_period(&self, period: u32) -> Result<(), RuntimeError>;
            async fn get_replace_request(&self, replace_id: H256) -> Result<PolkaBtcReplaceRequest, RuntimeError>;
        }
        #[async_trait]
        pub trait UtilFuncs {
            async fn get_current_chain_height(&self) -> Result<u32, RuntimeError>;
            async fn get_blockchain_height_at(&self, parachain_height: u32) -> Result<u32, RuntimeError>;
        }
    }

    #[tokio::test]
    async fn test_get_open_process_delays_succeeds() {
        // open_time = 95, current_block = 100, period = 10: remaining = 5 + margin
        // open_time = 10,  current_block = 100, period = 10: remaining = 0
        // open_time = 85,  current_block = 100, period = 10: remaining = -5 + margin
        let mut provider = MockProvider::default();
        provider
            .expect_get_vault_issue_requests()
            .times(1)
            .returning(|_| {
                Ok(vec![
                    (
                        H256::from_slice(&[1; 32]),
                        PolkaBtcIssueRequest {
                            opentime: 95,
                            ..Default::default()
                        },
                    ),
                    (
                        H256::from_slice(&[2; 32]),
                        PolkaBtcIssueRequest {
                            opentime: 10,
                            ..Default::default()
                        },
                    ),
                    (
                        H256::from_slice(&[3; 32]),
                        PolkaBtcIssueRequest {
                            opentime: 85,
                            ..Default::default()
                        },
                    ),
                ])
            });
        provider
            .expect_get_current_chain_height()
            .times(1)
            .returning(|| Ok(100));
        provider
            .expect_get_issue_period()
            .times(1)
            .returning(|| Ok(10));

        let mut canceller = CancellationScheduler::new(Arc::new(provider), Default::default());

        // checks that the delay is calculated correctly, and that the vec is sorted
        assert_eq!(
            canceller
                .get_open_requests_by_end::<IssueCanceller>()
                .await
                .unwrap(),
            vec![
                (H256::from_slice(&[2; 32]), 0),
                (H256::from_slice(&[3; 32]), 0),
                (H256::from_slice(&[1; 32]), 5)
            ]
        );
    }
    #[tokio::test]
    async fn test_get_open_process_delays_with_invalid_opentime_fails() {
        // if current_block is 5 and the issue was open at 10, something went wrong...
        let mut provider = MockProvider::default();
        provider
            .expect_get_vault_issue_requests()
            .times(1)
            .returning(|_| {
                Ok(vec![(
                    H256::from_slice(&[1; 32]),
                    PolkaBtcIssueRequest {
                        opentime: 10,
                        ..Default::default()
                    },
                )])
            });
        provider
            .expect_get_current_chain_height()
            .times(1)
            .returning(|| Ok(5));
        provider.expect_get_issue_period().returning(|| Ok(10));

        let mut canceller = CancellationScheduler::new(Arc::new(provider), Default::default());
        assert_err!(
            canceller.get_open_requests_by_end::<IssueCanceller>().await,
            Error::InvalidOpenTime
        );
    }

    #[tokio::test]
    async fn test_wait_for_event_succeeds() {
        // check that we actually cancel the issue when it expires
        let mut provider = MockProvider::default();
        provider
            .expect_get_vault_issue_requests()
            .times(1)
            .returning(|_| {
                Ok(vec![(
                    H256::from_slice(&[1; 32]),
                    PolkaBtcIssueRequest {
                        opentime: 10,
                        ..Default::default()
                    },
                )])
            });
        provider
            .expect_get_current_chain_height()
            .times(1)
            .returning(|| Ok(15));
        provider.expect_get_issue_period().returning(|| Ok(10));

        // check that it cancels the issue
        provider
            .expect_cancel_issue()
            .times(1)
            .returning(|_| Ok(()));

        let (_, mut block_listener) = mpsc::channel::<PolkaBtcHeader>(16);
        let (_, mut event_listener) = mpsc::channel::<RequestEvent>(16);
        let mut active_processes: Vec<ActiveRequest> = vec![];
        let mut cancellation_scheduler =
            CancellationScheduler::new(Arc::new(provider), AccountId::default());

        // simulate that we have a a new block
        let selector = TestEventSelector {
            on_event: |_, _| {
                Ok(BlockOrEvent::Block(PolkaBtcHeader {
                    parent_hash: BlakeTwo256::hash(&[0; 32]),
                    number: 30,
                    state_root: BlakeTwo256::hash(&[0; 32]),
                    extrinsics_root: BlakeTwo256::hash(&[0; 32]),
                    digest: Digest::default(),
                }))
            },
        };

        assert_eq!(
            cancellation_scheduler
                .wait_for_event::<IssueCanceller, _>(
                    &mut block_listener,
                    &mut event_listener,
                    &mut active_processes,
                    ListState::Invalid,
                    selector
                )
                .await
                .unwrap(),
            ListState::Valid
        );

        // issue should have been removed from the list after it has been canceled
        assert!(active_processes.is_empty());
    }

    #[tokio::test]
    async fn test_wait_for_event_remove_from_list() {
        // checks that we don't query for new issues, and that when the issue gets executed, it
        // is removed from the list
        let provider = MockProvider::default();

        let (_, mut block_listener) = mpsc::channel::<PolkaBtcHeader>(16);
        let (_, mut event_listener) = mpsc::channel::<RequestEvent>(16);
        let mut active_processes: Vec<ActiveRequest> = vec![
            ActiveRequest {
                id: H256::from_slice(&[1; 32]),
                end_time: 0,
            },
            ActiveRequest {
                id: H256::from_slice(&[2; 32]),
                end_time: 0,
            },
            ActiveRequest {
                id: H256::from_slice(&[3; 32]),
                end_time: 0,
            },
        ];

        let mut cancellation_scheduler =
            CancellationScheduler::new(Arc::new(provider), AccountId::default());

        // simulate that the issue gets executed
        let selector = TestEventSelector {
            on_event: |_, _| {
                Ok(BlockOrEvent::Event(RequestEvent::Executed(
                    H256::from_slice(&[2; 32]),
                )))
            },
        };

        // simulate that the issue gets executed
        assert_eq!(
            cancellation_scheduler
                .wait_for_event::<IssueCanceller, _>(
                    &mut block_listener,
                    &mut event_listener,
                    &mut active_processes,
                    ListState::Valid,
                    selector
                )
                .await
                .unwrap(),
            ListState::Valid
        );

        // check that the process with id 2 was removed
        assert_eq!(
            active_processes
                .into_iter()
                .map(|x| x.id)
                .collect::<Vec<H256>>(),
            vec![H256::from_slice(&[1; 32]), H256::from_slice(&[3; 32])]
        );
    }

    #[tokio::test]
    async fn test_wait_for_event_get_new_list() {
        // checks that we query for new issues, and that when the issue gets executed, it
        // is removed from the list
        let mut provider = MockProvider::default();
        provider
            .expect_get_vault_issue_requests()
            .times(1)
            .returning(|_| {
                Ok(vec![(
                    H256::from_slice(&[1; 32]),
                    PolkaBtcIssueRequest {
                        opentime: 10,
                        ..Default::default()
                    },
                )])
            });
        provider
            .expect_get_current_chain_height()
            .times(1)
            .returning(|| Ok(15));
        provider.expect_get_issue_period().returning(|| Ok(10));

        let (_, mut block_listener) = mpsc::channel::<PolkaBtcHeader>(16);
        let (_, mut event_listener) = mpsc::channel::<RequestEvent>(16);
        let mut active_processes: Vec<ActiveRequest> = vec![];
        let mut cancellation_scheduler =
            CancellationScheduler::new(Arc::new(provider), AccountId::default());

        // simulate that the issue gets executed
        let selector = TestEventSelector {
            on_event: |_, _| {
                Ok(BlockOrEvent::Event(RequestEvent::Executed(
                    H256::from_slice(&[1; 32]),
                )))
            },
        };

        assert_eq!(
            cancellation_scheduler
                .wait_for_event::<IssueCanceller, _>(
                    &mut block_listener,
                    &mut event_listener,
                    &mut active_processes,
                    ListState::Invalid,
                    selector
                )
                .await
                .unwrap(),
            ListState::Valid
        );

        // issue should have been removed from the list
        assert!(active_processes.is_empty());
    }

    #[tokio::test]
    async fn test_wait_for_event_timeout() {
        // check that if we fail to get the issue list, we return Invalid, but not Err
        let mut provider = MockProvider::default();
        provider
            .expect_get_vault_issue_requests()
            .times(1)
            .returning(|_| Err(RuntimeError::BlockNotFound));

        let (_, mut block_listener) = mpsc::channel::<PolkaBtcHeader>(16);
        let (_, mut event_listener) = mpsc::channel::<RequestEvent>(16);
        let mut active_processes: Vec<ActiveRequest> = vec![];
        let mut cancellation_scheduler =
            CancellationScheduler::new(Arc::new(provider), AccountId::default());

        // simulate that we have a timeout (new issue request opened)
        let selector = TestEventSelector {
            on_event: |_, _| Ok(BlockOrEvent::Event(RequestEvent::Opened)),
        };

        // state should remain invalid
        assert_eq!(
            cancellation_scheduler
                .wait_for_event::<IssueCanceller, _>(
                    &mut block_listener,
                    &mut event_listener,
                    &mut active_processes,
                    ListState::Invalid,
                    selector
                )
                .await
                .unwrap(),
            ListState::Invalid
        );
    }

    #[tokio::test]
    async fn test_wait_for_event_shutdown() {
        // check that if the selector fails, the error is propagated
        let provider = MockProvider::default();

        let (_, mut block_listener) = mpsc::channel::<PolkaBtcHeader>(16);
        let (_, mut event_listener) = mpsc::channel::<RequestEvent>(16);
        let mut active_processes: Vec<ActiveRequest> = vec![];
        let mut cancellation_scheduler =
            CancellationScheduler::new(Arc::new(provider), AccountId::default());

        // simulate that we have a timeout
        let selector = TestEventSelector {
            on_event: |_, _| Err(Error::ChannelClosed),
        };

        assert_err!(
            cancellation_scheduler
                .wait_for_event::<IssueCanceller, _>(
                    &mut block_listener,
                    &mut event_listener,
                    &mut active_processes,
                    ListState::Valid,
                    selector
                )
                .await,
            Error::ChannelClosed
        );
    }
}
