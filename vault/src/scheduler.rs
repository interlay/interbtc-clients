use super::Error;
use async_trait::async_trait;
use futures::channel::mpsc::Receiver;
use futures::*;
use log::*;
use runtime::{IssuePallet, ReplacePallet, UtilFuncs};
use sp_core::{crypto::AccountId32, H256};
use std::marker::{Send, Sync};
use std::sync::Arc;
use tokio::time;
use tokio::time::{Duration, Instant};

// TODO: re-use constant from the parachain
const SECONDS_PER_BLOCK: u32 = 6;

// number of seconds after the issue deadline before the issue is
// actually canceled. When set too low, chances are we try to cancel
// before required block has been added
const MARGIN_SECONDS: u32 = 5 * 60;

// number of seconds to wait after failing to read the open issue list
// before retrying
const QUERY_RETRY_INTERVAL: u32 = 15 * 60;

struct ActiveProcess {
    deadline: Instant,
    id: H256,
}

pub enum ProcessEvent {
    Opened,
    Executed(H256),
}

pub struct CancelationScheduler<P: IssuePallet + ReplacePallet + UtilFuncs> {
    provider: Arc<P>,
    vault_id: AccountId32,
    period: Option<u32>,
}

pub struct UnconvertedOpenTime {
    id: H256,
    opentime: u32,
}

#[async_trait]
pub trait Canceler<P> {
    /// Gets a list of open replace/issue processes
    async fn get_open_processes(
        provider: Arc<P>,
        vault_id: AccountId32,
    ) -> Result<Vec<UnconvertedOpenTime>, Error>
    where
        P: 'async_trait;

    /// Gets the timeout period in number of blocks
    async fn get_period(provider: Arc<P>) -> Result<u32, Error>
    where
        P: 'async_trait;

    /// Cancels the issue/replace
    async fn cancel_process(provider: Arc<P>, process_id: H256) -> Result<(), Error>
    where
        P: 'async_trait;

    /// Gets either "replace" or "issue"; used for logging
    fn type_name() -> String;
}

pub struct IssueCanceler;
#[async_trait]
impl<P: IssuePallet + ReplacePallet + Send + Sync> Canceler<P> for IssueCanceler {
    async fn get_open_processes(
        provider: Arc<P>,
        vault_id: AccountId32,
    ) -> Result<Vec<UnconvertedOpenTime>, Error>
    where
        P: 'async_trait,
    {
        let ret = provider
            .get_vault_issue_requests(vault_id)
            .await?
            .iter()
            .map(|(id, issue)| UnconvertedOpenTime {
                id: *id,
                opentime: issue.opentime,
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
    async fn cancel_process(provider: Arc<P>, process_id: H256) -> Result<(), Error>
    where
        P: 'async_trait,
    {
        Ok(provider.cancel_issue(process_id).await?)
    }
    fn type_name() -> String {
        "issue".to_string()
    }
}

pub struct ReplaceCanceler;
#[async_trait]
impl<P: IssuePallet + ReplacePallet + Send + Sync> Canceler<P> for ReplaceCanceler {
    async fn get_open_processes(
        provider: Arc<P>,
        vault_id: AccountId32,
    ) -> Result<Vec<UnconvertedOpenTime>, Error>
    where
        P: 'async_trait,
    {
        let ret = provider
            .get_new_vault_replace_requests(vault_id)
            .await?
            .iter()
            .map(|(id, replace)| UnconvertedOpenTime {
                id: *id,
                opentime: replace.open_time,
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
    async fn cancel_process(provider: Arc<P>, process_id: H256) -> Result<(), Error>
    where
        P: 'async_trait,
    {
        Ok(provider.cancel_replace(process_id).await?)
    }
    fn type_name() -> String {
        "replace".to_string()
    }
}

impl<P: IssuePallet + ReplacePallet + UtilFuncs> CancelationScheduler<P> {
    pub fn new(provider: Arc<P>, vault_id: AccountId32) -> CancelationScheduler<P> {
        CancelationScheduler {
            provider,
            vault_id,
            period: None,
        }
    }

    /// Listens for issueing events (i.e. issue received/executed). When
    /// the issue period has expired without the issue having been executed,
    /// this function will atempt to call cancel_event to get the collateral back.
    /// On start, queries open issues and schedules cancelation for these as well.
    ///
    /// # Arguments
    ///
    /// *`event_listener`: channel that signals issue events _for this vault_.
    pub async fn handle_cancelation<T: Canceler<P>>(
        &mut self,
        mut event_listener: Receiver<ProcessEvent>,
    ) {
        let mut active_processes_is_up_to_date = false;
        let mut active_processes: Vec<ActiveProcess> = vec![];

        loop {
            // try to get an up-to-date list of issues if we don't have it yet
            if !active_processes_is_up_to_date {
                active_processes.clear();
                match self.get_open_processes::<T>().await {
                    Ok(x) => {
                        active_processes = x;
                        active_processes_is_up_to_date = true;
                    }
                    Err(e) => {
                        error!("Failed to query open {}s: {}", T::type_name(), e);
                        active_processes.clear();
                    }
                }
            }

            // determine how long we will sleep
            let task_wait = if !active_processes_is_up_to_date {
                // failed to get the list; try again in 15 minutes
                time::delay_for(time::Duration::from_secs(QUERY_RETRY_INTERVAL.into())).fuse()
            } else {
                match active_processes.first() {
                    Some(issue) => {
                        // sleep until the first event
                        debug!(
                            "delaying until first {}: {:?}",
                            T::type_name(),
                            issue.deadline - time::Instant::now()
                        );
                        time::delay_until(issue.deadline).fuse()
                    }
                    None => {
                        // there are no open issues; we sleep until we get an event
                        debug!("No open {}s", T::type_name());
                        time::delay_for(time::Duration::from_millis(u32::MAX.into())).fuse()
                    }
                }
            };

            let task_read = event_listener.next().fuse();
            // pin the tasks; required for the select! macro
            pin_mut!(task_wait, task_read);
            // wait for both tasks, see which one fires first
            select! {
                _ = task_wait => {
                    // timeout occured, so try to cancel the issue
                    if active_processes.len() > 0
                        && T::cancel_process(self.provider.clone(), active_processes[0].id)
                            .await
                            .is_ok()
                    {
                        info!("Canceled {}", T::type_name());
                        active_processes.remove(0);
                    } else {
                        error!("No {} canceled!", T::type_name());
                        // We didn't remove an issue: force re-read of open
                        // issues at beginning of loop
                        active_processes_is_up_to_date = false;
                        // small delay to prevent spamming rpc calls on persistent failures
                        // Wrapped in a function to prevent "recursion limit reached" compiler
                        // error
                        self.rate_limit().await;
                    }
                }
                e = task_read => match e {
                    Some(ProcessEvent::Executed(id)) => {
                        debug!("Received event: executed {}", T::type_name());
                        active_processes.retain(|x| x.id != id);
                    },
                    Some(ProcessEvent::Opened) => {
                        debug!("Received event: opened {}", T::type_name());
                        // will query active processes at start of loop
                        active_processes_is_up_to_date = false;
                    }
                    _ => {
                        error!("Failed to read {} event", T::type_name());
                    }
                }
            }
        }
    }
    /// small helper function that delays for 30 seconds; used to prevent
    /// the "recursion limit reached" compiler error above
    pub async fn rate_limit(&self) {
        time::delay_for(time::Duration::from_secs(30)).await
    }

    /// Gets a list of issue that have been requested from this vault
    async fn get_open_processes<T: Canceler<P>>(&mut self) -> Result<Vec<ActiveProcess>, Error> {
        let ret = self
            .get_open_process_delays::<T>()
            .await?
            .into_iter()
            .map(|(id, delay)| ActiveProcess {
                id,
                deadline: Instant::now() + delay,
            })
            .collect();
        Ok(ret)
    }

    /// Gets a list of issue that have been requested from this vault
    async fn get_open_process_delays<T: Canceler<P>>(
        &mut self,
    ) -> Result<Vec<(H256, Duration)>, Error> {
        let open_processes =
            T::get_open_processes(self.provider.clone(), self.vault_id.clone()).await?;

        if open_processes.len() == 0 {
            return Ok(vec![]);
        }

        // get current block height and issue period
        let chain_height = self.provider.get_current_chain_height().await?;
        let period = self.get_cached_period::<T>().await?;

        // try to cancel 5 minutes after deadline, to acount for timing inaccuracies
        let margin_period = MARGIN_SECONDS / SECONDS_PER_BLOCK;

        let mut ret = open_processes
            .iter()
            .map(|UnconvertedOpenTime { id, opentime }| {
                // invalid opentime. Return an error so we will retry the operation later
                if *opentime > chain_height {
                    return Err(Error::InvalidOpenTime);
                }

                let deadline_block = opentime + period + margin_period;

                let waiting_time = if chain_height < deadline_block {
                    let remaining_blocks = deadline_block - chain_height;

                    time::Duration::from_secs(SECONDS_PER_BLOCK.into()) * remaining_blocks
                } else {
                    // deadline has already passed, should cancel ASAP
                    // this branch can occur when e.g. the vault has been restarted
                    Duration::from_secs(0)
                };

                Ok((*id, waiting_time))
            })
            .collect::<Result<Vec<(H256, Duration)>, Error>>()?;

        // sort by ascending duration
        ret.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        Ok(ret)
    }

    /// Cached function to get the issue/replace period, in number of blocks until
    /// it is allowed to be canceled
    async fn get_cached_period<T: Canceler<P>>(&mut self) -> Result<u32, Error> {
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
    use bitcoin::{
        BlockHash, Error as BitcoinError, GetRawTransactionResult, TransactionMetadata, Txid,
    };
    use runtime::{
        pallets::Core, AccountId, Error as RuntimeError, H256Le, PolkaBtcIssueRequest,
        PolkaBtcReplaceRequest, PolkaBtcRuntime, PolkaBtcVault,
    };
    use sp_core::{H160, H256};

    macro_rules! assert_ok {
        ( $x:expr $(,)? ) => {
            let is = $x;
            match is {
                Ok(_) => (),
                _ => assert!(false, "Expected Ok(_). Got {:#?}", is),
            }
        };
        ( $x:expr, $y:expr $(,)? ) => {
            assert_eq!($x, Ok($y));
        };
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
                tx_block_height: u32,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn cancel_issue(&self, issue_id: H256) -> Result<(), RuntimeError>;
            async fn get_vault_issue_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcIssueRequest)>, RuntimeError>;
            async fn get_issue_period(&self) -> Result<u32, RuntimeError>;
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
                tx_block_height: u32,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn cancel_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn get_new_vault_replace_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, RuntimeError>;
            async fn get_replace_period(&self) -> Result<u32, RuntimeError>;
        }
        #[async_trait]
        pub trait UtilFuncs {
            async fn get_current_chain_height(&self) -> Result<u32, RuntimeError>;
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

        let mut canceler = CancelationScheduler::new(Arc::new(provider), Default::default());

        let seconds_to_wait_1 = 5 * SECONDS_PER_BLOCK as u64 + MARGIN_SECONDS as u64;
        let seconds_to_wait_2 = 0;
        let seconds_to_wait_3 = MARGIN_SECONDS as u64 - 5 * SECONDS_PER_BLOCK as u64;

        // checks that the delay is calculated correctly, and that the vec is sorted
        assert_eq!(
            canceler
                .get_open_process_delays::<IssueCanceler>()
                .await
                .unwrap(),
            vec![
                (
                    H256::from_slice(&[2; 32]),
                    time::Duration::from_secs(seconds_to_wait_2)
                ),
                (
                    H256::from_slice(&[3; 32]),
                    time::Duration::from_secs(seconds_to_wait_3)
                ),
                (
                    H256::from_slice(&[1; 32]),
                    time::Duration::from_secs(seconds_to_wait_1)
                )
            ]
        );
    }
    #[tokio::test]
    async fn test_get_open_process_delays_fails() {
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

        let mut canceler = CancelationScheduler::new(Arc::new(provider), Default::default());
        assert_err!(
            canceler.get_open_process_delays::<IssueCanceler>().await,
            Error::InvalidOpenTime
        );
    }
}
