use super::Error;
use async_trait::async_trait;
use futures::channel::mpsc::Receiver;
use futures::*;
use log::*;
use runtime::{IssuePallet, PolkaBtcProvider, ReplacePallet};
use sp_core::{crypto::AccountId32, H256};
use std::sync::Arc;
use tokio::time;
use tokio::time::Instant;

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

pub struct CancelationScheduler {
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
    period: Option<u32>,
}

pub struct UnconvertedOpenTime {
    id: H256,
    opentime: u32,
}

#[async_trait]
pub trait Canceler {
    /// Gets a list of open replace/issue processes
    async fn get_open_processes(
        provider: Arc<PolkaBtcProvider>,
        vault_id: AccountId32,
    ) -> Result<Vec<UnconvertedOpenTime>, Error>;

    /// Gets the timeout period in number of blocks
    async fn get_period(provider: Arc<PolkaBtcProvider>) -> Result<u32, Error>;

    /// Cancels the issue/replace
    async fn cancel_process(provider: Arc<PolkaBtcProvider>, process_id: H256)
        -> Result<(), Error>;

    /// Gets either "replace" or "issue"; used for logging
    fn type_name() -> String;
}

pub struct IssueCanceler;
#[async_trait]
impl Canceler for IssueCanceler {
    async fn get_open_processes(
        provider: Arc<PolkaBtcProvider>,
        vault_id: AccountId32,
    ) -> Result<Vec<UnconvertedOpenTime>, Error> {
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
    async fn get_period(provider: Arc<PolkaBtcProvider>) -> Result<u32, Error> {
        Ok(provider.get_issue_period().await?)
    }
    async fn cancel_process(
        provider: Arc<PolkaBtcProvider>,
        process_id: H256,
    ) -> Result<(), Error> {
        Ok(provider.cancel_issue(process_id).await?)
    }
    fn type_name() -> String {
        "issue".to_string()
    }
}

pub struct ReplaceCanceler;
#[async_trait]
impl Canceler for ReplaceCanceler {
    async fn get_open_processes(
        provider: Arc<PolkaBtcProvider>,
        vault_id: AccountId32,
    ) -> Result<Vec<UnconvertedOpenTime>, Error> {
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
    async fn get_period(provider: Arc<PolkaBtcProvider>) -> Result<u32, Error> {
        Ok(provider.get_replace_period().await?)
    }
    async fn cancel_process(
        provider: Arc<PolkaBtcProvider>,
        process_id: H256,
    ) -> Result<(), Error> {
        Ok(provider.cancel_replace(process_id).await?)
    }
    fn type_name() -> String {
        "replace".to_string()
    }
}

impl CancelationScheduler {
    pub fn new(provider: Arc<PolkaBtcProvider>, vault_id: AccountId32) -> CancelationScheduler {
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
    pub async fn handle_cancelation<T: Canceler>(
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
                        active_processes
                            .sort_by(|a, b| a.deadline.partial_cmp(&b.deadline).unwrap());
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
    async fn get_open_processes<T: Canceler>(&mut self) -> Result<Vec<ActiveProcess>, Error> {
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

        let ret = open_processes
            .iter()
            .map(|UnconvertedOpenTime { id, opentime }| {
                let deadline_block = opentime + period + margin_period;

                let deadline = if chain_height < deadline_block {
                    let remaining_blocks = 2;
                    time::Instant::now()
                        + (time::Duration::from_secs(SECONDS_PER_BLOCK.into()) * remaining_blocks)
                } else {
                    // deadline has already passed, should cancel ASAP
                    // this branch can occur when e.g. the vault has been restarted
                    time::Instant::now()
                };

                ActiveProcess { id: *id, deadline }
            })
            .collect();
        Ok(ret)
    }

    /// Cached function to get the issue/replace period, in number of blocks until
    /// it is allowed to be canceled
    async fn get_cached_period<T: Canceler>(&mut self) -> Result<u32, Error> {
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
