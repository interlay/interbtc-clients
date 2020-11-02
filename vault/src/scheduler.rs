use super::Error;
use futures::channel::mpsc::Receiver;
use futures::*;
use log::*;
use runtime::{IssuePallet, PolkaBtcProvider};
use sp_core::{crypto::AccountId32, H256};
use std::sync::Arc;
use tokio::time;
use tokio::time::Instant;

const SECONDS_PER_BLOCK: u64 = 6;

struct ActiveIssue {
    deadline: Instant,
    id: H256,
}
pub enum IssueEvent {
    IssueReceived,
    IssueExecuted(H256),
}

pub struct CancelationScheduler {
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
    issue_period: Option<u64>,
}

impl CancelationScheduler {
    pub fn new(provider: Arc<PolkaBtcProvider>, vault_id: AccountId32) -> CancelationScheduler {
        CancelationScheduler {
            provider,
            vault_id,
            issue_period: None,
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
    pub async fn issue_canceler(&mut self, mut event_listener: Receiver<IssueEvent>) {
        let mut active_issues_is_up_to_date = false;
        let mut active_issues: Vec<ActiveIssue> = vec![];

        loop {
            // try to get an up-to-date list of issues if we don't have it yet
            if !active_issues_is_up_to_date {
                active_issues.clear();
                match self.get_open_issue_requests().await {
                    Ok(x) => {
                        active_issues = x;
                        active_issues.sort_by(|a, b| a.deadline.partial_cmp(&b.deadline).unwrap());
                        active_issues_is_up_to_date = true;
                    }
                    Err(e) => {
                        error!("Failed to query open issues: {}", e);
                        active_issues.clear();
                    }
                }
            }

            // determine how long we will sleep
            let task_wait = if !active_issues_is_up_to_date {
                // failed to query open issues; try again in 15 minutes
                time::delay_for(time::Duration::from_secs(15 * 60)).fuse()
            } else {
                match active_issues.first() {
                    Some(issue) => {
                        // sleep until the first event
                        debug!(
                            "delaying until first issue: {:?}",
                            issue.deadline - time::Instant::now()
                        );
                        time::delay_until(issue.deadline).fuse()
                    }
                    None => {
                        // there are no open issues; we sleep until we get an event
                        debug!("No open issues");
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
                    if active_issues.len() > 0
                        && self
                            .provider
                            .cancel_issue(active_issues[0].id)
                            .await
                            .is_ok()
                    {
                        info!("Canceled issue");
                        active_issues.remove(0);
                    } else {
                        error!("No issue canceled!");
                        // We didn't remove an issue: force re-read of open
                        // issues at beginning of loop
                        active_issues_is_up_to_date = false;
                        // small delay to prevent spamming rpc calls on persistent failures
                        // Wrapped in a function to prevent "recursion limit reached" compiler
                        // error
                        self.rate_limit().await;
                    }
                }
                e = task_read => match e {
                    Some(IssueEvent::IssueExecuted(id)) => {
                        debug!("Received execute_issue");
                        active_issues.retain(|x| x.id != id);
                    },
                    Some(IssueEvent::IssueReceived) => {
                        debug!("Received issue request");
                        // will query active issue at start of loop
                        active_issues_is_up_to_date = false;
                    }
                    _ => {
                        error!("Failed to read IssueEvent");
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
    async fn get_open_issue_requests(&mut self) -> Result<Vec<ActiveIssue>, Error> {
        let open_issues = self
            .provider
            .get_vault_issue_requests(self.vault_id.clone())
            .await?;

        if open_issues.len() == 0 {
            return Ok(vec![]);
        }

        // get current block height and issue period
        let chain_height = self.provider.get_current_chain_height().await?;
        let issue_period = self.get_issue_period().await?;

        // try to cancel 5 minutes after deadline, to acount for timing inaccuracies
        let margin_period = (5 * 60) / SECONDS_PER_BLOCK;

        let ret = open_issues
            .iter()
            .map(|(id, data)| {
                let deadline_block = data.opentime + issue_period + margin_period;

                let deadline = if chain_height < deadline_block {
                    let remaining_blocks = 2;
                    time::Instant::now() + (time::Duration::from_secs(6) * remaining_blocks)
                } else {
                    // deadline has already passed, should cancel ASAP
                    // this branch can occur when e.g. the vault has been restarted
                    time::Instant::now()
                };

                ActiveIssue {
                    id: *id,
                    deadline,
                }
            })
            .collect();
        Ok(ret)
    }

    /// Cached function to get the issue period, in number of blocks until
    /// the issue is allowed to be canceled
    async fn get_issue_period(&mut self) -> Result<u64, Error> {
        match self.issue_period {
            Some(x) => Ok(x),
            None => {
                let ret = self.provider.get_issue_period().await? as u64;
                self.issue_period = Some(ret);
                Ok(ret)
            }
        }
    }
}
