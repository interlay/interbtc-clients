use crate::scheduler::IssueEvent;
use futures::channel::mpsc::Sender;
use futures::SinkExt;
use log::{error, info};
use runtime::{
    pallets::issue::{ExecuteIssueEvent, RequestIssueEvent},
    PolkaBtcProvider, PolkaBtcRuntime,
};
use sp_core::crypto::AccountId32;
use std::sync::Arc;

/// Listen for RequestIssueEvent directed at this vault. Schedules a cancelation of
/// the received issue
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `vault_id` - the id of this vault
pub async fn listen_for_issue_requests(
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
    event_channel: Sender<IssueEvent>,
) -> Result<(), runtime::Error> {
    let vault_id = &vault_id;
    let event_channel = &event_channel;
    provider
        .on_event::<RequestIssueEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if event.vault_id == vault_id.clone() {
                    info!("Received event: request issue #{}", event.issue_id);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel.clone().send(IssueEvent::IssueReceived).await;
                }
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
pub async fn listen_for_issue_executes(
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
    event_channel: Sender<IssueEvent>,
) -> Result<(), runtime::Error> {
    let vault_id = &vault_id;
    let event_channel = &event_channel;
    provider
        .on_event::<ExecuteIssueEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if event.vault_id == vault_id.clone() {
                    info!("Received event: execute issue #{}", event.issue_id);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel
                        .clone()
                        .send(IssueEvent::IssueExecuted(event.issue_id))
                        .await;
                }
            },
            |error| error!("Error reading issue event: {}", error.to_string()),
        )
        .await
}
