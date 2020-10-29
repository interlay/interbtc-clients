use log::{error, info};
use runtime::{pallets::issue::RequestIssueEvent, PolkaBtcProvider, PolkaBtcRuntime};
use sp_core::crypto::AccountId32;
use std::sync::Arc;

/// Listen for RequestIssueEvent directed at this vault; this is only for logging, since
/// issueing requires no active participation of the vault
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `vault_id` - the id of this vault
pub async fn listen_for_issue_requests(
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
) -> Result<(), runtime::Error> {
    let vault_id = &vault_id;
    provider
        .on_event::<RequestIssueEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if event.vault_id == vault_id.clone() {
                    info!("Received issue request #{}", event.issue_id);
                }
            },
            |error| error!("Error reading issue event: {}", error.to_string()),
        )
        .await
}
