#![recursion_limit = "256"]

mod cancellation;
mod collateral;
mod error;
mod execution;
mod faucet;
mod issue;
mod redeem;
mod refund;
mod relay;
mod replace;
mod system;
mod types;
mod vaults;

// use runtime::{InterBtcParachain, VaultId, VaultRegistryPallet};
// use std::time::Duration;
//
pub mod service {
    pub use crate::{
        cancellation::{CancellationScheduler, IssueCanceller, ReplaceCanceller},
        collateral::maintain_collateralization_rate,
        execution::execute_open_requests,
        issue::{
            listen_for_issue_cancels, listen_for_issue_executes, listen_for_issue_requests, process_issue_requests,
        },
        redeem::listen_for_redeem_requests,
        refund::listen_for_refund_requests,
        relay::{Config, Runner},
        replace::{listen_for_accept_replace, listen_for_execute_replace, listen_for_replace_requests},
        vaults::{listen_for_vaults_registered, listen_for_wallet_updates, report_vault_thefts},
    };
}
use std::time::Duration;
pub use system::{VaultService, VaultServiceConfig, ABOUT, AUTHORS, NAME, VERSION};

use runtime::{InterBtcParachain, VaultId, VaultRegistryPallet};

// pub use crate::{cancellation::Event, error::Error, system::*, types::IssueRequests};
pub use crate::{cancellation::Event, error::Error, types::IssueRequests};
pub use system::VaultIdManager;
pub use vaults::Vaults;
//
pub(crate) async fn deposit_collateral(api: &InterBtcParachain, vault_id: &VaultId, amount: u128) -> Result<(), Error> {
    let result = api.deposit_collateral(vault_id, amount).await;
    tracing::info!("Locking additional collateral; amount {}: {:?}", amount, result);
    Ok(result?)
}

// /// At startup we wait until a new block has arrived before we start event listeners.
// /// This constant defines the rate at which we check whether the chain height has increased.
pub const CHAIN_HEIGHT_POLLING_INTERVAL: Duration = Duration::from_millis(500);
