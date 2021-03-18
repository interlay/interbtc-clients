#![recursion_limit = "256"]

mod cancellation;
mod collateral;
mod constants;
mod error;
mod execution;
mod faucet;
mod issue;
mod redeem;
mod refund;
mod replace;
mod system;
mod types;

use log::*;
use runtime::{PolkaBtcProvider, VaultRegistryPallet};

pub mod service {
    pub use crate::{
        cancellation::{CancellationScheduler, IssueCanceller, ReplaceCanceller},
        collateral::maintain_collateralization_rate,
        execution::execute_open_requests,
        issue::{listen_for_issue_cancels, listen_for_issue_executes, listen_for_issue_requests},
        redeem::listen_for_redeem_requests,
        refund::listen_for_refund_requests,
        replace::{
            listen_for_accept_replace, listen_for_auction_replace, listen_for_execute_replace,
            listen_for_replace_requests, monitor_collateral_of_vaults,
        },
    };
}
pub use crate::{
    cancellation::RequestEvent,
    error::Error,
    system::{VaultService, VaultServiceConfig},
    types::IssueRequests,
};

pub(crate) async fn lock_additional_collateral(api: &PolkaBtcProvider, amount: u128) -> Result<(), Error> {
    let result = api.lock_additional_collateral(amount).await;
    info!("Locking additional collateral; amount {}: {:?}", amount, result);
    Ok(result?)
}
