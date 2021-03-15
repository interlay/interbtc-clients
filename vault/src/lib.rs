#![recursion_limit = "256"]

mod cancellation;
mod collateral;
mod constants;
mod error;
mod execution;
mod faucet;
mod http;
mod issue;
mod redeem;
mod refund;
mod replace;
mod system;

use log::*;
use runtime::{PolkaBtcProvider, VaultRegistryPallet};

pub use crate::error::Error;
pub mod service {
    pub use crate::cancellation::CancellationScheduler;
    pub use crate::cancellation::IssueCanceller;
    pub use crate::cancellation::ReplaceCanceller;
    pub use crate::collateral::maintain_collateralization_rate;
    pub use crate::execution::execute_open_issue_requests;
    pub use crate::execution::execute_open_requests;
    pub use crate::issue::listen_for_issue_cancels;
    pub use crate::issue::listen_for_issue_executes;
    pub use crate::issue::listen_for_issue_requests;
    pub use crate::redeem::listen_for_redeem_requests;
    pub use crate::refund::listen_for_refund_requests;
    pub use crate::replace::listen_for_accept_replace;
    pub use crate::replace::listen_for_auction_replace;
    pub use crate::replace::listen_for_execute_replace;
    pub use crate::replace::listen_for_replace_requests;
    pub use crate::replace::monitor_collateral_of_vaults;
}
pub use crate::cancellation::RequestEvent;
pub use crate::issue::IssueRequests;
pub use crate::system::{VaultService, VaultServiceConfig};

pub(crate) async fn lock_additional_collateral(
    api: &PolkaBtcProvider,
    amount: u128,
) -> Result<(), Error> {
    let result = api.lock_additional_collateral(amount).await;
    info!(
        "Locking additional collateral; amount {}: {:?}",
        amount, result
    );
    Ok(result?)
}
