#![recursion_limit = "256"]

mod cancellation;
mod collateral;
mod error;
mod execution;
mod faucet;
mod issue;
mod redeem;
mod refund;
mod replace;
mod retry;
mod system;
mod types;

use runtime::{PolkaBtcProvider, VaultRegistryPallet};
use std::time::Duration;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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
    tracing::info!("Locking additional collateral; amount {}: {:?}", amount, result);
    Ok(result?)
}

/// Retry bitcoin ops for at most 24 hours
pub const BITCOIN_MAX_RETRYING_TIME: Duration = Duration::from_secs(24 * 60 * 60);

/// At startup we wait until a new block has arrived before we start event listeners.
/// This constant defines the rate at which we check whether the chain height has increased.
pub const CHAIN_HEIGHT_POLLING_INTERVAL: Duration = Duration::from_millis(500);

pub fn init_subscriber() {
    let fmt_layer = fmt::layer();
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init();
}
