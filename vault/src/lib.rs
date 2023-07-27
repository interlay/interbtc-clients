#![recursion_limit = "256"]
#![feature(array_zip)]

mod cancellation;
pub mod delay;
mod error;
mod execution;
mod faucet;
mod issue;
pub mod metrics;
pub mod process;
mod redeem;
pub mod relay;
mod replace;
pub mod services;
mod system;
mod types;

pub mod service {
    pub use crate::{
        cancellation::{CancellationScheduler, IssueCanceller, ReplaceCanceller},
        execution::execute_open_requests,
        issue::{
            listen_for_issue_cancels, listen_for_issue_executes, listen_for_issue_requests, process_issue_requests,
        },
        metrics::monitor_bridge_metrics,
        redeem::listen_for_redeem_requests,
        relay::{Config, Runner},
        replace::{listen_for_accept_replace, listen_for_execute_replace, listen_for_replace_requests},
    };
}
use governor::Quota;
use nonzero_ext::*;
use std::time::Duration;
pub use system::{VaultService, VaultServiceConfig, ABOUT, AUTHORS, NAME, VERSION};

use runtime::{InterBtcParachain, VaultId, VaultRegistryPallet};

pub use crate::{cancellation::Event, error::Error, types::IssueRequests};
pub use delay::{OrderedVaultsDelay, RandomDelay, ZeroDelay};
pub use system::VaultIdManager;

pub(crate) async fn deposit_collateral(api: &InterBtcParachain, vault_id: &VaultId, amount: u128) -> Result<(), Error> {
    let result = api.deposit_collateral(vault_id, amount).await;
    tracing::info!("Locking additional collateral; amount {}: {:?}", amount, result);
    Ok(result?)
}

/// At startup we wait until a new block has arrived before we start event listeners.
/// This constant defines the rate at which we check whether the chain height has increased.
pub const CHAIN_HEIGHT_POLLING_INTERVAL: Duration = Duration::from_millis(500);

/// explicitly yield at most once per second
pub const YIELD_RATE: Quota = Quota::per_second(nonzero!(1u32));
