mod backing;
mod error;
mod issuing;

pub use error::Error;

pub use backing::Client as BitcoinClient;

pub use issuing::Client as PolkaBtcClient;

use futures::executor::block_on;
use log::error;
use relayer_core::Runner;
use runtime::PolkaBtcProvider;
use std::sync::Arc;
use std::time::Duration;

pub fn run_relayer(
    runner: Runner<Error, BitcoinClient, PolkaBtcClient>,
    provider: Arc<PolkaBtcProvider>,
    timeout: Duration,
) {
    loop {
        block_on(super::utils::wait_until_registered(&provider, timeout));
        if let Err(err) = runner.submit_next() {
            error!("Failed to submit_next: {}", err);
        }
    }
}
