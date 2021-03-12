mod backing;
mod error;
mod issuing;

pub use error::Error;

pub use backing::Client as BitcoinClient;

pub use issuing::Client as PolkaBtcClient;

use crate::core::Runner;
use log::error;
use runtime::PolkaBtcProvider;
use std::sync::Arc;
use std::time::Duration;

pub async fn run_relayer(
    runner: Runner<Error, BitcoinClient, PolkaBtcClient>,
    provider: Arc<PolkaBtcProvider>,
    timeout: Duration,
) {
    loop {
        super::utils::wait_until_registered(&provider, timeout).await;
        if let Err(err) = runner.submit_next().await {
            error!("Failed to submit_next: {}", err);
        }
    }
}
