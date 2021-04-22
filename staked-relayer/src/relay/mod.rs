mod backing;
mod error;
mod issuing;

pub use error::Error;

pub use backing::Client as BitcoinClient;

pub use issuing::Client as PolkaBtcClient;

use crate::core::{Error as CoreError, Runner};
use runtime::PolkaBtcProvider;
use service::Error as ServiceError;
use std::time::Duration;

pub async fn run_relayer(
    runner: Runner<Error, BitcoinClient, PolkaBtcClient>,
    provider: PolkaBtcProvider,
    timeout: Duration,
) -> Result<(), ServiceError> {
    loop {
        super::utils::wait_until_registered(&provider, timeout).await;
        match runner.submit_next().await {
            Ok(_) => (),
            Err(CoreError::Issuing(Error::PolkaBtcError(ref err))) if err.is_duplicate_block() => {
                tracing::info!("Attempted to submit block that already exists")
            }
            Err(CoreError::Backing(Error::BitcoinError(err))) if err.is_connection_refused() => {
                return Err(ServiceError::ClientShutdown);
            }
            Err(err) => {
                tracing::error!("Failed to submit_next: {}", err);
            }
        }
    }
}
