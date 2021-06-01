mod backing;
mod error;
mod issuing;

pub use error::Error;

pub use backing::Client as BitcoinClient;

pub use issuing::Client as PolkaBtcClient;

use crate::core::{Error as CoreError, Runner};
use service::Error as ServiceError;

pub async fn run_relayer(runner: Runner<Error, BitcoinClient, PolkaBtcClient>) -> Result<(), ServiceError> {
    loop {
        match runner.submit_next().await {
            Ok(_) => (),
            Err(CoreError::Issuing(Error::PolkaBtcError(ref err))) if err.is_duplicate_block() => {
                tracing::info!("Attempted to submit block that already exists")
            }
            Err(CoreError::Issuing(Error::PolkaBtcError(ref err))) if err.is_rpc_disconnect_error() => {
                return Err(ServiceError::ClientShutdown);
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
