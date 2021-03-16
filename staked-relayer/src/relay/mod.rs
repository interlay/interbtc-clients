mod backing;
mod error;
mod issuing;

pub use error::Error;

pub use backing::Client as BitcoinClient;

pub use issuing::Client as PolkaBtcClient;

use crate::core::{Error as CoreError, Runner};
use log::{error, info};
use runtime::{
    substrate_subxt::{Error as SubxtError, ModuleError as SubxtModuleError, RuntimeError as SubxtRuntimeError},
    Error as RuntimeError, PolkaBtcProvider, BTC_RELAY_MODULE, DUPLICATE_BLOCK_ERROR,
};
use std::time::Duration;

pub async fn run_relayer(
    runner: Runner<Error, BitcoinClient, PolkaBtcClient>,
    provider: PolkaBtcProvider,
    timeout: Duration,
) {
    loop {
        super::utils::wait_until_registered(&provider, timeout).await;
        match runner.submit_next().await {
            Ok(_) => (),
            Err(CoreError::Issuing(Error::PolkaBtcError(RuntimeError::XtError(SubxtError::Runtime(
                SubxtRuntimeError::Module(SubxtModuleError { ref module, ref error }),
            )))))
                if module == BTC_RELAY_MODULE && error == DUPLICATE_BLOCK_ERROR =>
            {
                info!("Attempted to submit block that already exists")
            }
            Err(err) => {
                error!("Failed to submit_next: {}", err);
            }
        }
    }
}
