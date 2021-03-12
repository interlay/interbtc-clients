use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error<E: std::error::Error> {
    #[error("Client already initialized")]
    AlreadyInitialized,
    #[error("Client has not been initialized")]
    NotInitialized,
    #[error("Block already submitted")]
    BlockExists,
    #[error("Cannot read the best height")]
    CannotFetchBestHeight,
    #[error("Block hash not found for the given height")]
    BlockHashNotFound,
    #[error("Call failed after {0} retries")]
    CallFailed(u32),
    #[error("Backing error: {0}")]
    Backing(E),
    #[error("Issuing error: {0}")]
    Issuing(E),
}
