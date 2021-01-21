mod backing;
mod error;
mod issuing;

pub use error::Error;

pub use backing::Client as BitcoinClient;

pub use issuing::Client as PolkaBtcClient;
