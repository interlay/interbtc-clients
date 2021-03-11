mod error;
mod faucet;
mod http;
mod oracle;
pub mod relay;
mod sla;
mod types;
pub mod utils;
mod vault;
mod core;

pub use error::Error;
pub use types::Vaults;

pub mod service {
    pub use crate::faucet::fund_and_register;
    pub use crate::http::start_http;
    pub use crate::oracle::{OracleService, OracleServiceConfig};
    pub use crate::sla::SlaUpdateService;
    pub use crate::vault::{VaultTheftService, VaultTheftServiceConfig};
    pub use crate::vault::{VaultUpdateService, VaultUpdateServiceConfig};
}
