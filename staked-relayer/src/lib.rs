mod core;
mod error;
mod faucet;
mod http;
mod oracle;
mod status;
mod vault;

pub mod relay;
pub mod system;
pub mod utils;

pub use error::Error;
pub use vault::Vaults;

pub mod service {
    pub use crate::core::{Config, Runner};
    pub use crate::faucet::fund_and_register;
    pub use crate::http::start_http;
    pub use crate::oracle::report_offline_oracle;
    pub use crate::status::listen_for_blocks_stored;
    pub use crate::status::listen_for_status_updates;
    pub use crate::vault::listen_for_vaults_registered;
    pub use crate::vault::listen_for_wallet_updates;
    pub use crate::vault::report_vault_thefts;
}
