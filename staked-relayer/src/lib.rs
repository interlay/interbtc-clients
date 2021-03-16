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
    pub use crate::{
        core::{Config, Runner},
        faucet::fund_and_register,
        http::start_http,
        oracle::report_offline_oracle,
        status::{listen_for_blocks_stored, listen_for_status_updates},
        vault::{listen_for_vaults_registered, listen_for_wallet_updates, report_vault_thefts},
    };
}
