mod error;
mod faucet;
mod http;
mod oracle;
pub mod relay;
mod status;
pub mod utils;
mod vault;

pub use error::Error;
pub use vault::Vaults;

pub mod service {
    pub use crate::faucet::get_faucet_allowance;
    pub use crate::faucet::get_funding;
    pub use crate::http::start as start_api;
    pub use crate::oracle::report_offline_oracle;
    pub use crate::status::listen_for_blocks_stored;
    pub use crate::status::listen_for_status_updates;
    pub use crate::vault::listen_for_vaults_registered;
    pub use crate::vault::listen_for_wallet_updates;
    pub use crate::vault::report_vault_thefts;
}
