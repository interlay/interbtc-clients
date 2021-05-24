mod core;
mod error;
mod faucet;
mod vault;

pub mod relay;
pub mod system;

pub use error::Error;
pub use vault::Vaults;

pub mod service {
    pub use crate::{
        core::{Config, Runner},
        faucet::connect_and_fund,
        vault::{listen_for_vaults_registered, listen_for_wallet_updates, report_vault_thefts},
    };
}
