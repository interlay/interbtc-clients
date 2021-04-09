mod core;
mod error;
mod faucet;
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
        status::{listen_for_blocks_stored, listen_for_status_updates},
        vault::{listen_for_vaults_registered, listen_for_wallet_updates, report_vault_thefts},
    };
}

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init_subscriber() {
    let fmt_layer = fmt::layer();
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init();
}
