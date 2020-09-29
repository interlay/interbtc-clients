#[path = "param.rs"]
mod param;
#[path = "utils.rs"]
mod utils;

use runtime::{Error, PolkaBtcProvider, VaultRegistryPallet};

/// Register a vault with a Bitcoin address
pub async fn register_vault(
    vault_prov: PolkaBtcProvider,
    btc_address: &str,
    collateral: u128,
) -> Result<(), Error> {
    let address = utils::get_address_from_string(btc_address);
    vault_prov.register_vault(collateral, address).await?;
    println!("Registered vault {:?}", vault_prov.get_address().await);

    Ok(())
}
