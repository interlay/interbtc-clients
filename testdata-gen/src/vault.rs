#[path = "param.rs"]
mod param;

use runtime::{Error, PolkaBtcProvider, VaultRegistryPallet};
use bitcoin::get_address_from_string;

/// Register a vault with a Bitcoin address
pub async fn register_vault(
    vault_prov: PolkaBtcProvider,
    btc_address: &str,
    collateral: u128,
) -> Result<(), Error> {
    let address = get_address_from_string(btc_address);
    vault_prov.register_vault(collateral, address).await?;
    println!("Registered vault {:?}", vault_prov.get_address().await);

    Ok(())
}
