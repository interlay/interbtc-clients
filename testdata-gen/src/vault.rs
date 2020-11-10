use crate::Error;
use bitcoin::get_hash_from_string;
use log::info;
use runtime::PolkaBtcProvider;

/// Register a vault with a Bitcoin address
pub async fn register_vault(
    vault_prov: PolkaBtcProvider,
    btc_address: &str,
    collateral: u128,
) -> Result<(), Error> {
    let address = get_hash_from_string(btc_address)?;
    vault_prov.register_vault(collateral, address).await?;
    info!("Registered vault {:?}", vault_prov.get_account_id());

    Ok(())
}