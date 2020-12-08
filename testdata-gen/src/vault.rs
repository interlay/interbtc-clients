use crate::Error;
use log::info;
use runtime::{BtcAddress, PolkaBtcProvider, VaultRegistryPallet};

/// Register a vault with a Bitcoin address
pub async fn register_vault(
    vault_prov: PolkaBtcProvider,
    btc_address: BtcAddress,
    collateral: u128,
) -> Result<(), Error> {
    vault_prov.register_vault(collateral, btc_address).await?;
    info!("Registered vault {:?}", vault_prov.get_account_id());

    Ok(())
}
