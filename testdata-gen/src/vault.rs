use crate::Error;
use log::info;
use runtime::PolkaBtcProvider;
use sp_core::H160;

/// Register a vault with a Bitcoin address
pub async fn register_vault(
    vault_prov: PolkaBtcProvider,
    btc_address: H160,
    collateral: u128,
) -> Result<(), Error> {
    vault_prov.register_vault(collateral, btc_address).await?;
    info!("Registered vault {:?}", vault_prov.get_account_id());

    Ok(())
}
