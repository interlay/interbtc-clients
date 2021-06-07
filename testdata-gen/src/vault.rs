use crate::Error;
use log::info;
use runtime::{BtcPublicKey, InterBtcParachain, UtilFuncs, VaultRegistryPallet};

/// Register a vault with a Bitcoin address
pub async fn register_vault(
    vault_prov: InterBtcParachain,
    public_key: BtcPublicKey,
    collateral: u128,
) -> Result<(), Error> {
    vault_prov.register_vault(collateral, public_key).await?;
    info!("Registered vault {:?}", vault_prov.get_account_id());

    Ok(())
}
