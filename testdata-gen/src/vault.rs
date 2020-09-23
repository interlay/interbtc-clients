#[path = "param.rs"] mod param;
#[path = "utils.rs"] mod utils;

use runtime::{PolkaBtcProvider, Error};

/// Register a vault with a Bitcoin address
pub async fn register_vault(vault_prov: PolkaBtcProvider, btc_address: &str) -> Result<(), Error> {
    let address = utils::get_address_from_string(btc_address);
    vault_prov.register_vault(param::VAULT_COLLATERAL, address).await?;
    println!("Registered vault BOB");

    Ok(())
}