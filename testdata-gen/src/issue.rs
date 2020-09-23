#[path = "param.rs"] mod param;

use sp_core::{H160, H256, U256};
use sp_core::crypto::AccountId32;
use runtime::{PolkaBtcProvider, IssuePallet, Error};

/// Request issue of PolkaBTC
pub async fn request_issue(issue_prov: PolkaBtcProvider, amount: u128, vault_id: AccountId32) -> Result<(), Error> {
    issue_prov.request_issue(amount, vault_id.clone(), param::GRIEFING_COLLATERAL).await?;

    println!("Requested {:?} to issue {:?} PolkaBTC from {:?}", issue_prov.get_address().await, amount, vault_id);

    Ok(())
}