#[path = "param.rs"]
mod param;

use module_bitcoin::types::H256Le;
use runtime::{Error, IssuePallet, PolkaBtcProvider};
use sp_core::crypto::AccountId32;
use sp_core::H256;

/// Request issue of PolkaBTC
pub async fn request_issue(
    issue_prov: PolkaBtcProvider,
    amount: u128,
    vault_id: AccountId32,
) -> Result<H256, Error> {
    let issue_id = issue_prov
        .request_issue(amount, vault_id.clone(), param::GRIEFING_COLLATERAL)
        .await?;

    println!(
        "Requested {:?} to issue {:?} PolkaBTC from {:?}",
        issue_prov.get_address().await,
        amount,
        vault_id
    );

    Ok(issue_id)
}

/// Execute issue of PolkaBTC
pub async fn execute_issue(
    issue_prov: PolkaBtcProvider,
    issue_id: &H256,
    tx_id: &H256Le,
    tx_block_height: &u32,
    merkle_proof: &Vec<u8>,
    raw_tx: &Vec<u8>,
) -> Result<(), Error> {
    issue_prov
        .execute_issue(
            *issue_id,
            *tx_id,
            *tx_block_height,
            merkle_proof.clone(),
            raw_tx.clone(),
        )
        .await?;
    println!("Executed issue ID {:?}", issue_id);

    Ok(())
}
