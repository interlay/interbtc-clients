#![allow(dead_code)]

use crate::Error;
use bitcoin::get_hash_from_string;
use runtime::pallets::btc_relay::H256Le;
use runtime::{PolkaBtcProvider, RedeemPallet};
use sp_core::crypto::AccountId32;
use sp_core::H256;

/// Request redeem of PolkaBTC
pub async fn request_redeem(
    redeem_prov: &PolkaBtcProvider,
    amount_polka_btc: u128,
    btc_address: &str,
    vault_id: AccountId32,
) -> Result<H256, Error> {
    let address = get_hash_from_string(btc_address)?;
    let redeem_id = redeem_prov
        .request_redeem(amount_polka_btc, address, vault_id.clone())
        .await?;

    println!(
        "Requested {:?} to redeem {:?} PolkaBTC from {:?}",
        redeem_prov.get_account_id(),
        amount_polka_btc,
        vault_id
    );

    Ok(redeem_id)
}

/// Execute redeem of PolkaBTC
pub async fn execute_redeem(
    redeem_prov: PolkaBtcProvider,
    redeem_id: &H256,
    tx_id: &H256Le,
    tx_block_height: &u32,
    merkle_proof: &Vec<u8>,
    raw_tx: &Vec<u8>,
) -> Result<(), Error> {
    redeem_prov
        .execute_redeem(
            *redeem_id,
            *tx_id,
            *tx_block_height,
            merkle_proof.clone(),
            raw_tx.clone(),
        )
        .await?;
    println!("Executed redeem ID {:?}", redeem_id);

    Ok(())
}
