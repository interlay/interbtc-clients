#![allow(dead_code)]

use crate::{utils, Error};
use bitcoin::get_hash_from_string;
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use log::info;
use runtime::pallets::btc_relay::H256Le;
use runtime::{PolkaBtcProvider, RedeemPallet};
use sp_core::crypto::AccountId32;
use sp_core::H256;
use std::convert::TryInto;
use std::time::Duration;

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

    info!(
        "Requested {:?} to redeem {:?} PolkaBTC from {:?}",
        redeem_prov.get_account_id(),
        amount_polka_btc,
        vault_id
    );

    Ok(redeem_id)
}

/// Execute redeem of PolkaBTC
pub async fn execute_redeem(
    redeem_prov: &PolkaBtcProvider,
    btc_rpc: &BitcoinCore,
    redeem_id: H256,
    redeem_amount: u128,
    btc_address: String,
) -> Result<(), Error> {
    let tx_metadata = btc_rpc
        .send_to_address(
            btc_address,
            redeem_amount.try_into().unwrap(),
            &redeem_id.to_fixed_bytes(),
            Duration::from_secs(15 * 60),
            1,
        )
        .await?;

    utils::wait_for_block_in_relay(redeem_prov, tx_metadata.block_hash).await;

    redeem_prov
        .execute_redeem(
            redeem_id,
            H256Le::from_bytes_le(tx_metadata.txid.as_ref()),
            tx_metadata.block_height,
            tx_metadata.proof,
            tx_metadata.raw_tx,
        )
        .await?;

    info!("Executed redeem ID {:?}", redeem_id);
    Ok(())
}
