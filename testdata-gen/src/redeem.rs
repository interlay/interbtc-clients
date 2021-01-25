#![allow(dead_code)]

use crate::{utils, Error};
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use log::info;
use runtime::pallets::btc_relay::H256Le;
use runtime::{AccountId, BtcAddress, PolkaBtcProvider, RedeemPallet, UtilFuncs};
use sp_core::H256;
use std::convert::TryInto;
use std::time::Duration;

/// Request redeem of PolkaBTC
pub async fn request_redeem(
    redeem_prov: &PolkaBtcProvider,
    amount_polka_btc: u128,
    btc_address: BtcAddress,
    vault_id: AccountId,
) -> Result<H256, Error> {
    let redeem_id = redeem_prov
        .request_redeem(amount_polka_btc, btc_address, vault_id.clone())
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
    btc_address: BtcAddress,
) -> Result<(), Error> {
    let tx_metadata = btc_rpc
        .send_to_address(
            btc_address,
            redeem_amount.try_into().unwrap(),
            Some(redeem_id),
            Duration::from_secs(15 * 60),
            1,
        )
        .await?;

    utils::wait_for_block_in_relay(redeem_prov, tx_metadata.block_hash).await;

    redeem_prov
        .execute_redeem(
            redeem_id,
            H256Le::from_bytes_le(tx_metadata.txid.as_ref()),
            tx_metadata.proof,
            tx_metadata.raw_tx,
        )
        .await?;

    info!("Executed redeem ID {:?}", redeem_id);
    Ok(())
}

/// Set redeem period of PolkaBTC
pub async fn set_redeem_period(redeem_prov: &PolkaBtcProvider, period: u32) -> Result<(), Error> {
    redeem_prov.set_redeem_period(period).await?;

    info!("Set the redeem period to {:?}", period);

    Ok(())
}
