#![allow(dead_code)]

use crate::Error;
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use log::info;
use runtime::{AccountId, BtcAddress, BtcRelayPallet, H256Le, InterBtcParachain, RedeemPallet, UtilFuncs};
use sp_core::H256;
use std::convert::TryInto;

/// Request redeem
pub async fn request_redeem(
    redeem_prov: &InterBtcParachain,
    amount: u128,
    btc_address: BtcAddress,
    vault_id: AccountId,
) -> Result<H256, Error> {
    let redeem_id = redeem_prov.request_redeem(amount, btc_address, &vault_id).await?;

    info!(
        "Requested {:?} to redeem {:?} tokens from {:?}",
        redeem_prov.get_account_id(),
        amount,
        vault_id
    );

    Ok(redeem_id)
}

/// Execute redeem
pub async fn execute_redeem(
    redeem_prov: &InterBtcParachain,
    btc_rpc: &BitcoinCore,
    redeem_id: H256,
    redeem_amount: u128,
    btc_address: BtcAddress,
) -> Result<(), Error> {
    let tx_metadata = btc_rpc
        .send_to_address(btc_address, redeem_amount.try_into().unwrap(), Some(redeem_id), 1)
        .await?;

    redeem_prov
        .wait_for_block_in_relay(H256Le::from_bytes_le(&tx_metadata.block_hash.to_vec()), None)
        .await?;

    redeem_prov
        .execute_redeem(redeem_id, &tx_metadata.proof, &tx_metadata.raw_tx)
        .await?;

    info!("Executed redeem ID {:?}", redeem_id);
    Ok(())
}

/// Set redeem period
pub async fn set_redeem_period(redeem_prov: &InterBtcParachain, period: u32) -> Result<(), Error> {
    redeem_prov.set_redeem_period(period).await?;

    info!("Set the redeem period to {:?}", period);

    Ok(())
}
