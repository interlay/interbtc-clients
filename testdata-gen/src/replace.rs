#![allow(dead_code)]

use crate::Error;
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use log::info;
use runtime::{AccountId, BtcAddress, BtcRelayPallet, H256Le, PolkaBtcProvider, ReplacePallet, UtilFuncs};
use sp_core::H256;
use std::{convert::TryInto, time::Duration};

/// Request redeem
pub async fn request_replace(
    replace_prov: &PolkaBtcProvider,
    amount: u128,
    griefing_collateral: u128,
) -> Result<(), Error> {
    replace_prov.request_replace(amount, griefing_collateral).await?;
    info!(
        "Requested {:?} to replace {:?} tokens",
        replace_prov.get_account_id(),
        amount,
    );
    Ok(())
}

pub async fn accept_replace(
    replace_prov: &PolkaBtcProvider,
    btc_rpc: &BitcoinCore,
    old_vault: AccountId,
    amount_btc: u128,
    collateral: u128,
) -> Result<(), Error> {
    info!("Collateral: {}", collateral);
    let address = btc_rpc.get_new_address().await?;
    replace_prov
        .accept_replace(old_vault, amount_btc, collateral, address)
        .await?;
    Ok(())
}

pub async fn execute_replace(
    replace_prov: &PolkaBtcProvider,
    btc_rpc: &BitcoinCore,
    replace_id: H256,
) -> Result<(), Error> {
    let replace_request = replace_prov.get_replace_request(replace_id).await?;
    info!("Satoshis: {}", replace_request.amount);

    let tx_metadata = btc_rpc
        .send_to_address::<BtcAddress>(
            replace_request.btc_address,
            replace_request.amount.try_into().unwrap(),
            Some(replace_id),
            1,
        )
        .await?;

    replace_prov
        .wait_for_block_in_relay(H256Le::from_bytes_le(&tx_metadata.block_hash.to_vec()), None)
        .await?;

    replace_prov
        .execute_replace(replace_id, tx_metadata.proof, tx_metadata.raw_tx)
        .await?;

    Ok(())
}

/// Set replace period
pub async fn set_replace_period(replace_prov: &PolkaBtcProvider, period: u32) -> Result<(), Error> {
    replace_prov.set_replace_period(period).await?;

    info!("Set the replace period to {:?}", period,);

    Ok(())
}
