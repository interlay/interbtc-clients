#![allow(dead_code)]

use crate::{utils, Error};
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use log::info;
use runtime::pallets::btc_relay::H256Le;
use runtime::{BtcAddress, IssuePallet, PolkaBtcProvider};
use sp_core::crypto::AccountId32;
use sp_core::H256;
use std::convert::TryInto;
use std::time::Duration;

/// Request issue of PolkaBTC
pub async fn request_issue(
    issue_prov: &PolkaBtcProvider,
    amount: u128,
    griefing_collateral: u128,
    vault_id: AccountId32,
) -> Result<H256, Error> {
    let issue_id = issue_prov
        .request_issue(amount, vault_id.clone(), griefing_collateral)
        .await?;

    info!(
        "Requested {:?} to issue {:?} PolkaBTC from {:?}",
        issue_prov.get_account_id(),
        amount,
        vault_id
    );

    Ok(issue_id)
}

/// Execute issue of PolkaBTC
pub async fn execute_issue(
    issue_prov: &PolkaBtcProvider,
    btc_rpc: &BitcoinCore,
    issue_id: H256,
    issue_amount: u128,
    vault_btc_address: String,
) -> Result<(), Error> {
    let tx_metadata = btc_rpc
        .send_to_address::<BtcAddress>(
            vault_btc_address,
            issue_amount.try_into().unwrap(),
            &issue_id.to_fixed_bytes(),
            Duration::from_secs(15 * 60),
            1,
        )
        .await?;

    utils::wait_for_block_in_relay(issue_prov, tx_metadata.block_hash).await;

    issue_prov
        .execute_issue(
            issue_id,
            H256Le::from_bytes_le(tx_metadata.txid.as_ref()),
            tx_metadata.block_height,
            tx_metadata.proof,
            tx_metadata.raw_tx,
        )
        .await?;

    info!("Executed issue ID {:?}", issue_id);
    Ok(())
}
