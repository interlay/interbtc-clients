#![allow(dead_code)]

use crate::Error;
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use log::info;
use runtime::{
    AccountId, BtcAddress, BtcRelayPallet, H256Le, InterBtcIssueRequest, InterBtcParachain, InterBtcRequestIssueEvent,
    IssuePallet, UtilFuncs,
};
use sp_core::H256;
use std::convert::TryInto;

/// Fetch an issue request by it's ID
pub async fn get_issue_by_id(issue_prov: &InterBtcParachain, issue_id: H256) -> Result<InterBtcIssueRequest, Error> {
    let issue_request = issue_prov.get_issue_request(issue_id).await?;

    Ok(issue_request)
}

/// Request issue
pub async fn request_issue(
    issue_prov: &InterBtcParachain,
    amount: u128,
    griefing_collateral: u128,
    vault_id: AccountId,
) -> Result<InterBtcRequestIssueEvent, Error> {
    let issue_data = issue_prov.request_issue(amount, &vault_id, griefing_collateral).await?;

    info!(
        "Requested {:?} to issue {:?} tokens from {:?}",
        issue_prov.get_account_id(),
        amount,
        issue_data.vault_id
    );

    Ok(issue_data)
}

/// Execute issue
pub async fn execute_issue(
    issue_prov: &InterBtcParachain,
    btc_rpc: &BitcoinCore,
    issue_id: H256,
    issue_amount: u128,
    vault_btc_address: BtcAddress,
) -> Result<(), Error> {
    let tx_metadata = btc_rpc
        .send_to_address(vault_btc_address, issue_amount.try_into().unwrap(), None, 1)
        .await?;

    issue_prov
        .wait_for_block_in_relay(H256Le::from_bytes_le(&tx_metadata.block_hash.to_vec()), None)
        .await?;

    issue_prov
        .execute_issue(issue_id, &tx_metadata.proof, &tx_metadata.raw_tx)
        .await?;

    info!("Executed issue ID {:?}", issue_id);
    Ok(())
}

/// Set issue period
pub async fn set_issue_period(issue_prov: &InterBtcParachain, period: u32) -> Result<(), Error> {
    issue_prov.set_issue_period(period).await?;

    info!("Set the issue period to {:?}", period,);

    Ok(())
}
