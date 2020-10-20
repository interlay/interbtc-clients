#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
mod btc_relay;
mod error;
mod issue;
mod param;
mod redeem;
mod vault;

use bitcoin::{BitcoinCore, BitcoinCoreApi};
use error::Error;
use runtime::{
    ExchangeRateOraclePallet, H256Le, PolkaBtcProvider, PolkaBtcRuntime, TimestampPallet,
};
use sp_core::H256;
use sp_keyring::AccountKeyring;
use std::{sync::Arc, time::Duration};
use substrate_subxt::PairSigner;

/// Generates testdata to be used on a development environment of the BTC-Parachain
#[tokio::main]
async fn main() -> Result<(), Error> {
    // setup BTC Parachain connection
    let alice = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Alice.pair());
    let bob = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Bob.pair());
    let alice_prov = PolkaBtcProvider::from_url(param::POLKA_BTC_URL.to_string(), alice).await?;
    let bob_prov = PolkaBtcProvider::from_url(param::POLKA_BTC_URL.to_string(), bob).await?;
    let charlie = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Charlie.pair());
    let charlie_prov =
        PolkaBtcProvider::from_url(param::POLKA_BTC_URL.to_string(), charlie).await?;

    // EXCHANGE RATE
    let oracle_prov = bob_prov.clone();

    // set exchange rate to 0.00038 at granularity 5
    let btc_to_dot_rate: u128 = 1;
    oracle_prov.set_exchange_rate_info(btc_to_dot_rate).await?;

    // get exchange rate
    let (rate, time, delay) = oracle_prov.get_exchange_rate_info().await?;
    println!(
        "Exchange Rate BTC/DOT: {:?}, Last Update: {}, Delay: {}",
        rate, time, delay
    );

    let current_time = oracle_prov.get_time_now().await?;
    println!("Current Time: {}", current_time);

    // INIT BTC RELAY
    // let mut btc_simulator = btc_relay::BtcSimulator::new(alice_prov.clone(), 1);
    // &btc_simulator.initialize().await?;
    let btc_rpc = &Arc::new(BitcoinCore::new(bitcoin::bitcoin_rpc_from_env()?));

    // ISSUE
    // register Bob as a vault
    // vault::register_vault(
    //     bob_prov.clone(),
    //     param::BOB_BTC_ADDRESS,
    //     param::BOB_VAULT_COLLATERAL,
    // )
    // .await?;

    // register Charlie as a vault
    // vault::register_vault(
    //     charlie_prov.clone(),
    //     param::CHARLIE_BTC_ADDRESS,
    //     param::CHARLIE_VAULT_COLLATERAL,
    // )
    // .await;

    println!("Requesting issue...");
    // Alice issues with Bob
    let issue_id = issue::request_issue(
        alice_prov.clone(),
        param::ALICE_ISSUE_AMOUNT,
        AccountKeyring::Bob.to_account_id(),
    )
    .await?;
    println!("btc payment..");

    let tx_metadata = btc_rpc
        .send_to_address(
            "bcrt1qywc4rq6sd778a0zud325xlk5yzmd2w3ed9larg".to_string(),
            param::ALICE_ISSUE_AMOUNT as u64,
            &issue_id.to_fixed_bytes(),
            Duration::from_secs(15 * 60),
            1,
        )
        .await
        .unwrap();
    //     // Alice makes the BTC payment and the BTC tx is included in BTC-Relay
    // let (tx_id, tx_block_height, merkle_proof, raw_tx) = &btc_simulator
    //     .generate_transaction_and_include(
    //         param::BOB_BTC_ADDRESS,
    //         param::ALICE_ISSUE_AMOUNT,
    //         issue_id,
    //     )
    //     .await?;

    // println!("BTC H256Le transaction id: {:?}", tx_id.to_string());
    println!("executing issue..");
    // Alice completes the issue request
    loop {
        match issue::execute_issue(
            alice_prov.clone(),
            &issue_id,
            &H256Le::from_bytes_le(tx_metadata.txid.as_ref()),
            &tx_metadata.block_height,
            &tx_metadata.proof,
            &tx_metadata.raw_tx,
        )
        .await
        {
            Ok(_) => break,
            Err(e) => {
                println!("Error: {}", e.to_string());
                tokio::time::delay_for(tokio::time::Duration::from_millis(5_000)).await;
            }
        };
    }
    println!("request_redeem..");

    // REDEEM
    // Alice redeems PolkaBTC
    let redeem_id = redeem::request_redeem(
        alice_prov.clone(),
        param::ALICE_REDEEM_AMOUNT_1,
        param::ALICE_BTC_ADDRESS,
        AccountKeyring::Bob.to_account_id(),
    )
    .await?;

    // // Bob (vault) makes the BTC payment and the BTC tx is included in BTC-Relay
    // let (tx_id, tx_block_height, merkle_proof, raw_tx) = &btc_simulator
    //     .generate_transaction_and_include(
    //         param::ALICE_BTC_ADDRESS,
    //         param::ALICE_REDEEM_AMOUNT_1,
    //         redeem_id,
    //     )
    //     .await?;

    // // Bob (vault) completes the redeem request
    // redeem::execute_redeem(
    //     bob_prov.clone(),
    //     &redeem_id,
    //     tx_id,
    //     tx_block_height,
    //     merkle_proof,
    //     raw_tx,
    // )
    // .await?;

    Ok(())
}
