mod btc_relay;
mod issue;
mod param;
mod redeem;
mod utils;
mod vault;

use runtime::{
    Error, ExchangeRateOraclePallet, PolkaBtcProvider, PolkaBtcRuntime, TimestampPallet,
};
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use substrate_subxt::PairSigner;
use tokio::sync::RwLock;

/// Generates testdata to be used on a development environment of the BTC-Parachain
#[tokio::main]
async fn main() -> Result<(), Error> {
    // setup BTC Parachain connection
    let alice = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Alice.pair());
    let bob = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Bob.pair());
    let alice_prov = PolkaBtcProvider::from_url(
        param::POLKA_BTC_URL.to_string(),
        Arc::new(RwLock::new(alice)),
    )
    .await?;
    let bob_prov =
        PolkaBtcProvider::from_url(param::POLKA_BTC_URL.to_string(), Arc::new(RwLock::new(bob)))
            .await?;

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
    let mut btc_simulator = btc_relay::BtcSimulator::new(alice_prov.clone(), 1);
    &btc_simulator.initialize().await?;

    // ISSUE
    // register Bob as a vault
    vault::register_vault(
        bob_prov.clone(),
        param::BOB_BTC_ADDRESS,
        param::BOB_VAULT_COLLATERAL,
    )
    .await?;

    // Alice issues with Bob
    let issue_id = issue::request_issue(
        alice_prov.clone(),
        param::ALICE_ISSUE_AMOUNT,
        AccountKeyring::Bob.to_account_id(),
    )
    .await?;

    // Alice makes the BTC payment and the BTC tx is included in BTC-Relay
    let (tx_id, tx_block_height, merkle_proof, raw_tx) = &btc_simulator
        .generate_transaction_and_include(
            param::BOB_BTC_ADDRESS,
            param::ALICE_ISSUE_AMOUNT,
            issue_id,
        )
        .await?;

    // Alice completes the issue request
    issue::execute_issue(
        alice_prov.clone(),
        &issue_id,
        tx_id,
        tx_block_height,
        merkle_proof,
        raw_tx,
    )
    .await?;

    // REDEEM
    // Alice redeems PolkaBTC
    let redeem_id = redeem::request_redeem(
        alice_prov.clone(),
        param::ALICE_REDEEM_AMOUNT_1,
        param::ALICE_BTC_ADDRESS,
        AccountKeyring::Bob.to_account_id(),
    )
    .await?;

    // Bob (vault) makes the BTC payment and the BTC tx is included in BTC-Relay
    let (tx_id, tx_block_height, merkle_proof, raw_tx) = &btc_simulator
        .generate_transaction_and_include(
            param::ALICE_BTC_ADDRESS,
            param::ALICE_REDEEM_AMOUNT_1,
            redeem_id,
        )
        .await?;

    // Bob (vault) completes the redeem request
    redeem::execute_redeem(
        bob_prov.clone(),
        &redeem_id,
        tx_id,
        tx_block_height,
        merkle_proof,
        raw_tx,
    )
    .await?;

    Ok(())
}
