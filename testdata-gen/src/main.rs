mod param;
mod utils;
mod btc_relay;
mod vault;
mod issue;

use sp_core::{H160, H256, U256};
use sp_keyring::AccountKeyring;
use substrate_subxt::PairSigner;
use runtime::{ExchangeRateOraclePallet, PolkaBtcProvider, PolkaBtcRuntime, Error};
use tokio::sync::Mutex;
use std::sync::Arc;

/// Generates testdata to be used on a development environment of the BTC-Parachain
#[tokio::main]
async fn main() -> Result<(), Error> {
    // setup BTC Parachain connection
    let alice = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Alice.pair());
    let bob = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Bob.pair());
    let alice_prov = PolkaBtcProvider::from_url(param::POLKA_BTC_URL.to_string(), Arc::new(Mutex::new(alice))).await?;
    let bob_prov = PolkaBtcProvider::from_url(param::POLKA_BTC_URL.to_string(), Arc::new(Mutex::new(bob))).await?;

    // EXCHANGE RATE
    let oracle_prov = bob_prov.clone();

    // set exchange rate to 0.00038 at granularity 5
    let btc_to_dot_rate: u128 = 38;
    // FIXME: Error: XtError(TypeSizeUnavailable("StatusCode"))
    // oracle_prov.set_exchange_rate_info(btc_to_dot_rate).await?;

    // get exchange rate
    let (rate, _time, _delay) = oracle_prov.get_exchange_rate_info().await?;
    println!("Exchange Rate BTC/DOT {:?}", rate);

    // INIT BTC RELAY
    let mut btc_simulator = btc_relay::BtcSimulator::new(alice_prov.clone(), 1);
    let prev_block = &btc_simulator.initialize().await?;

    // TODO: move this to the issue process
    let return_data = H256::zero();
    let (tx_id, tx_block_height, bytes_proof, raw_tx) = &btc_simulator.generate_transaction_and_include(
        prev_block,
        param::BOB_BTC_ADDRESS,
        param::ALICE_ISSUE_AMOUNT,
        return_data
    ).await?;

    // ISSUE
    // register Bob as a vault
    vault::register_vault(bob_prov.clone(), param::BOB_BTC_ADDRESS).await?;
    // Alice issues with Bob
    // TODO: get the issue_id from the request issue event
    // FIXME: Error: XtError(Metadata(ErrorNotFound(1)))
    issue::request_issue(alice_prov.clone(), param::ALICE_ISSUE_AMOUNT, AccountKeyring::Bob.to_account_id()).await?;

    Ok(())
}
