use sp_keyring::AccountKeyring;
use primitive_types::{H256, U256};
use sp_core::H160;
use substrate_subxt::PairSigner;
use runtime::{ExchangeRateOraclePallet, PolkaBtcProvider, PolkaBtcRuntime, Error};
use tokio::sync::Mutex;
use std::sync::Arc;
use module_bitcoin::types::*;
use module_bitcoin::formatter::Formattable;
use hex;

const POLKA_BTC_URL: &str = "ws://127.0.0.1:9944";
const ALICE_BTC_ADDRESS: &str = "66c7060feb882664ae62ffad0051fe843e318e85";

/// Generates testdata to be used on a development environment of the BTC-Parachain
#[tokio::main]
async fn main() -> Result<(), Error> {
    // setup BTC Parachain connection
    let alice = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Alice.pair());
    let bob = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Bob.pair());
    let alice_prov = PolkaBtcProvider::from_url(POLKA_BTC_URL.to_string(), Arc::new(Mutex::new(alice))).await?;
    let bob_prov = PolkaBtcProvider::from_url(POLKA_BTC_URL.to_string(), Arc::new(Mutex::new(bob))).await?;

    // EXCHANGE RATE
    let oracle_prov = bob_prov.clone();

    // set exchange rate to 0.00038 at granularity 5
    let btc_to_dot_rate: u128 = 38;
    oracle_prov.set_exchange_rate_info(btc_to_dot_rate).await?;

    // get exchange rate
    let (rate, _time, _delay) = oracle_prov.get_exchange_rate_info().await?;
    println!("Exchange Rate BTC/DOT {:?}", rate);

    // BTC RELAY
    let relay_prov = alice_prov.clone();
    
    let dest_address = H160::from_slice(
        hex::decode(ALICE_BTC_ADDRESS)
                .unwrap()
                .as_slice(),
        ); 
    let address = Address::from(*dest_address.as_fixed_bytes()); 
    let mut height: u32 = 1;
    // initialize BTC Relay with one block
    let init_block = BlockBuilder::new()
        .with_version(2)
        .with_coinbase(&address, 50, 3)
        .with_timestamp(1588813835)
        .mine(U256::from(2).pow(254.into()));

    let init_block_hash = init_block.header.hash();
    let raw_init_block_header = RawBlockHeader::from_bytes(&init_block.header.format())
        .expect("could not serialize block header");

    relay_prov.initialize_btc_relay(raw_init_block_header, height).await?;

    Ok(())
}
