#![allow(dead_code)]
use sp_core::H160;

pub fn get_address_from_string(btc_address: &str) -> H160 {
    H160::from_slice(hex::decode(btc_address).unwrap().as_slice())
}
