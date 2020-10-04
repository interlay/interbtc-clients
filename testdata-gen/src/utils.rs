#![allow(dead_code)]
use sp_core::H160;
use std::str::FromStr;

pub fn get_address_from_string(btc_address: &str) -> H160 {
    H160::from_str(btc_address).unwrap()
}

pub fn get_address_from_hex(btc_address: &str) -> H160 {
    H160::from_slice(hex::decode(btc_address).unwrap().as_slice())
}