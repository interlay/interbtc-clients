#![allow(dead_code)]
use sp_core::H160;
use relayer_core::bitcoin::bitcoincore_rpc::bitcoin::{hashes::Hash, util::address::{ Payload, Address }};
use std::str::FromStr;


pub fn get_address_from_string(btc_address: &str) -> H160 {
    let addr = Address::from_str(btc_address).unwrap();
    let hash = match addr.payload {
        Payload::PubkeyHash(hash) => hash.as_hash().into_inner(),
        Payload::ScriptHash(hash) => hash.as_hash().into_inner(),
        Payload::WitnessProgram { version, program } => {} 
    };
    H160::from_slice(hash)
}

pub fn get_address_from_hex(btc_address: &str) -> H160 {
    H160::from_slice(hex::decode(btc_address).unwrap().as_slice())
}