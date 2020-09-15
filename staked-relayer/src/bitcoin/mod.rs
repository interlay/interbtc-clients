mod block;

pub use block::BitcoinMonitor;

use bitcoincore_rpc::bitcoin::blockdata::opcodes;
use bitcoincore_rpc::bitcoincore_rpc_json::GetRawTransactionResult;
use sp_core::H160;

fn bytes_to_h160<B: AsRef<[u8]>>(bytes: B) -> H160 {
    let slice = bytes.as_ref();
    let mut result = [0u8; 20];
    result.copy_from_slice(slice);
    result.into()
}

pub fn is_p2sh2wpkh(data: Vec<u8>) -> bool {
    data.len() == 23 && data[0] == opcodes::all::OP_PUSHBYTES_22.into_u8()
}

pub fn extract_btc_addresses(tx: GetRawTransactionResult) -> Vec<H160> {
    tx.vin
        .into_iter()
        .filter_map(|vin| {
            if let Some(script_sig) = &vin.script_sig {
                // this always returns ok so should be safe to unwrap
                let script = script_sig.script().unwrap();
                let bytes = script.to_bytes();
                if script.is_p2sh() {
                    return Some(bytes_to_h160(bytes[2..22].to_vec()));
                } else if script.is_p2pkh() {
                    return Some(bytes_to_h160(bytes[3..23].to_vec()));
                } else if script.is_v0_p2wpkh() {
                    return Some(bytes_to_h160(bytes[2..22].to_vec()));
                } else if is_p2sh2wpkh(bytes.to_vec()) {
                    return Some(bytes_to_h160(bytes[3..23].to_vec()));
                }
            }
            None
        })
        .collect::<Vec<H160>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoincore_rpc::bitcoin::{Txid, Wtxid};
    use bitcoincore_rpc::bitcoincore_rpc_json::{
        GetRawTransactionResultVin, GetRawTransactionResultVinScriptSig,
    };

    #[test]
    fn test_tx_has_inputs() {
        let mut addr = H160::zero();
        addr.assign_from_slice(&hex::decode("4ef45ff516f84c62b09ad4f605f92abc103f916b").unwrap());

        assert_eq!(
            extract_btc_addresses(GetRawTransactionResult {
                in_active_chain: None,
                hex: vec![],
                txid: Txid::default(),
                hash: Wtxid::default(),
                size: 0,
                vsize: 0,
                version: 0,
                locktime: 0,
                vin: vec![GetRawTransactionResultVin {
                    sequence: 0,
                    coinbase: None,
                    txid: None,
                    vout: None,
                    script_sig: Some(GetRawTransactionResultVinScriptSig {
                        asm: "".to_string(),
                        hex: vec![
                            169, 20, 78, 244, 95, 245, 22, 248, 76, 98, 176, 154, 212, 246, 5, 249,
                            42, 188, 16, 63, 145, 107, 135
                        ],
                    }),
                    txinwitness: None,
                }],
                vout: vec![],
                blockhash: None,
                confirmations: None,
                time: None,
                blocktime: None,
            }),
            vec![addr]
        );
    }
}
