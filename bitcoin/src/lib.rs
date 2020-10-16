mod error;
pub use error::{ConversionError, Error};

use async_trait::async_trait;
use std::time::Duration;
use tokio::time::delay_for;

pub use bitcoincore_rpc::{
    bitcoin::{
        blockdata::opcodes::all as opcodes,
        blockdata::script::Builder,
        consensus::encode::serialize,
        hash_types::BlockHash,
        hashes::{hex::ToHex, Hash},
        util::{address::Payload, psbt::serialize::Serialize},
        Address, Amount, Network, Transaction, TxOut, Txid,
    },
    bitcoincore_rpc_json::GetRawTransactionResult,
    json,
    jsonrpc::Error as JsonRpcError,
    Auth, Client, Error as BitcoinError, RpcApi,
};
use sp_core::H160;
use std::collections::HashMap;
use std::env::var;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{convert::TryInto, str::FromStr};

pub fn read_env(s: &str) -> Result<String, Error> {
    var(s).map_err(|e| Error::ReadVar(s.to_string(), e))
}

pub fn bitcoin_rpc_from_env() -> Result<Client, Error> {
    let url = read_env("BITCOIN_RPC_URL")?;
    let user = read_env("BITCOIN_RPC_USER")?;
    let pass = read_env("BITCOIN_RPC_PASS")?;
    Ok(Client::new(url, Auth::UserPass(user, pass))?)
}

#[async_trait]
pub trait BitcoinCoreApi {
    async fn wait_for_block(&self, height: u32, delay: Duration) -> Result<BlockHash, Error>;

    fn get_block_transactions(
        &self,
        hash: &BlockHash,
    ) -> Result<Vec<Option<GetRawTransactionResult>>, Error>;

    fn get_raw_tx_for(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, Error>;

    fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error>;

    async fn send_to_address(
        &self,
        address: String,
        sat: u64,
        redeem_id: &[u8; 32],
    ) -> Result<Txid, Error>;
}

pub struct BitcoinCore {
    rpc: Client,
}

impl BitcoinCore {
    pub fn new(rpc: Client) -> Self {
        Self { rpc }
    }
}

#[async_trait]
impl BitcoinCoreApi for BitcoinCore {
    /// Wait for a specified height to return a `BlockHash` or
    /// exit on error.
    ///
    /// # Arguments
    /// * `height` - block height to fetch
    /// * `delay` - wait period before re-checking
    async fn wait_for_block(&self, height: u32, delay: Duration) -> Result<BlockHash, Error> {
        loop {
            match self.rpc.get_block_hash(height.into()) {
                Ok(hash) => return Ok(hash),
                Err(e) => {
                    delay_for(delay).await;
                    if let BitcoinError::JsonRpc(JsonRpcError::Rpc(rpc_error)) = &e {
                        // https://github.com/bitcoin/bitcoin/blob/be3af4f31089726267ce2dbdd6c9c153bb5aeae1/src/rpc/protocol.h#L43
                        if rpc_error.code == -8 {
                            continue;
                        }
                    }
                    return Err(e.into());
                }
            }
        }
    }

    /// Get all transactions in a block identified by the
    /// given hash.
    ///
    /// # Arguments
    /// * `hash` - block hash to query
    fn get_block_transactions(
        &self,
        hash: &BlockHash,
    ) -> Result<Vec<Option<GetRawTransactionResult>>, Error> {
        let info = self.rpc.get_block_info(hash)?;
        let txs = info
            .tx
            .iter()
            .map(
                |id| match self.rpc.get_raw_transaction_info(&id, Some(hash)) {
                    Ok(tx) => Some(tx),
                    // TODO: log error
                    Err(_) => None,
                },
            )
            .collect::<Vec<Option<GetRawTransactionResult>>>();
        Ok(txs)
    }

    /// Get the raw transaction identified by `Txid` and stored
    /// in the specified block.
    ///
    /// # Arguments
    /// * `txid` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    fn get_raw_tx_for(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(serialize(
            &self.rpc.get_raw_transaction(txid, Some(block_hash))?,
        ))
    }

    /// Get the merkle proof which can be used to validate transaction inclusion.
    ///
    /// # Arguments
    /// * `txid` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(self.rpc.get_tx_out_proof(&[txid], Some(block_hash))?)
    }

    /// Get the block hash for a given height.
    ///
    /// # Arguments
    /// * `height` - block height
    fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, Error> {
        Ok(self.rpc.get_block_hash(height.into())?)
    }

    /// Checks if the local full node has seen the specified block hash.
    ///
    /// # Arguments
    /// * `block_hash` - hash of the block to verify
    fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error> {
        // TODO: match exact error
        Ok(match self.rpc.get_block(&block_hash) {
            Ok(_) => true,
            Err(_) => false,
        })
    }

    /// Send an amount of Bitcoin to an address.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to fund
    /// * `sat` - number of Satoshis to transfer
    /// * `redeem_id` - the redeemid for which this transfer is being made
    async fn send_to_address(
        &self,
        address: String,
        sat: u64,
        redeem_id: &[u8; 32],
    ) -> Result<Txid, Error> {
        let mut recipients = HashMap::<String, Amount>::new();
        recipients.insert(address.clone(), Amount::from_sat(sat));

        let raw_tx = self
            .rpc
            .create_raw_transaction_hex(&[], &recipients, None, None)?;

        let funding_opts = json::FundRawTransactionOptions {
            fee_rate: Some(Amount::from_sat(10000)),
            ..Default::default()
        };

        let raw_tx = self
            .rpc
            .fund_raw_transaction(raw_tx, Some(&funding_opts), None)?;

        let mut tx = raw_tx.transaction().unwrap();

        fix_transaction_output_order(&mut tx, address)?;

        // include the redeem is in the transaction
        add_redeem_id(&mut tx, redeem_id);

        let signed_raw_tx =
            self.rpc
                .sign_raw_transaction_with_wallet(tx.serialize().to_hex(), None, None)?;

        let txid = self
            .rpc
            .send_raw_transaction(signed_raw_tx.transaction().unwrap().serialize().to_hex())?;

        TxMonitor {
            rpc: &self.rpc,
            txid,
        }
        .await
    }
}

pub struct TxMonitor<'a> {
    rpc: &'a Client,
    txid: Txid,
}

impl<'a> Future for TxMonitor<'a> {
    type Output = Result<Txid, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.rpc.get_transaction(&self.txid, None) {
            Ok(res) => {
                if res.info.confirmations > 0 {
                    Poll::Ready(Ok(self.txid))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Err(err) => Poll::Ready(Err(err.into())),
        }
    }
}

/// Ensures we follow the spec: the payment to the recipient needs to be the
/// first uxto. Funding the transaction sometimes places the return-to-self
/// uxto first, so this function performs a swap of uxtos if necessary
fn fix_transaction_output_order(
    tx: &mut Transaction,
    recipient_address: String,
) -> Result<(), Error> {
    let address_hash = get_hash_from_string(recipient_address.as_str())?;
    let recipient_raw = address_hash.as_bytes();
    let output0_addr = &tx.output[0].script_pubkey.as_bytes()[2..];

    if recipient_raw != output0_addr {
        // most likely the return-to-self output was put first
        if tx.output.len() > 1 && recipient_raw == &tx.output[1].script_pubkey.as_bytes()[2..] {
            tx.output.swap(0, 1);
        } else {
            // if this executes we have a bug in the code
            panic!("Could not find recipient address in bitcoin transaction");
        }
    }
    Ok(())
}

/// Adds op_return with the given id at index 1, occording to the redeem spec
fn add_redeem_id(tx: &mut Transaction, redeem_id: &[u8; 32]) {
    // Index 1: Data UTXO: OP_RETURN containing identifier
    tx.output.insert(
        1,
        TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::OP_RETURN)
                .push_slice(redeem_id)
                .into_script(),
        },
    );
}

pub fn get_hash_from_string(btc_address: &str) -> Result<H160, ConversionError> {
    let addr = Address::from_str(btc_address)?;
    let hash = match addr.payload {
        Payload::PubkeyHash(hash) => hash.as_hash().into_inner(),
        Payload::ScriptHash(hash) => hash.as_hash().into_inner(),
        Payload::WitnessProgram {
            version: _,
            program,
        } => program
            .try_into()
            .map_err(|_| ConversionError::WitnessProgramError)?,
    };
    Ok(H160::from(hash))
}

pub fn get_address_from_hex(btc_address: &str) -> Result<H160, ConversionError> {
    let decoded = hex::decode(btc_address)?;
    Ok(H160::from_slice(decoded.as_slice()))
}

pub fn hash_to_p2wpkh(btc_address: H160, network: Network) -> Result<String, ConversionError> {
    let witness_script = Builder::new()
        .push_opcode(0.into())
        .push_slice(btc_address.as_bytes())
        .into_script();

    let payload =
        Payload::from_script(&witness_script).ok_or(ConversionError::WitnessProgramError)?;
    let address = Address { network, payload };

    Ok(address.to_string())
}

fn bytes_to_h160<B: AsRef<[u8]>>(bytes: B) -> H160 {
    let slice = bytes.as_ref();
    let mut result = [0u8; 20];
    result.copy_from_slice(slice);
    result.into()
}

pub fn is_p2sh2wpkh(data: Vec<u8>) -> bool {
    data.len() == 23 && data[0] == opcodes::OP_PUSHBYTES_22.into_u8()
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

    use bitcoincore_rpc::{
        bitcoin::{Txid, Wtxid},
        bitcoincore_rpc_json::{GetRawTransactionResultVin, GetRawTransactionResultVinScriptSig},
    };

    #[test]
    fn test_hash_to_p2wpkh() {
        let addr = "bcrt1q6v2c7q7uv8vu6xle2k9ryfj3y3fuuy4rqnl50f";
        let addr_hash = get_hash_from_string(addr).unwrap();
        let rebuilt_addr = hash_to_p2wpkh(addr_hash, Network::Regtest).unwrap();
        assert_eq!(addr, rebuilt_addr);
    }

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
