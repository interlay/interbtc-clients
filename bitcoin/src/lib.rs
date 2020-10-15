mod error;
pub use error::{ConversionError, Error};

pub use bitcoincore_rpc::{
    bitcoin::{
        blockdata::opcodes::all as opcodes,
        blockdata::script::Builder,
        hashes::{hex::ToHex, Hash},
        util::{address::Payload, psbt::serialize::Serialize},
        Address, Amount, Network, Transaction, TxOut, Txid,
    },
    json, Auth, Client, Error as BitcoinError, RpcApi,
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

pub struct BitcoinCore {
    rpc: Client,
}

impl BitcoinCore {
    pub fn new(rpc: Client) -> Self {
        Self { rpc }
    }

    /// Send an amount of Bitcoin to an address.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to fund
    /// * `sat` - number of Satoshis to transfer
    /// * `redeem_id` - the redeemid for which this transfer is being made
    pub async fn send_to_address(
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

    pub fn get_proof_for(&self, txid: Txid) -> Result<Vec<u8>, Error> {
        let proof = self.rpc.get_tx_out_proof(&[txid], None)?;
        Ok(proof)
    }

    pub fn get_raw_tx_for(&self, txid: Txid) -> Result<Vec<u8>, Error> {
        let raw_tx = self.rpc.get_transaction(&txid, None)?;
        Ok(raw_tx.transaction().unwrap().serialize())
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
fn fix_transaction_output_order(tx: &mut Transaction, recipient_address: String) -> Result<(), Error>{
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hash_to_p2wpkh() {
        let addr = "bcrt1q6v2c7q7uv8vu6xle2k9ryfj3y3fuuy4rqnl50f";
        let addr_hash = get_hash_from_string(addr);
        let rebuilt_addr = hash_to_p2wpkh(addr_hash, Network::Regtest);
        assert_eq!(addr, rebuilt_addr);
    }
}
