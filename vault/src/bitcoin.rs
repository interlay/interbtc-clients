use crate::Error;
pub use bitcoincore_rpc::{
    bitcoin::{
        blockdata::opcodes::all as opcodes,
        blockdata::script::Builder,
        hashes::hex::ToHex,
        util::{address::Payload, psbt::serialize::Serialize},
        Address, Amount, Transaction, TxOut, Txid,
    },
    Auth, Client, Error as BitcoinError, RpcApi,
};
use std::collections::HashMap;
use std::env::var;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

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

    /// Fetch the total unspent balance for a Bitcoin address.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address
    pub fn get_account_balance(&self, address: &Address) -> Result<u64, Error> {
        let amount = self.rpc.get_received_by_address(address, Some(0))?;
        return Ok(amount.as_sat());
    }

    /// Send an amount of Bitcoin to an address.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to fund
    /// * `sat` - number of Satoshis to transfer
    pub async fn send_to_address(&self, address: String, sat: u64) -> Result<Txid, Error> {
        let mut recipients = HashMap::<String, Amount>::new();
        recipients.insert(address, Amount::from_sat(sat));

        let raw_tx = self
            .rpc
            .create_raw_transaction_hex(&[], &recipients, None, None)?;
        let raw_tx = self.rpc.fund_raw_transaction(raw_tx, None, None)?;

        let mut tx = raw_tx.transaction().unwrap();

        // TODO: json decode fails because no address, fix upstream?
        add_op_return(&mut tx);

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
                    return Poll::Pending;
                }
            }
            Err(err) => return Poll::Ready(Err(err.into())),
        }
    }
}

#[allow(dead_code)]
fn add_op_return(tx: &mut Transaction) {
    tx.output.push(TxOut {
        value: 0,
        script_pubkey: Builder::new()
            .push_opcode(opcodes::OP_RETURN)
            .push_slice(&[0; 32])
            .into_script(),
    });
}

pub fn extract_witness_program(addr: &str) -> Option<String> {
    let address = Address::from_str(addr).unwrap();
    if let Payload::WitnessProgram {
        version: _,
        program,
    } = address.payload
    {
        return Some(hex::encode(program));
    }
    None
}
