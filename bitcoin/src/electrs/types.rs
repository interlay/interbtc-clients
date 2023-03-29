use crate::{BlockHash, Script, Txid};
use serde::Deserialize;

// https://github.com/Blockstream/electrs/blob/adedee15f1fe460398a7045b292604df2161adc0/src/util/transaction.rs#L17-L26
#[derive(Deserialize)]
pub struct TransactionStatus {
    pub confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<BlockHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_time: Option<u32>,
}

// https://github.com/Blockstream/electrs/blob/adedee15f1fe460398a7045b292604df2161adc0/src/rest.rs#L167-L189
#[derive(Deserialize)]
pub struct TxInValue {
    pub txid: Txid,
    pub vout: u32,
    pub prevout: Option<TxOutValue>,
    pub scriptsig: Script,
    pub scriptsig_asm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Vec<String>>,
    pub is_coinbase: bool,
    pub sequence: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_redeemscript_asm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_witnessscript_asm: Option<String>,
}

// https://github.com/Blockstream/electrs/blob/adedee15f1fe460398a7045b292604df2161adc0/src/rest.rs#L239-L270
#[derive(Deserialize)]
pub struct TxOutValue {
    pub scriptpubkey: Script,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

// https://github.com/Blockstream/electrs/blob/adedee15f1fe460398a7045b292604df2161adc0/src/rest.rs#L115-L127
#[derive(Deserialize)]
pub struct TransactionValue {
    pub txid: Txid,
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<TxInValue>,
    pub vout: Vec<TxOutValue>,
    pub size: u32,
    pub weight: u32,
    pub fee: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<TransactionStatus>,
}

// https://github.com/Blockstream/electrs/blob/adedee15f1fe460398a7045b292604df2161adc0/src/rest.rs#L356-L396
#[derive(Deserialize)]
pub struct UtxoValue {
    pub txid: Txid,
    pub vout: u32,
    pub status: TransactionStatus,
    pub value: u64,
}
