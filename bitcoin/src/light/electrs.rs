use super::error::Error;
use crate::{
    deserialize, opcodes, serialize, Address, Block, BlockHash, BlockHeader, Builder as ScriptBuilder, FromHex,
    Network, OutPoint, Script, SignedAmount, ToHex, Transaction, Txid, H256,
};
use reqwest::{Client, Url};
use sha2::{Digest, Sha256};
use std::str::FromStr;

// https://github.com/Blockstream/esplora/blob/master/API.md
const ELECTRS_TESTNET_URL: &str = "https://btc-testnet.interlay.io";
const ELECTRS_MAINNET_URL: &str = "https://btc-mainnet.interlay.io";
const ELECTRS_LOCALHOST_URL: &str = "http://localhost:3002";

pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: u64,
}

#[allow(dead_code)]
pub struct TxData {
    pub txid: Txid,
    pub raw_merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
}

#[derive(Debug)]
pub struct TxInfo {
    pub confirmations: u32,
    pub height: u32,
    pub hash: BlockHash,
    pub fee: SignedAmount,
}

mod electrs_types {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Block {
        pub height: u32,
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct TxStatus {
        pub confirmed: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub block_height: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub block_hash: Option<String>,
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Transaction {
        #[serde(rename = "txid")]
        pub txid: String,
        #[serde(rename = "fee")]
        pub fee: i64,
        #[serde(rename = "vout", skip_serializing_if = "Option::is_none")]
        pub vout: Option<Vec<VOut>>,
        #[serde(rename = "status")]
        pub status: TxStatus,
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct VOut {
        #[serde(rename = "scriptpubkey", skip_serializing_if = "Option::is_none")]
        pub scriptpubkey: Option<String>,
        #[serde(rename = "value", skip_serializing_if = "Option::is_none")]
        pub value: Option<f32>,
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Utxo {
        #[serde(rename = "txid")]
        pub txid: String,
        #[serde(rename = "vout")]
        pub vout: u32,
        #[serde(rename = "value")]
        pub value: u64,
    }
}

#[derive(Clone)]
pub struct ElectrsClient {
    url: Url,
    cli: Client,
}

impl ElectrsClient {
    pub fn new(electrs_url: Option<String>, network: Network) -> Self {
        Self {
            url: electrs_url
                .unwrap_or_else(|| {
                    match network {
                        Network::Bitcoin => ELECTRS_MAINNET_URL,
                        Network::Testnet => ELECTRS_TESTNET_URL,
                        _ => ELECTRS_LOCALHOST_URL,
                    }
                    .to_owned()
                })
                .parse()
                .unwrap(),
            cli: Client::new(),
        }
    }

    async fn get(&self, url: Url) -> Result<String, Error> {
        Ok(self.cli.get(url).send().await?.error_for_status()?.text().await?)
    }

    async fn get_and_decode<T: serde::de::DeserializeOwned>(&self, url: Url) -> Result<T, Error> {
        let body = self.get(url).await?;
        Ok(serde_json::from_str(&body)?)
    }

    pub(crate) async fn get_blocks_tip_height(&self) -> Result<u32, Error> {
        let url = self.url.join("/blocks/tip/height")?;
        Ok(self.get(url).await?.parse()?)
    }

    pub(crate) async fn get_blocks_tip_hash(&self) -> Result<BlockHash, Error> {
        let url = self.url.join("/blocks/tip/hash")?;
        let response = self.get(url).await?;
        Ok(BlockHash::from_str(&response)?)
    }

    pub(crate) async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, Error> {
        let url = self.url.join(&format!("/block/{hash}/header"))?;
        let raw_block_header = Vec::<u8>::from_hex(&self.get(url).await?)?;
        Ok(deserialize(&raw_block_header)?)
    }

    pub(crate) async fn get_transactions_in_block(&self, hash: &BlockHash) -> Result<Vec<Transaction>, Error> {
        let url = self.url.join(&format!("/block/{hash}/txids"))?;
        let raw_txids: Vec<String> = self.get_and_decode(url).await?;
        let txids: Vec<Txid> = raw_txids
            .iter()
            .map(|txid| Txid::from_str(txid))
            .collect::<Result<Vec<_>, _>>()?;
        let txs = futures::future::join_all(txids.iter().map(|txid| self.get_raw_tx(txid)))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|raw_tx| deserialize(&raw_tx))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(txs)
    }

    pub(crate) async fn get_block(&self, hash: &BlockHash) -> Result<Block, Error> {
        let header = self.get_block_header(hash).await?;
        let txdata = self.get_transactions_in_block(hash).await?;
        Ok(Block { header, txdata })
    }

    pub(crate) async fn get_block_hash(&self, height: u32) -> Result<BlockHash, Error> {
        let url = self.url.join(&format!("/block-height/{height}"))?;
        let response = self.get(url).await?;
        Ok(BlockHash::from_str(&response)?)
    }

    pub(crate) async fn get_raw_mempool(&self) -> Result<Vec<Txid>, Error> {
        let url = self.url.join("/mempool/txids")?;
        let txs: Vec<String> = self.get_and_decode(url).await?;
        Ok(txs
            .iter()
            .map(|txid| Txid::from_str(txid))
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub(crate) async fn get_raw_merkle_proof(&self, txid: &Txid) -> Result<Vec<u8>, Error> {
        let url = self.url.join(&format!("/tx/{txid}/merkleblock-proof"))?;
        Ok(Vec::<u8>::from_hex(&self.get(url).await?)?)
    }

    pub(crate) async fn get_raw_tx(&self, txid: &Txid) -> Result<Vec<u8>, Error> {
        let url = self.url.join(&format!("/tx/{txid}/hex"))?;
        Ok(Vec::<u8>::from_hex(&self.get(url).await?)?)
    }

    pub(crate) async fn get_tx_info(&self, txid: &Txid) -> Result<TxInfo, Error> {
        let url = self.url.join(&format!("/tx/{txid}"))?;
        let tx: electrs_types::Transaction = self.get_and_decode(url).await?;
        let tip = self.get_blocks_tip_height().await?;
        let (height, hash) = match (tx.status.block_height, tx.status.block_hash) {
            (Some(height), Some(hash)) => (height, hash),
            _ => return Err(Error::InvalidAddress),
        };
        Ok(TxInfo {
            confirmations: tip.saturating_sub(height),
            height,
            hash: BlockHash::from_str(&hash)?,
            fee: SignedAmount::from_sat(tx.fee),
        })
    }

    pub(crate) async fn get_utxos_for_address(&self, address: Address) -> Result<Vec<Utxo>, Error> {
        let url = self.url.join(&format!("/address/{address}/utxo"))?;
        let utxos: Vec<electrs_types::Utxo> = self.get_and_decode(url).await?;

        utxos
            .into_iter()
            .map(|utxo| {
                Ok(Utxo {
                    outpoint: OutPoint {
                        txid: Txid::from_hex(&utxo.txid)?,
                        vout: utxo.vout,
                    },
                    value: utxo.value,
                })
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    pub(crate) async fn get_script_pubkey(&self, outpoint: OutPoint) -> Result<Script, Error> {
        let url = self.url.join(&format!("/tx/{txid}", txid = outpoint.txid))?;

        let tx: electrs_types::Transaction = self.get_and_decode(url).await?;
        Ok(Script::from_str(
            &tx.vout
                .ok_or(Error::NoPrevOut)?
                .get(outpoint.vout as usize)
                .ok_or(Error::NoPrevOut)?
                .clone()
                .scriptpubkey
                .ok_or(Error::NoPrevOut)?,
        )?)
    }

    pub(crate) async fn send_transaction(&self, tx: Transaction) -> Result<Txid, Error> {
        let url = self.url.join("/tx")?;
        let txid = self
            .cli
            .post(url)
            .body(serialize(&tx).to_hex())
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        Ok(Txid::from_str(&txid)?)
    }

    #[allow(dead_code)]
    pub(crate) async fn get_tx_by_op_return(&self, data: H256) -> Result<Option<TxData>, Error> {
        let script = ScriptBuilder::new()
            .push_opcode(opcodes::OP_RETURN)
            .push_slice(data.as_bytes())
            .into_script();

        let script_hash = {
            let mut hasher = Sha256::default();
            hasher.input(script.as_bytes());
            hasher.result().as_slice().to_vec()
        };

        let url = self.url.join(&format!(
            "/scripthash/{scripthash}/txs",
            scripthash = script_hash.to_hex()
        ))?;

        let txs: Vec<electrs_types::Transaction> = self.get_and_decode(url).await?;
        log::info!("Found {} transactions", txs.len());

        // for now, use the first tx - should probably return
        // an error if there are more that one
        if let Some(tx) = txs.first().cloned() {
            let txid = Txid::from_str(&tx.txid)?;
            log::info!("Fetching merkle proof");
            // TODO: return error if not confirmed
            let raw_merkle_proof = self.get_raw_merkle_proof(&txid).await?;

            log::info!("Fetching transaction");
            let raw_tx = self.get_raw_tx(&txid).await?;

            Ok(Some(TxData {
                txid,
                raw_merkle_proof,
                raw_tx,
            }))
        } else {
            Ok(None)
        }
    }
}
