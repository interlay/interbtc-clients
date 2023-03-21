mod error;

pub use error::Error;

use crate::{
    deserialize, opcodes, serialize, Address, Block, BlockHash, BlockHeader, Builder as ScriptBuilder, FromHex,
    Network, OutPoint, Script, SignedAmount, ToHex, Transaction, Txid, H256,
};
use esplora_btc_api::models::{Transaction as ElectrsTransaction, Utxo as ElectrsUtxo};
use futures::future::{join_all, try_join};
use reqwest::{Client, Url};
use sha2::{Digest, Sha256};
use std::str::FromStr;

const ELECTRS_TRANSACTIONS_PER_PAGE: usize = 25;

// https://github.com/Blockstream/esplora/blob/master/API.md
const ELECTRS_TESTNET_URL: &str = "https://btc-testnet.interlay.io";
const ELECTRS_MAINNET_URL: &str = "https://btc-mainnet.interlay.io";
const ELECTRS_LOCALHOST_URL: &str = "http://localhost:3002";

pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: u64,
}

#[derive(Debug)]
pub struct TxInfo {
    pub confirmations: u32,
    pub height: u32,
    pub hash: BlockHash,
    pub fee: SignedAmount,
}

// NOTE: the `esplora_btc_api` OpenAPI lib build cannot decode plain strings
// (using `serde_json::from_str`) and it doesn't support paged api calls
#[derive(Clone)]
pub struct ElectrsClient {
    url: Url,
    cli: Client,
}

impl ElectrsClient {
    pub fn new(electrs_url: Option<String>, network: Network) -> Result<Self, Error> {
        Ok(Self {
            url: electrs_url
                .unwrap_or_else(|| {
                    match network {
                        Network::Bitcoin => ELECTRS_MAINNET_URL,
                        Network::Testnet => ELECTRS_TESTNET_URL,
                        _ => ELECTRS_LOCALHOST_URL,
                    }
                    .to_owned()
                })
                .parse()?,
            cli: Client::new(),
        })
    }

    async fn get(&self, path: &str) -> Result<String, Error> {
        let url = self.url.join(path)?;
        Ok(self.cli.get(url).send().await?.error_for_status()?.text().await?)
    }

    // only use this for parsing valid json, it will fail on strings
    async fn get_and_decode<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let body = self.get(path).await?;
        Ok(serde_json::from_str(&body)?)
    }

    pub(crate) async fn get_tx_hex(&self, txid: &str) -> Result<String, Error> {
        self.get(&format!("/tx/{txid}/hex")).await
    }

    pub(crate) async fn get_tx_merkle_block_proof(&self, txid: &str) -> Result<String, Error> {
        self.get(&format!("/tx/{txid}/merkleblock-proof")).await
    }

    pub(crate) async fn get_raw_tx(&self, txid: &Txid) -> Result<Vec<u8>, Error> {
        Ok(Vec::<u8>::from_hex(&self.get_tx_hex(&txid.to_string()).await?)?)
    }

    pub(crate) async fn get_raw_tx_merkle_proof(&self, txid: &Txid) -> Result<Vec<u8>, Error> {
        Ok(Vec::<u8>::from_hex(
            &self.get_tx_merkle_block_proof(&txid.to_string()).await?,
        )?)
    }

    pub(crate) async fn get_address_tx_history_full(&self, address: &str) -> Result<Vec<ElectrsTransaction>, Error> {
        let mut last_seen_txid = Default::default();
        let mut ret = Vec::<ElectrsTransaction>::new();
        loop {
            let mut transactions: Vec<ElectrsTransaction> = self
                .get_and_decode(&format!("/address/{address}/txs/chain/{last_seen_txid}"))
                .await?;
            let page_size = transactions.len();
            last_seen_txid = transactions.last().map_or(Default::default(), |tx| tx.txid.clone());
            ret.append(&mut transactions);
            if page_size < ELECTRS_TRANSACTIONS_PER_PAGE {
                // no further pages
                break;
            }
        }
        Ok(ret)
    }

    pub(crate) async fn get_blocks_tip_height(&self) -> Result<u32, Error> {
        Ok(self.get("/blocks/tip/height").await?.parse()?)
    }

    pub(crate) async fn get_blocks_tip_hash(&self) -> Result<BlockHash, Error> {
        let response = self.get("/blocks/tip/hash").await?;
        Ok(BlockHash::from_str(&response)?)
    }

    pub(crate) async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, Error> {
        let raw_block_header = Vec::<u8>::from_hex(&self.get(&format!("/block/{hash}/header")).await?)?;
        Ok(deserialize(&raw_block_header)?)
    }

    // TODO: this is expensive and not strictly required by the light-client, deprecate?
    pub(crate) async fn get_transactions_in_block(&self, hash: &BlockHash) -> Result<Vec<Transaction>, Error> {
        let raw_txids: Vec<String> = self.get_and_decode(&format!("/block/{hash}/txids")).await?;
        let txids: Vec<Txid> = raw_txids
            .iter()
            .map(|txid| Txid::from_str(txid))
            .collect::<Result<Vec<_>, _>>()?;
        let txs = join_all(txids.iter().map(|txid| self.get_raw_tx(txid)))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|raw_tx| deserialize(&raw_tx))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(txs)
    }

    pub(crate) async fn get_block(&self, hash: &BlockHash) -> Result<Block, Error> {
        let (header, txdata) = try_join(self.get_block_header(hash), self.get_transactions_in_block(hash)).await?;
        Ok(Block { header, txdata })
    }

    pub(crate) async fn get_block_hash(&self, height: u32) -> Result<BlockHash, Error> {
        let response = self.get(&format!("/block-height/{height}")).await?;
        Ok(BlockHash::from_str(&response)?)
    }

    pub(crate) async fn get_raw_mempool(&self) -> Result<Vec<Txid>, Error> {
        let txs: Vec<String> = self.get_and_decode("/mempool/txids").await?;
        Ok(txs
            .iter()
            .map(|txid| Txid::from_str(txid))
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub(crate) async fn get_tx_info(&self, txid: &Txid) -> Result<TxInfo, Error> {
        let tx: ElectrsTransaction = self.get_and_decode(&format!("/tx/{txid}")).await?;
        let tip = self.get_blocks_tip_height().await?;
        let (height, hash) = match tx.status.map(|status| (status.block_height, status.block_hash)) {
            Some((Some(height), Some(hash))) => (height as u32, hash),
            _ => return Err(Error::InvalidAddress),
        };
        Ok(TxInfo {
            confirmations: tip.saturating_sub(height),
            height,
            hash: BlockHash::from_str(&hash)?,
            fee: SignedAmount::from_sat(tx.fee.unwrap_or_default() as i64),
        })
    }

    pub(crate) async fn get_utxos_for_address(&self, address: Address) -> Result<Vec<Utxo>, Error> {
        let utxos: Vec<ElectrsUtxo> = self.get_and_decode(&format!("/address/{address}/utxo")).await?;

        utxos
            .into_iter()
            .map(|utxo| {
                Ok(Utxo {
                    outpoint: OutPoint {
                        txid: Txid::from_hex(&utxo.txid)?,
                        vout: utxo.vout as u32,
                    },
                    value: utxo.value as u64,
                })
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    pub(crate) async fn get_script_pubkey(&self, outpoint: OutPoint) -> Result<Script, Error> {
        let tx: ElectrsTransaction = self
            .get_and_decode(&format!("/tx/{txid}", txid = outpoint.txid))
            .await?;
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

    pub(crate) async fn get_tx_for_op_return(&self, data: H256) -> Result<Option<Txid>, Error> {
        let script = ScriptBuilder::new()
            .push_opcode(opcodes::OP_RETURN)
            .push_slice(data.as_bytes())
            .into_script();

        let script_hash = {
            let mut hasher = Sha256::default();
            hasher.input(script.as_bytes());
            hasher.result().as_slice().to_vec()
        };

        // TODO: page this using last_seen_txid
        // NOTE: includes unconfirmed txs
        let txs: Vec<ElectrsTransaction> = self
            .get_and_decode(&format!(
                "/scripthash/{scripthash}/txs",
                scripthash = script_hash.to_hex()
            ))
            .await?;
        log::info!("Found {} transactions", txs.len());

        // TODO: check payment amount or throw error
        // if there are multiple transactions
        if let Some(tx) = txs.first().cloned() {
            let txid = Txid::from_str(&tx.txid)?;
            Ok(Some(txid))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoincore_rpc::bitcoin::hashes::{hex::FromHex, sha256::Hash as Sha256Hash, Hash};
    use esplora_btc_api::apis::configuration::Configuration as ElectrsConfiguration;

    // TODO: mock the electrs endpoint
    async fn test_electrs(url: &str, script_hex: &str, expected_txid: &str) {
        let config = ElectrsConfiguration {
            base_path: url.to_owned(),
            ..Default::default()
        };

        let script_bytes = Vec::from_hex(script_hex).unwrap();
        let script_hash = Sha256Hash::hash(&script_bytes);

        let txs = esplora_btc_api::apis::scripthash_api::get_txs_by_scripthash(&config, &hex::encode(script_hash))
            .await
            .unwrap();
        assert!(txs.iter().any(|tx| { &tx.txid == expected_txid }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_esplora_mainnet() {
        let script_hex = "6a24aa21a9ed932d00baa7d428106db4f785d398d60d0b9c1369c38448717db4a8f36d2512e3";
        let expected_txid = "d734d56c70ee7ac67d31a22f4b9a781619c5cff1803942b52036cd7eab1692e7";
        test_electrs(ELECTRS_MAINNET_URL, script_hex, expected_txid).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_esplora_testnet() {
        let script_hex = "6a208b26f7cf49e1ad4d9f81d237933da8810644a85ac25b3c22a6a2324e1ba02efc";
        let expected_txid = "ec736ccba2cb7d1a97145a7e98d32f8eec362cd140e917ce40842a492f43b49b";
        test_electrs(ELECTRS_TESTNET_URL, script_hex, expected_txid).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_esplora_testnet2() {
        let script_hex = "6a4c5054325b0f43c54432b8df76322d225c9759359f73b283e108441862c2ee6fe4a021f6825bee72311ec0f53dd7197d0e325dca9a45aa3af296294b42c667b6db214a5174001fe7f40004001f7a07000b02";
        let expected_txid = "ddfaa4f63b9cbdf72299b91074fbff13b02816f2a29109b2fecfd912a7476807";
        test_electrs(ELECTRS_TESTNET_URL, script_hex, expected_txid).await;
    }
}
