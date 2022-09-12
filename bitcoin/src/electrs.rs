use crate::{Error, Network};
use esplora_btc_api::models::Transaction;
use reqwest::{Client, Url};

const ELECTRS_TRANSACTIONS_PER_PAGE: usize = 25;

const ELECTRS_TESTNET_URL: &str = "https://btc-testnet.interlay.io";
const ELECTRS_MAINNET_URL: &str = "https://btc-mainnet.interlay.io";
const ELECTRS_LOCALHOST_URL: &str = "http://localhost:3002";

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

    async fn get_and_decode<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let body = self.get(path).await?;
        Ok(serde_json::from_str(&body)?)
    }

    // the esplora_btc_api lib breaks on these two because it tries to serde_json::from_str on a plain string value
    pub async fn get_tx_hex(&self, txid: &str) -> Result<String, Error> {
        self.get(&format!("tx/{txid}/hex")).await
    }

    pub async fn get_tx_merkle_block_proof(&self, txid: &str) -> Result<String, Error> {
        self.get(&format!("tx/{txid}/merkleblock-proof")).await
    }

    // and it doesn't currently support the paged api call
    pub async fn get_address_tx_history_full(&self, address: &str) -> Result<Vec<Transaction>, Error> {
        let mut last_seen_txid = Default::default();
        let mut ret = Vec::<Transaction>::new();
        loop {
            let mut transactions: Vec<Transaction> = self
                .get_and_decode(&format!("address/{address}/txs/chain/{last_seen_txid}"))
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
