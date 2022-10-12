use super::{get_http, BitcoinFeed};
use crate::Error;
use async_trait::async_trait;
use clap::Parser;
use reqwest::Url;

#[derive(Parser, Debug, Clone)]
pub struct BlockstreamCli {
    /// Fetch the bitcoin fee estimate from Blockstream (https://blockstream.info/api/).
    #[clap(long)]
    blockstream_url: Option<Url>,
}

pub struct BlockstreamApi {
    url: Url,
}

impl Default for BlockstreamApi {
    fn default() -> Self {
        Self {
            // Mainnet: https://blockstream.info/api/
            // Testnet: https://blockstream.info/testnet/api/
            url: Url::parse("https://blockstream.info/api/").unwrap(),
        }
    }
}

impl BlockstreamApi {
    pub fn from_opts(opts: BlockstreamCli) -> Option<Self> {
        opts.blockstream_url.map(Self::new)
    }

    pub fn new(url: Url) -> Self {
        Self { url }
    }

    pub async fn get_fee_estimate(&self, confirmation_target: u32) -> Result<f64, Error> {
        // https://github.com/Blockstream/esplora/blob/master/API.md
        let mut url = self.url.clone();
        url.set_path(&format!("{}/fee-estimates", self.url.path()));

        let fee_estimate = get_http(url)
            .await?
            .get(&confirmation_target.to_string())
            .ok_or(Error::InvalidResponse)?
            .as_f64()
            .ok_or(Error::InvalidResponse)?;

        Ok(fee_estimate)
    }
}

#[async_trait]
impl BitcoinFeed for BlockstreamApi {
    async fn get_fee_estimate(&self, confirmation_target: u32) -> Result<f64, Error> {
        self.get_fee_estimate(confirmation_target).await
    }
}
