use super::{get_http, BitcoinFeed};
use crate::Error;
use async_trait::async_trait;
use clap::Parser;
use reqwest::Url;

#[derive(Parser, Debug, Clone)]
pub struct BlockCypherCli {
    /// Fetch the bitcoin fee estimate from BlockCypher (https://api.blockcypher.com/v1/btc/main).
    #[clap(long)]
    blockcypher_url: Option<Url>,
}

pub struct BlockCypherApi {
    url: Url,
}

impl Default for BlockCypherApi {
    fn default() -> Self {
        Self {
            // Mainnet: https://api.blockcypher.com/v1/btc/main
            // Testnet: https://api.blockcypher.com/v1/btc/test3
            url: Url::parse("https://api.blockcypher.com/v1/btc/main").unwrap(),
        }
    }
}

impl BlockCypherApi {
    pub fn from_opts(opts: BlockCypherCli) -> Option<Self> {
        opts.blockcypher_url.map(Self::new)
    }

    pub fn new(url: Url) -> Self {
        Self { url }
    }

    pub async fn get_fee_estimate(&self, confirmation_target: u32) -> Result<f64, Error> {
        // https://www.blockcypher.com/dev/bitcoin/#restful-resources
        let url = self.url.clone();

        let attribute = match confirmation_target {
            1..=2 => "high_fee_per_kb",
            3..=6 => "medium_fee_per_kb",
            _ => "low_fee_per_kb",
        };

        let fee_estimate = get_http(url)
            .await?
            .get(&attribute)
            .ok_or(Error::InvalidResponse)?
            .as_f64()
            .ok_or(Error::InvalidResponse)?;

        // convert to sat/byte
        Ok(fee_estimate / 1_000.0)
    }
}

#[async_trait]
impl BitcoinFeed for BlockCypherApi {
    async fn get_fee_estimate(&self, confirmation_target: u32) -> Result<f64, Error> {
        self.get_fee_estimate(confirmation_target).await
    }
}
