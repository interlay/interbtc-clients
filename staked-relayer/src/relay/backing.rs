use super::Error;
use crate::core::{Backing, Error as CoreError};
use async_trait::async_trait;
use bitcoin::serialize;
pub use bitcoin::{BitcoinCore, BitcoinCoreApi};

pub struct Client {
    bitcoin_core: BitcoinCore,
}

impl Client {
    pub fn new(bitcoin_core: BitcoinCore) -> Self {
        Client { bitcoin_core }
    }
}

#[async_trait]
impl Backing<Error> for Client {
    async fn get_block_count(&self) -> Result<u32, CoreError<Error>> {
        let count = self
            .bitcoin_core
            .get_block_count()
            .await
            .map_err(|e| CoreError::Backing(Error::BitcoinError(e)))?;
        return Ok(count as u32);
    }

    async fn get_block_header(&self, height: u32) -> Result<Option<Vec<u8>>, CoreError<Error>> {
        let block_hash = match self.bitcoin_core.get_block_hash(height).await {
            Ok(h) => h,
            Err(_) => {
                // TODO: match error
                return Ok(None);
            }
        };
        let block_header = self
            .bitcoin_core
            .get_block_header(&block_hash)
            .await
            .map_err(|e| CoreError::Backing(Error::BitcoinError(e)))?;
        Ok(Some(serialize(&block_header)))
    }

    async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, CoreError<Error>> {
        let block_hash = self
            .bitcoin_core
            .get_block_hash(height)
            .await
            .map(|hash| serialize(&hash))
            .map_err(|e| CoreError::Backing(Error::BitcoinError(e)))?;
        Ok(block_hash)
    }
}
