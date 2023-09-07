use crate::{serialize, BitcoinCoreApi, DynBitcoinCoreApi, Error as BitcoinError};
use async_trait::async_trait;

#[async_trait]
pub trait Backing {
    /// Returns the height of the longest chain
    async fn get_block_count(&self) -> Result<u32, BitcoinError>;

    /// Returns the raw header of a block in storage
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the block to fetch
    async fn get_block_header(&self, height: u32) -> Result<Option<Vec<u8>>, BitcoinError>;

    /// Returns the (little endian) hash of a block
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the block to fetch
    async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, BitcoinError>;
}

#[async_trait]
impl Backing for DynBitcoinCoreApi {
    async fn get_block_count(&self) -> Result<u32, BitcoinError> {
        let count = BitcoinCoreApi::get_block_count(&**self).await?;
        return Ok(count as u32);
    }

    async fn get_block_header(&self, height: u32) -> Result<Option<Vec<u8>>, BitcoinError> {
        let block_hash = match BitcoinCoreApi::get_block_hash(&**self, height).await {
            Ok(h) => h,
            Err(BitcoinError::InvalidBitcoinHeight) => {
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        let block_header = BitcoinCoreApi::get_block_header(&**self, &block_hash).await?;
        Ok(Some(serialize(&block_header)))
    }

    async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, BitcoinError> {
        let block_hash = BitcoinCoreApi::get_block_hash(&**self, height)
            .await
            .map(|hash| serialize(&hash))?;
        Ok(block_hash)
    }
}
