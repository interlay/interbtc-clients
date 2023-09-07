use async_trait::async_trait;
use std::{fmt, sync::Arc};

#[async_trait]
pub trait RandomDelay: fmt::Debug {
    type Error;
    async fn delay(&self, seed_data: &[u8; 32]) -> Result<(), Self::Error>;
}

#[async_trait]
pub trait Issuing {
    type Error;

    /// Returns true if the light client is initialized
    async fn is_initialized(&self) -> Result<bool, Self::Error>;

    /// Initialize the light client
    ///
    /// # Arguments
    ///
    /// * `header` - Raw block header
    /// * `height` - Starting height
    async fn initialize(&self, header: Vec<u8>, height: u32) -> Result<(), Self::Error>;

    /// Submit a block header and wait for inclusion
    ///
    /// # Arguments
    ///
    /// * `header` - Raw block header
    async fn submit_block_header(
        &self,
        header: Vec<u8>,
        random_delay: Arc<Box<dyn RandomDelay<Error = Self::Error> + Send + Sync>>,
    ) -> Result<(), Self::Error>;

    /// Submit a batch of block headers and wait for inclusion
    ///
    /// # Arguments
    ///
    /// * `headers` - Raw block headers (multiple of 80 bytes)
    async fn submit_block_header_batch(&self, headers: Vec<Vec<u8>>) -> Result<(), Self::Error>;

    /// Returns the light client's chain tip
    async fn get_best_height(&self) -> Result<u32, Self::Error>;

    /// Returns the block hash stored at a given height,
    /// this is assumed to be in little-endian format
    ///
    /// # Arguments
    ///
    /// * `height` - Height of the block to fetch
    async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, Self::Error>;

    /// Returns true if the block described by the hash
    /// has been stored in the light client
    ///
    /// # Arguments
    ///
    /// * `hash_le` - Hash (little-endian) of the block
    async fn is_block_stored(&self, hash_le: Vec<u8>) -> Result<bool, Self::Error>;
}
