use super::Error;
use async_trait::async_trait;
use std::error::Error as StdError;

#[async_trait]
pub trait Backing<E: StdError> {
    /// Returns the height of the longest chain
    async fn get_block_count(&self) -> Result<u32, Error<E>>;

    /// Returns the raw header of a block in storage
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the block to fetch
    async fn get_block_header(&self, height: u32) -> Result<Option<Vec<u8>>, Error<E>>;

    /// Returns the (little endian) hash of a block
    ///
    /// # Arguments
    ///
    /// * `height` - The height of the block to fetch
    async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, Error<E>>;
}

#[async_trait]
pub trait Issuing<E: StdError> {
    /// Returns true if the light client is initialized
    async fn is_initialized(&self) -> Result<bool, Error<E>>;

    /// Initialize the light client
    ///
    /// # Arguments
    ///
    /// * `header` - Raw block header
    /// * `height` - Starting height
    async fn initialize(&self, header: Vec<u8>, height: u32) -> Result<(), Error<E>>;

    /// Submit a block header and wait for inclusion
    ///
    /// # Arguments
    ///
    /// * `header` - Raw block header
    async fn submit_block_header(&self, header: Vec<u8>) -> Result<(), Error<E>>;

    /// Submit a batch of block headers and wait for inclusion
    ///
    /// # Arguments
    ///
    /// * `headers` - Raw block headers (multiple of 80 bytes)
    async fn submit_block_header_batch(&self, headers: Vec<Vec<u8>>) -> Result<(), Error<E>>;

    /// Returns the light client's chain tip
    async fn get_best_height(&self) -> Result<u32, Error<E>>;

    /// Returns the block hash stored at a given height,
    /// this is assumed to be in little-endian format
    ///
    /// # Arguments
    ///
    /// * `height` - Height of the block to fetch
    async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, Error<E>>;

    /// Returns true if the block described by the hash
    /// has been stored in the light client
    ///
    /// # Arguments
    ///
    /// * `hash_le` - Hash (little-endian) of the block
    async fn is_block_stored(&self, hash_le: Vec<u8>) -> Result<bool, Error<E>>;
}
