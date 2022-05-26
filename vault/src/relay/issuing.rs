use std::{convert::TryInto, fmt::Debug};

use super::Error;
use crate::vaults::RandomDelay;
use async_trait::async_trait;
use bitcoin::{sha256, Hash};
use runtime::{BtcRelayPallet, H256Le, InterBtcParachain, RawBlockHeader, RelayPallet};

#[async_trait]
pub trait Issuing {
    /// Returns true if the light client is initialized
    async fn is_initialized(&self) -> Result<bool, Error>;

    /// Initialize the light client
    ///
    /// # Arguments
    ///
    /// * `header` - Raw block header
    /// * `height` - Starting height
    async fn initialize(&self, header: Vec<u8>, height: u32) -> Result<(), Error>;

    /// Submit a block header and wait for inclusion
    ///
    /// # Arguments
    ///
    /// * `header` - Raw block header
    async fn submit_block_header<RD: RandomDelay + Debug + Send + Sync>(
        &self,
        header: Vec<u8>,
        random_delay: Option<RD>,
    ) -> Result<(), Error>;

    /// Submit a batch of block headers and wait for inclusion
    ///
    /// # Arguments
    ///
    /// * `headers` - Raw block headers (multiple of 80 bytes)
    async fn submit_block_header_batch(&self, headers: Vec<Vec<u8>>) -> Result<(), Error>;

    /// Returns the light client's chain tip
    async fn get_best_height(&self) -> Result<u32, Error>;

    /// Returns the block hash stored at a given height,
    /// this is assumed to be in little-endian format
    ///
    /// # Arguments
    ///
    /// * `height` - Height of the block to fetch
    async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, Error>;

    /// Returns true if the block described by the hash
    /// has been stored in the light client
    ///
    /// # Arguments
    ///
    /// * `hash_le` - Hash (little-endian) of the block
    async fn is_block_stored(&self, hash_le: Vec<u8>) -> Result<bool, Error>;
}

fn encode_raw_header(bytes: Vec<u8>) -> Result<RawBlockHeader, Error> {
    let raw = bytes.try_into().map_err(|_| Error::SerializeHeader)?;
    Ok(RawBlockHeader(raw))
}

#[async_trait]
impl Issuing for InterBtcParachain {
    async fn is_initialized(&self) -> Result<bool, Error> {
        let hash = BtcRelayPallet::get_best_block(self).await?;
        Ok(!hash.is_zero())
    }

    async fn initialize(&self, header: Vec<u8>, height: u32) -> Result<(), Error> {
        RelayPallet::initialize_btc_relay(self, encode_raw_header(header)?, height)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "submit_block_header", skip(self, header))]
    async fn submit_block_header<RD: RandomDelay + Debug + Send + Sync>(
        &self,
        header: Vec<u8>,
        random_delay: Option<RD>,
    ) -> Result<(), Error> {
        let raw_block_header = encode_raw_header(header.clone())?;

        // wait a random amount of blocks, to avoid all vaults flooding the parachain with
        // this transaction
        if let Some(random_delay) = random_delay {
            random_delay
                .delay(&sha256::Hash::hash(header.as_slice()).into_inner())
                .await?;
        }
        if self
            .is_block_stored(raw_block_header.hash().to_bytes_le().to_vec())
            .await?
        {
            return Ok(());
        }
        RelayPallet::store_block_header(self, raw_block_header)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "submit_block_header_batch", skip(self, headers))]
    async fn submit_block_header_batch(&self, headers: Vec<Vec<u8>>) -> Result<(), Error> {
        RelayPallet::store_block_headers(
            self,
            headers
                .iter()
                .map(|header| encode_raw_header(header.to_vec()))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .await
        .map_err(Into::into)
    }

    async fn get_best_height(&self) -> Result<u32, Error> {
        BtcRelayPallet::get_best_block_height(self).await.map_err(Into::into)
    }

    async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, Error> {
        let hash = BtcRelayPallet::get_block_hash(self, height).await?;
        hex::decode(hash.to_hex_le()).map_err(|_| Error::DecodeHash)
    }

    async fn is_block_stored(&self, hash_le: Vec<u8>) -> Result<bool, Error> {
        let head = BtcRelayPallet::get_block_header(self, H256Le::from_bytes_le(&hash_le)).await?;
        Ok(head.block_height > 0)
    }
}
