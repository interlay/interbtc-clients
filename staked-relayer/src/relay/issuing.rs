use super::Error;
use crate::core::{Error as CoreError, Issuing};
use async_trait::async_trait;
use runtime::PolkaBtcProvider;
use runtime::{BtcRelayPallet, H256Le, RawBlockHeader};

pub struct Client {
    rpc: PolkaBtcProvider,
}

impl Client {
    pub fn new(rpc: PolkaBtcProvider) -> Self {
        Self { rpc }
    }
}

fn encode_raw_header(bytes: Vec<u8>) -> Result<RawBlockHeader, CoreError<Error>> {
    RawBlockHeader::from_bytes(bytes).map_err(|_| CoreError::Issuing(Error::SerializeHeader))
}

#[async_trait]
impl Issuing<Error> for Client {
    async fn is_initialized(&self) -> Result<bool, CoreError<Error>> {
        let hash = self
            .rpc
            .get_best_block()
            .await
            .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))?;
        Ok(!hash.is_zero())
    }

    async fn initialize(&self, header: Vec<u8>, height: u32) -> Result<(), CoreError<Error>> {
        self.rpc
            .initialize_btc_relay(encode_raw_header(header)?, height)
            .await
            .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))
    }

    async fn submit_block_header(&self, header: Vec<u8>) -> Result<(), CoreError<Error>> {
        let raw_block_header = encode_raw_header(header)?;
        if self
            .is_block_stored(raw_block_header.hash().to_bytes_le().to_vec())
            .await?
        {
            return Ok(());
        }
        self.rpc
            .store_block_header(raw_block_header)
            .await
            .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))
    }

    async fn submit_block_header_batch(
        &self,
        headers: Vec<Vec<u8>>,
    ) -> Result<(), CoreError<Error>> {
        self.rpc
            .store_block_headers(
                headers
                    .iter()
                    .map(|header| encode_raw_header(header.to_vec()))
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .await
            .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))
    }

    async fn get_best_height(&self) -> Result<u32, CoreError<Error>> {
        self.rpc
            .get_best_block_height()
            .await
            .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))
    }

    async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, CoreError<Error>> {
        let hash = self
            .rpc
            .get_block_hash(height)
            .await
            .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))?;
        hex::decode(hash.to_hex_le()).map_err(|_| CoreError::Issuing(Error::DecodeHash))
    }

    async fn is_block_stored(&self, hash_le: Vec<u8>) -> Result<bool, CoreError<Error>> {
        let head = self
            .rpc
            .get_block_header(H256Le::from_bytes_le(&hash_le))
            .await
            .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))?;
        Ok(head.block_height > 0)
    }
}
