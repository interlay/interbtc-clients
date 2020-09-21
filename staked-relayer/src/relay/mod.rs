mod error;

pub use error::Error;
use futures::executor::block_on;
use log::error;
use relayer_core::{Error as CoreError, Issuing};
use runtime::PolkaBtcProvider;
use runtime::{H256Le, RawBlockHeader};
use std::sync::Arc;

pub struct Client {
    rpc: Arc<PolkaBtcProvider>,
}

impl Client {
    pub fn new(rpc: Arc<PolkaBtcProvider>) -> Self {
        Self { rpc }
    }
}

fn encode_raw_header(bytes: Vec<u8>) -> Result<RawBlockHeader, CoreError<Error>> {
    RawBlockHeader::from_bytes(bytes).map_err(|_| CoreError::Issuing(Error::SerializeHeader))
}

impl Issuing<Error> for Client {
    fn is_initialized(&self) -> Result<bool, CoreError<Error>> {
        let hash = block_on(self.rpc.get_best_block())
            .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))?;
        Ok(!hash.is_zero())
    }

    fn initialize(&self, header: Vec<u8>, height: u32) -> Result<(), CoreError<Error>> {
        block_on(
            self.rpc
                .initialize_btc_relay(encode_raw_header(header)?, height),
        )
        .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))
    }

    fn submit_block_header(&self, header: Vec<u8>) -> Result<(), CoreError<Error>> {
        block_on(self.rpc.store_block_header(encode_raw_header(header)?)).map_err(|e| {
            error!("Failed to submit block: {}", e);
            CoreError::Issuing(Error::PolkaBtcError(e))
        })
    }

    fn submit_block_header_batch(&self, _headers: Vec<u8>) -> Result<(), CoreError<Error>> {
        // TODO: expose functionality on-chain
        self.submit_block_header(_headers)
    }

    fn get_best_height(&self) -> Result<u32, CoreError<Error>> {
        block_on(self.rpc.get_best_block_height())
            .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))
    }

    fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, CoreError<Error>> {
        let hash = block_on(self.rpc.get_block_hash(height))
            .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))?;
        hex::decode(hash.to_hex_le()).map_err(|_| CoreError::Issuing(Error::DecodeHash))
    }

    fn is_block_stored(&self, hash_le: Vec<u8>) -> Result<bool, CoreError<Error>> {
        let head = block_on(self.rpc.get_block_header(H256Le::from_bytes_le(&hash_le)))
            .map_err(|e| CoreError::Issuing(Error::PolkaBtcError(e)))?;
        Ok(head.block_height > 0)
    }
}
