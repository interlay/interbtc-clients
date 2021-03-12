use super::Error;
use crate::core::{Backing, Error as CoreError};
use async_trait::async_trait;
pub use bitcoin::Client as RPC;
use bitcoin::{serialize, RpcApi};
use std::sync::Arc;

pub struct Client {
    rpc: Arc<RPC>,
}

impl Client {
    pub fn new(rpc: Arc<RPC>) -> Self {
        Client { rpc }
    }
}

#[async_trait]
impl Backing<Error> for Client {
    fn get_block_count(&self) -> Result<u32, CoreError<Error>> {
        let count = self
            .rpc
            .get_block_count()
            .map_err(|e| CoreError::Backing(Error::BitcoinError(e)))?;
        return Ok(count as u32);
    }

    fn get_block_header(&self, height: u32) -> Result<Option<Vec<u8>>, CoreError<Error>> {
        let block_hash = match self.rpc.get_block_hash(height as u64) {
            Ok(h) => h,
            Err(_) => {
                // TODO: match error
                return Ok(None);
            }
        };
        let block_header = self
            .rpc
            .get_block_header(&block_hash)
            .map_err(|e| CoreError::Backing(Error::BitcoinError(e)))?;
        Ok(Some(serialize(&block_header)))
    }

    fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, CoreError<Error>> {
        let block_hash = self
            .rpc
            .get_block_hash(height as u64)
            .map(|hash| serialize(&hash))
            .map_err(|e| CoreError::Backing(Error::BitcoinError(e)))?;
        Ok(block_hash)
    }
}
