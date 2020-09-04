use crate::rpc::Provider;
use crate::Error;
use futures::executor::block_on;
use relayer_core::{Error as CoreError, Issuing};
use runtime::{H256Le, RawBlockHeader};

pub struct Client {
    rpc: Provider,
}

impl Client {
    pub fn new(rpc: Provider) -> Result<Self, Error> {
        Ok(Client { rpc })
    }
}

fn encode_raw_header(bytes: Vec<u8>) -> Result<RawBlockHeader, CoreError<Error>> {
    RawBlockHeader::from_bytes(bytes).map_err(|e| CoreError::Issuing(Error::Other(e.to_string())))
}

impl Issuing<Error> for Client {
    fn initialize(&self, header: Vec<u8>, height: u32) -> Result<(), CoreError<Error>> {
        block_on(
            self.rpc
                .initialize_btc_relay(encode_raw_header(header)?, height),
        )
        .map_err(|e| CoreError::Issuing(Error::RpcError(e)))
    }

    fn submit_block_header(&self, header: Vec<u8>) -> Result<(), CoreError<Error>> {
        println!("submit_block_header");
        block_on(self.rpc.store_block_header(encode_raw_header(header)?))
            .map_err(|e| CoreError::Issuing(Error::RpcError(e)))
    }

    fn submit_block_header_batch(&self, _headers: Vec<u8>) -> Result<(), CoreError<Error>> {
        println!("submit_block_header_batch");
        Ok(())
    }

    fn get_best_height(&self) -> Result<u32, CoreError<Error>> {
        block_on(self.rpc.get_best_block_height())
            .map_err(|e| CoreError::Issuing(Error::RpcError(e)))
    }

    fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, CoreError<Error>> {
        let hash = block_on(self.rpc.get_block_hash(height))
            .map_err(|e| CoreError::Issuing(Error::RpcError(e)))?;
        hex::decode(hash.to_hex_be())
            .map_err(|_| CoreError::Issuing(Error::Other("failed to decode hash".to_string())))
    }

    // TODO: check endianness
    fn is_block_stored(&self, hash: Vec<u8>) -> Result<bool, CoreError<Error>> {
        let head = block_on(self.rpc.get_block_header(H256Le::from_bytes_le(&hash)))
            .map_err(|e| CoreError::Issuing(Error::RpcError(e)))?;
        Ok(head.block_height > 0)
    }
}
