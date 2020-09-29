use relayer_core::bitcoin::bitcoincore_rpc::{
    bitcoin::{consensus::encode::serialize, hash_types::BlockHash, Txid},
    bitcoincore_rpc_json::GetRawTransactionResult,
    jsonrpc::Error as JsonRpcError,
    Client, Error as BtcError, RpcApi,
};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::Error;
pub trait BitcoinCore {
    fn wait_for_block(&self, height: u32) -> BlockMonitor;

    fn get_block_transactions(
        &self,
        hash: &BlockHash,
    ) -> Result<Vec<Option<GetRawTransactionResult>>, Error>;

    fn get_raw_tx(&self, tx_id: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    fn get_proof(&self, tx_id: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    fn get_block_hash(&self, height: u32) -> Result<BlockHash, Error>;

    fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error>;
}

pub struct BitcoinMonitor {
    rpc: Client,
}

impl BitcoinMonitor {
    pub fn new(rpc: Client) -> Self {
        BitcoinMonitor { rpc }
    }
}

impl BitcoinCore for BitcoinMonitor {
    /// Return an asynchronous future that can be `await`ed on
    /// the specified height.
    ///
    /// # Arguments
    /// * `height` - block height to fetch
    fn wait_for_block(&self, height: u32) -> BlockMonitor {
        BlockMonitor {
            rpc: &self.rpc,
            height,
        }
    }

    /// Get all transactions in a block identified by the
    /// given hash.
    ///
    /// # Arguments
    /// * `hash` - block hash to query
    fn get_block_transactions(
        &self,
        hash: &BlockHash,
    ) -> Result<Vec<Option<GetRawTransactionResult>>, Error> {
        let info = self.rpc.get_block_info(hash)?;
        let txs = info
            .tx
            .iter()
            .map(
                |id| match self.rpc.get_raw_transaction_info(&id, Some(hash)) {
                    Ok(tx) => Some(tx),
                    // TODO: log error
                    Err(_) => None,
                },
            )
            .collect::<Vec<Option<GetRawTransactionResult>>>();
        Ok(txs)
    }

    /// Get the raw transaction identified by `Txid` and stored
    /// in the specified block.
    ///
    /// # Arguments
    /// * `tx_id` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    fn get_raw_tx(&self, tx_id: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(serialize(
            &self.rpc.get_raw_transaction(tx_id, Some(block_hash))?,
        ))
    }

    /// Get the merkle proof which can be used to validate transaction inclusion.
    ///
    /// # Arguments
    /// * `tx_id` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    fn get_proof(&self, tx_id: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(self.rpc.get_tx_out_proof(&[tx_id], Some(block_hash))?)
    }

    /// Get the block hash for a given height.
    ///
    /// # Arguments
    /// * `height` - block height
    fn get_block_hash(&self, height: u32) -> Result<BlockHash, Error> {
        Ok(self.rpc.get_block_hash(height.into())?)
    }

    /// Checks if the local full node has seen the specified block hash.
    ///
    /// # Arguments
    /// * `block_hash` - hash of the block to verify
    fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error> {
        // TODO: match exact error
        Ok(match self.rpc.get_block(&block_hash) {
            Ok(_) => true,
            Err(_) => false,
        })
    }
}

pub struct BlockMonitor<'a> {
    rpc: &'a Client,
    height: u32,
}

impl<'a> Future for BlockMonitor<'a> {
    type Output = Result<BlockHash, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.rpc.get_block_hash(self.height.into()) {
            Ok(hash) => Poll::Ready(Ok(hash)),
            Err(e) => {
                if let BtcError::JsonRpc(JsonRpcError::Rpc(rpc_error)) = &e {
                    // https://github.com/bitcoin/bitcoin/blob/be3af4f31089726267ce2dbdd6c9c153bb5aeae1/src/rpc/protocol.h#L43
                    if rpc_error.code == -8 {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e.into()))
            }
        }
    }
}
