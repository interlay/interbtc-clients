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

pub struct BitcoinMonitor {
    rpc: Client,
}

impl BitcoinMonitor {
    pub fn new(rpc: Client) -> Self {
        BitcoinMonitor { rpc }
    }

    /// Return an asynchronous future that can be `await`ed on
    /// the specified height.
    ///
    /// # Arguments
    /// * `height` - block height to fetch
    pub fn wait_for_block(&self, height: u32) -> BlockMonitor {
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
    pub fn get_block_transactions(
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
    pub fn get_raw_tx(&self, tx_id: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(serialize(
            &self.rpc.get_raw_transaction(tx_id, Some(block_hash))?,
        ))
    }

    /// Get the merkle proof which can be used to validate transaction inclusion.
    ///
    /// # Arguments
    /// * `tx_id` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    pub fn get_proof(&self, tx_id: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(self.rpc.get_tx_out_proof(&[tx_id], Some(block_hash))?)
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
