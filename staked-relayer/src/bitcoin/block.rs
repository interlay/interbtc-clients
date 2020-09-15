use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::hex::ToHex;
use bitcoin::util::address::Payload;
use bitcoin::util::psbt::serialize::Serialize;
use bitcoincore_rpc::bitcoincore_rpc_json::GetRawTransactionResult;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use bitcoincore_rpc::{
    bitcoin::{
        blockdata::opcodes::all as opcodes, blockdata::script::Builder, Address, Amount,
        Transaction, TxOut, Txid,
    },
    Auth,
};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::env::read_env;
use crate::Error;

pub struct BitcoinMonitor {
    rpc: Client,
}

impl BitcoinMonitor {
    pub fn new(rpc: Client) -> Self {
        BitcoinMonitor { rpc }
    }

    pub fn from_env() -> Result<Self, Error> {
        let url = read_env("BITCOIN_RPC_URL")?;
        let user = read_env("BITCOIN_RPC_USER")?;
        let pass = read_env("BITCOIN_RPC_PASS")?;
        Ok(Self::new(
            Client::new(url, Auth::UserPass(user, pass)).unwrap(),
        ))
    }

    pub fn wait_for_block(&self, height: u64) -> BlockMonitor {
        BlockMonitor {
            rpc: &self.rpc,
            height,
        }
    }

    pub fn get_block_transactions(
        &self,
        hash: BlockHash,
    ) -> Result<Vec<Option<GetRawTransactionResult>>, Error> {
        let info = self.rpc.get_block_info(&hash)?;
        let txs = info
            .tx
            .iter()
            .map(
                |id| match self.rpc.get_raw_transaction_info(&id, Some(&hash)) {
                    Ok(tx) => Some(tx),
                    // TODO: log error
                    Err(_) => None,
                },
            )
            .collect::<Vec<Option<GetRawTransactionResult>>>();
        Ok(txs)
    }
}

pub struct BlockMonitor<'a> {
    rpc: &'a Client,
    height: u64,
}

impl<'a> Future for BlockMonitor<'a> {
    type Output = Result<BlockHash, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.rpc.get_block_hash(self.height) {
            Ok(hash) => Poll::Ready(Ok(hash)),
            Err(_) => {
                // TODO: check error
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
