#[cfg(feature = "cli")]
pub mod cli;

mod addr;
mod error;
mod iter;

pub use addr::PartialAddress;
use async_trait::async_trait;
use backoff::{future::FutureOperation as _, ExponentialBackoff};
pub use bitcoincore_rpc::{
    bitcoin::{
        blockdata::opcodes::all as opcodes,
        blockdata::script::Builder,
        consensus::encode::serialize,
        hash_types::BlockHash,
        hashes::{hex::ToHex, Hash},
        util::{address::Payload, psbt::serialize::Serialize},
        Address, Amount, Block, BlockHeader, Network, PubkeyHash, Script, ScriptHash, Transaction,
        TxOut, Txid, WPubkeyHash,
    },
    bitcoincore_rpc_json::{GetRawTransactionResult, GetTransactionResult, WalletTxInfo},
    json::{self, AddressType, GetBlockResult},
    jsonrpc::error::RpcError,
    jsonrpc::Error as JsonRpcError,
    Auth, Client, Error as BitcoinError, RpcApi,
};
pub use error::{BitcoinRpcError, ConversionError, Error};
pub use iter::{get_transactions, stream_blocks, stream_in_chain_transactions};
use rand::{self, Rng};
use sp_core::H256;
use std::sync::Arc;
use std::{collections::HashMap, time::Duration};
use tokio::time::delay_for;

#[macro_use]
extern crate num_derive;

const NOT_IN_MEMPOOL_ERROR_CODE: i32 = BitcoinRpcError::RpcInvalidAddressOrKey as i32;

pub struct TransactionMetadata {
    pub txid: Txid,
    pub proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
    pub block_height: u32,
    pub block_hash: BlockHash,
}

#[async_trait]
pub trait BitcoinCoreApi {
    async fn wait_for_block(&self, height: u32, delay: Duration) -> Result<BlockHash, Error>;

    fn get_block_count(&self) -> Result<u64, Error>;

    fn get_block_transactions(
        &self,
        hash: &BlockHash,
    ) -> Result<Vec<Option<GetRawTransactionResult>>, Error>;

    fn get_raw_tx_for(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, Error>;

    fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error>;

    fn get_new_address<A: PartialAddress + 'static>(&self) -> Result<A, Error>;

    fn get_best_block_hash(&self) -> Result<BlockHash, Error>;

    fn get_block(&self, hash: &BlockHash) -> Result<Block, Error>;

    fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, Error>;

    fn get_mempool_transactions<'a>(
        self: Arc<Self>,
    ) -> Result<Box<dyn Iterator<Item = Result<Transaction, Error>> + 'a>, Error>;

    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        op_timeout: Duration,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error>;

    async fn send_to_address<A: PartialAddress + 'static>(
        &self,
        address: String,
        sat: u64,
        redeem_id: &[u8; 32],
        op_timeout: Duration,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error>;

    fn create_wallet(&self, wallet: &str) -> Result<(), Error>;
}

pub struct BitcoinCore {
    rpc: Client,
}

impl BitcoinCore {
    pub fn new(rpc: Client) -> Self {
        Self { rpc }
    }
}

/// true if the given indicates that the item was not found in the mempool
fn err_not_in_mempool(err: &bitcoincore_rpc::Error) -> bool {
    matches!(err,
        &bitcoincore_rpc::Error::JsonRpc(
            JsonRpcError::Rpc(
                RpcError {code: NOT_IN_MEMPOOL_ERROR_CODE, .. }
        )))
}

#[async_trait]
impl BitcoinCoreApi for BitcoinCore {
    /// Wait for a specified height to return a `BlockHash` or
    /// exit on error.
    ///
    /// # Arguments
    /// * `height` - block height to fetch
    /// * `delay` - wait period before re-checking
    async fn wait_for_block(&self, height: u32, delay: Duration) -> Result<BlockHash, Error> {
        loop {
            match self.rpc.get_block_hash(height.into()) {
                Ok(hash) => return Ok(hash),
                Err(e) => {
                    delay_for(delay).await;
                    if let BitcoinError::JsonRpc(JsonRpcError::Rpc(rpc_error)) = &e {
                        match BitcoinRpcError::from(rpc_error.clone()) {
                            // block does not exist yet
                            BitcoinRpcError::RpcInvalidParameter => continue,
                            _ => (),
                        };
                    }
                    return Err(e.into());
                }
            }
        }
    }

    /// Get the tip of the main chain as reported by Bitcoin core.
    fn get_block_count(&self) -> Result<u64, Error> {
        Ok(self.rpc.get_block_count()?)
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
    /// * `txid` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    fn get_raw_tx_for(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(serialize(
            &self.rpc.get_raw_transaction(txid, Some(block_hash))?,
        ))
    }

    /// Get the merkle proof which can be used to validate transaction inclusion.
    ///
    /// # Arguments
    /// * `txid` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(self.rpc.get_tx_out_proof(&[txid], Some(block_hash))?)
    }

    /// Get the block hash for a given height.
    ///
    /// # Arguments
    /// * `height` - block height
    fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, Error> {
        match self.rpc.get_block_hash(height.into()) {
            Ok(block_hash) => Ok(block_hash),
            Err(e) => Err(
                if let BitcoinError::JsonRpc(JsonRpcError::Rpc(rpc_error)) = &e {
                    match BitcoinRpcError::from(rpc_error.clone()) {
                        // block does not exist yet
                        BitcoinRpcError::RpcInvalidParameter => Error::InvalidBitcoinHeight,
                        _ => e.into(),
                    }
                } else {
                    e.into()
                },
            ),
        }
    }

    /// Checks if the local full node has seen the specified block hash.
    ///
    /// # Arguments
    /// * `block_hash` - hash of the block to verify
    fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error> {
        // TODO: match exact error
        Ok(self.rpc.get_block(&block_hash).is_ok())
    }

    /// Gets a new address from the wallet
    fn get_new_address<A: PartialAddress + 'static>(&self) -> Result<A, Error> {
        let address = self.rpc.get_new_address(None, Some(AddressType::Bech32))?;
        Ok(A::decode_str(&address.to_string())?)
    }

    fn get_best_block_hash(&self) -> Result<BlockHash, Error> {
        Ok(self.rpc.get_best_block_hash()?)
    }

    fn get_block(&self, hash: &BlockHash) -> Result<Block, Error> {
        Ok(self.rpc.get_block(hash)?)
    }

    fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, Error> {
        Ok(self.rpc.get_block_info(hash)?)
    }

    /// Get the transactions that are currently in the mempool. Since `impl trait` is not
    /// allowed within trait method, we have to use trait objects.
    fn get_mempool_transactions<'a>(
        self: Arc<Self>,
    ) -> Result<Box<dyn Iterator<Item = Result<Transaction, Error>> + 'a>, Error> {
        // get txids from the mempool
        let txids = self.rpc.get_raw_mempool()?;
        // map txid to the actual Transaction structs
        let iterator = txids.into_iter().filter_map(move |txid| {
            match self.rpc.get_raw_transaction_info(&txid, None) {
                Ok(x) => Some(x.transaction().map_err(Into::into)),
                Err(e) if err_not_in_mempool(&e) => None, // not in mempool anymore, so filter out
                Err(e) => Some(Err(e.into())),            // unknown error, propagate to user
            }
        });
        Ok(Box::new(iterator))
    }
    /// Waits for the required number of confirmations, and collects data about the
    /// transaction
    ///
    /// # Arguments
    /// * `txid` - transaction ID
    /// * `op_timeout` - wait period before re-checking
    /// * `op_timeout` - how long operations will be retried
    /// * `num_confirmations` - how many confirmations we need to wait for
    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        op_timeout: Duration,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error> {
        let get_retry_policy = || ExponentialBackoff {
            max_elapsed_time: Some(op_timeout),
            ..Default::default()
        };

        let (block_height, block_hash) = (|| async {
            Ok(match self.rpc.get_transaction(&txid, None) {
                Ok(GetTransactionResult {
                    info:
                        WalletTxInfo {
                            confirmations,
                            blockhash: Some(hash),
                            blockheight: Some(height),
                            ..
                        },
                    ..
                }) if confirmations >= 0 && confirmations as u32 >= num_confirmations => {
                    Ok((height, hash))
                }
                Ok(_) => Err(Error::ConfirmationError),
                Err(e) => Err(e.into()),
            }?)
        })
        .retry(get_retry_policy())
        .await?;

        let proof = (|| async { Ok(self.get_proof_for(txid, &block_hash)?) })
            .retry(get_retry_policy())
            .await?;

        let raw_tx = (|| async { Ok(self.get_raw_tx_for(&txid, &block_hash)?) })
            .retry(get_retry_policy())
            .await?;

        Ok(TransactionMetadata {
            txid,
            block_hash,
            block_height,
            proof,
            raw_tx,
        })
    }

    /// Send an amount of Bitcoin to an address and wait until it has a confirmation.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to fund
    /// * `sat` - number of Satoshis to transfer
    /// * `redeem_id` - the redeemid for which this transfer is being made
    /// * `op_timeout` - how long operations will be retried
    /// * `num_confirmations` - how many confirmations we need to wait for
    async fn send_to_address<A: PartialAddress + 'static>(
        &self,
        address: String,
        sat: u64,
        redeem_id: &[u8; 32],
        op_timeout: Duration,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error> {
        let mut recipients = HashMap::<String, Amount>::new();
        recipients.insert(address.clone(), Amount::from_sat(sat));

        let delay = rand::thread_rng().gen_range(1000, 10000);
        delay_for(Duration::from_millis(delay)).await;

        let raw_tx = self
            .rpc
            .create_raw_transaction_hex(&[], &recipients, None, None)?;

        let raw_tx = self.rpc.fund_raw_transaction(raw_tx, None, None)?;

        let mut tx = raw_tx.transaction().unwrap();

        fix_transaction_output_order(&mut tx, A::decode_str(&address)?)?;

        // include the redeem is in the transaction
        add_redeem_id(&mut tx, redeem_id);

        let signed_raw_tx =
            self.rpc
                .sign_raw_transaction_with_wallet(tx.serialize().to_hex(), None, None)?;

        let txid = self
            .rpc
            .send_raw_transaction(signed_raw_tx.transaction().unwrap().serialize().to_hex())?;

        #[cfg(feature = "regtest")]
        self.rpc.generate_to_address(
            1,
            &self.rpc.get_new_address(None, Some(AddressType::Bech32))?,
        )?;

        Ok(self
            .wait_for_transaction_metadata(txid, op_timeout, num_confirmations)
            .await?)
    }

    /// Create or load a wallet on Bitcoin Core.
    ///
    /// # Arguments
    /// * `wallet` - name of the wallet
    fn create_wallet(&self, wallet: &str) -> Result<(), Error> {
        // NOTE: bitcoincore-rpc does not expose listwalletdir
        if self.rpc.list_wallets()?.contains(&wallet.to_string()) {
            // wallet already loaded
            return Ok(());
        } else if let Ok(_) = self.rpc.load_wallet(wallet) {
            // wallet successfully loaded
            return Ok(());
        }
        // wallet does not exist, create
        self.rpc.create_wallet(wallet, None, None, None, None)?;
        Ok(())
    }
}

/// Extension trait for transaction, adding methods to help to match the Transaction to Replace/Redeem requests
pub trait TransactionExt {
    fn get_op_return(&self) -> Option<H256>;
    fn get_payment_amount_to<A: PartialAddress + PartialEq>(&self, dest: A) -> Option<u64>;
}

impl TransactionExt for Transaction {
    /// Extract the hash from the OP_RETURN uxto, if present
    fn get_op_return(&self) -> Option<H256> {
        // we only consider the first three items because the parachain only checks the first 3 positions
        self.output.iter().take(3).find_map(|x| {
            // match a slice that starts with op_return (0x6a), then has 32 as
            // the length indicator, and then has 32 bytes (the H256)
            match x.script_pubkey.to_bytes().as_slice() {
                [0x6a, 32, rest @ ..] if rest.len() == 32 => Some(H256::from_slice(rest)),
                _ => None,
            }
        })
    }

    /// Get the amount of btc that self sent to `dest`, if any
    fn get_payment_amount_to<A: PartialAddress + PartialEq>(&self, dest: A) -> Option<u64> {
        // we only consider the first three items because the parachain only checks the first 3 positions
        self.output.iter().take(3).find_map(|uxto| {
            let payload = Payload::from_script(&uxto.script_pubkey)?;
            let address = A::from_payload(payload).ok()?;
            if address == dest {
                Some(uxto.value)
            } else {
                None
            }
        })
    }
}

/// Ensures we follow the spec: the payment to the recipient needs to be the
/// first uxto. Funding the transaction sometimes places the return-to-self
/// uxto first, so this function performs a swap of uxtos if necessary
fn fix_transaction_output_order<A: PartialAddress>(
    tx: &mut Transaction,
    recipient_address: A,
) -> Result<(), Error> {
    // TODO: remove, we no longer check ordering on first three outputs
    let output0_address = A::from_payload(
        Payload::from_script(&tx.output[0].script_pubkey).ok_or(Error::InvalidAddress)?,
    )?;
    if recipient_address != output0_address {
        // most likely the return-to-self output was put first
        let output1_address = A::from_payload(
            Payload::from_script(&tx.output[1].script_pubkey).ok_or(Error::InvalidAddress)?,
        )?;
        if tx.output.len() > 1 && recipient_address == output1_address {
            tx.output.swap(0, 1);
        } else {
            // if this executes we have a bug in the code
            panic!("Could not find recipient address in bitcoin transaction");
        }
    }
    Ok(())
}

/// Adds op_return with the given id at index 1, occording to the redeem spec
fn add_redeem_id(tx: &mut Transaction, redeem_id: &[u8; 32]) {
    // Index 1: Data UTXO: OP_RETURN containing identifier
    tx.output.insert(
        1,
        TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::OP_RETURN)
                .push_slice(redeem_id)
                .into_script(),
        },
    );
}

pub fn extract_btc_addresses<A: PartialAddress>(tx: GetRawTransactionResult) -> Vec<A> {
    tx.vin
        .into_iter()
        .filter_map(|vin| {
            if let Some(script_sig) = &vin.script_sig {
                // this always returns ok so should be safe to unwrap
                let script = script_sig.script().unwrap();

                return Payload::from_script(&script).map_or(None, |payload| {
                    PartialAddress::from_payload(payload).map_or(None, |addr| Some(addr))
                });
            }
            None
        })
        .collect::<Vec<A>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoincore_rpc::{
        bitcoin::{Txid, Wtxid},
        bitcoincore_rpc_json::{GetRawTransactionResultVin, GetRawTransactionResultVinScriptSig},
    };

    mockall::mock! {
        Bitcoin {}

        #[async_trait]
        trait BitcoinCoreApi {
            async fn wait_for_block(&self, height: u32, delay: Duration) -> Result<BlockHash, Error>;

            fn get_block_count(&self) -> Result<u64, Error>;

            fn get_block_transactions(
                &self,
                hash: &BlockHash,
            ) -> Result<Vec<Option<GetRawTransactionResult>>, Error>;

            fn get_raw_tx_for(
                &self,
                txid: &Txid,
                block_hash: &BlockHash,
            ) -> Result<Vec<u8>, Error>;

            fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

            fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, Error>;

            fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error>;

            fn get_new_address<A: PartialAddress + 'static>(&self) -> Result<A, Error>;

            fn get_best_block_hash(&self) -> Result<BlockHash, Error>;

            fn get_block(&self, hash: &BlockHash) -> Result<Block, Error>;

            fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, Error>;

            fn get_mempool_transactions<'a>(
                self: Arc<Self>,
            ) -> Result<Box<dyn Iterator<Item = Result<Transaction, Error>> + 'a>, Error>;

            async fn wait_for_transaction_metadata(
                &self,
                txid: Txid,
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, Error>;

            async fn send_to_address<A: PartialAddress + 'static>(
                &self,
                address: String,
                sat: u64,
                redeem_id: &[u8; 32],
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, Error>;

            fn create_wallet(&self, wallet: &str) -> Result<(), Error>;
        }
    }

    #[test]
    fn test_tx_has_inputs() {
        let addr = Payload::ScriptHash(
            ScriptHash::from_slice(
                &hex::decode("4ef45ff516f84c62b09ad4f605f92abc103f916b").unwrap(),
            )
            .unwrap(),
        );

        assert_eq!(
            extract_btc_addresses::<Payload>(GetRawTransactionResult {
                in_active_chain: None,
                hex: vec![],
                txid: Txid::default(),
                hash: Wtxid::default(),
                size: 0,
                vsize: 0,
                version: 0,
                locktime: 0,
                vin: vec![GetRawTransactionResultVin {
                    sequence: 0,
                    coinbase: None,
                    txid: None,
                    vout: None,
                    script_sig: Some(GetRawTransactionResultVinScriptSig {
                        asm: "".to_string(),
                        hex: vec![
                            169, 20, 78, 244, 95, 245, 22, 248, 76, 98, 176, 154, 212, 246, 5, 249,
                            42, 188, 16, 63, 145, 107, 135
                        ],
                    }),
                    txinwitness: None,
                }],
                vout: vec![],
                blockhash: None,
                confirmations: None,
                time: None,
                blocktime: None,
            }),
            vec![addr]
        );
    }
}
