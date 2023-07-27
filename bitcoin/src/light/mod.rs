mod error;
mod wallet;

pub use crate::{Error as BitcoinError, *};
use bitcoincore_rpc::bitcoin::secp256k1::Scalar;
pub use error::Error;

use async_trait::async_trait;
use backoff::future::retry;
use futures::future::{join_all, try_join, try_join4, try_join_all};
use std::{convert::TryFrom, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::sleep};

const RETRY_DURATION: Duration = Duration::from_millis(1000);

#[derive(Clone)]
pub struct BitcoinLight {
    private_key: PrivateKey,
    secp_ctx: secp256k1::Secp256k1<secp256k1::All>,
    electrs: ElectrsClient,
    transaction_creation_lock: Arc<Mutex<()>>,
    wallet: wallet::Wallet,
}

impl BitcoinLight {
    pub fn new(electrs_url: Option<String>, private_key: PrivateKey) -> Result<Self, Error> {
        let network = private_key.network;
        let electrs_client = ElectrsClient::new(electrs_url, network)?;
        let wallet = wallet::Wallet::new(network, electrs_client.clone());
        // store the derivation key so it can be used for change
        wallet.put_p2wpkh_key(private_key.inner)?;
        Ok(Self {
            private_key,
            secp_ctx: secp256k1::Secp256k1::new(),
            electrs: electrs_client,
            transaction_creation_lock: Arc::new(Mutex::new(())),
            wallet,
        })
    }

    fn get_change_address(&self) -> Result<Address, Error> {
        self.wallet
            .key_store
            .read()?
            .first_key_value()
            .map(|(address, _)| address.clone())
            .ok_or(Error::NoChangeAddress)
    }

    pub async fn fund_and_sign_transaction(
        &self,
        recipient: Address,
        unsigned_tx: Transaction,
        change_address: Address,
        fee_rate: SatPerVbyte,
        prev_txid: Option<Txid>,
    ) -> Result<LockedTransaction, BitcoinError> {
        let lock = self.transaction_creation_lock.clone().lock_owned().await;
        let mut psbt = self
            .wallet
            .fund_transaction(unsigned_tx, change_address, fee_rate.0.saturating_mul(1000), prev_txid)
            .await?;
        self.wallet.sign_transaction(&mut psbt)?;
        let signed_tx = psbt.extract_tx();
        Ok(LockedTransaction::new(signed_tx, recipient.to_string(), Some(lock)))
    }

    pub async fn create_transaction(
        &self,
        recipient: Address,
        sat: u64,
        fee_rate: SatPerVbyte,
        request_id: Option<H256>,
    ) -> Result<LockedTransaction, BitcoinError> {
        let unsigned_tx = self.wallet.create_transaction(recipient.clone(), sat, request_id);
        let change_address = self.get_change_address()?;
        self.fund_and_sign_transaction(recipient, unsigned_tx, change_address, fee_rate, None)
            .await
    }

    async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, BitcoinError> {
        let txid = self.electrs.send_transaction(transaction.transaction).await?;
        Ok(txid)
    }

    async fn get_coinbase_txid(&self, block_hash: &BlockHash) -> Result<Txid, BitcoinError> {
        Ok(self.electrs.get_coinbase_txid(&block_hash).await?)
    }
}

#[async_trait]
impl BitcoinCoreApi for BitcoinLight {
    fn is_full_node(&self) -> bool {
        false
    }

    fn network(&self) -> Network {
        self.private_key.network
    }

    async fn wait_for_block(&self, height: u32, num_confirmations: u32) -> Result<Block, BitcoinError> {
        loop {
            match try_join(
                self.electrs.get_block_hash(height),
                self.electrs.get_blocks_tip_height(),
            )
            .await
            {
                Ok((hash, best)) => {
                    if best.saturating_sub(height) >= num_confirmations {
                        return Ok(self.electrs.get_block(&hash).await?);
                    } else {
                        sleep(RETRY_DURATION).await;
                        continue;
                    }
                }
                _ => {
                    // TODO: handle error
                    sleep(RETRY_DURATION).await;
                    continue;
                }
            }
        }
    }

    async fn get_block_count(&self) -> Result<u64, BitcoinError> {
        Ok(self.electrs.get_blocks_tip_height().await?.into())
    }

    fn get_balance(&self, _min_confirmations: Option<u32>) -> Result<Amount, BitcoinError> {
        // TODO: implement
        Ok(Default::default())
    }

    fn list_transactions(&self, _max_count: Option<usize>) -> Result<Vec<json::ListTransactionResult>, BitcoinError> {
        // TODO: implement
        Ok(Default::default())
    }

    // TODO: remove this later
    fn list_addresses(&self) -> Result<Vec<Address>, BitcoinError> {
        // don't need to migrate keys
        Ok(Default::default())
    }

    async fn get_raw_tx(&self, txid: &Txid, _block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError> {
        Ok(self.electrs.get_raw_tx(txid).await?)
    }

    async fn get_transaction(&self, txid: &Txid, _block_hash: Option<BlockHash>) -> Result<Transaction, BitcoinError> {
        let raw_tx = self.electrs.get_raw_tx(txid).await?;
        deserialize(&raw_tx).map_err(Into::into)
    }

    async fn get_proof(&self, txid: Txid, _block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError> {
        Ok(self.electrs.get_raw_tx_merkle_proof(&txid).await?)
    }

    async fn get_block_hash(&self, height: u32) -> Result<BlockHash, BitcoinError> {
        match self.electrs.get_block_hash(height).await {
            Ok(block_hash) => Ok(block_hash),
            Err(err) if err.is_not_found() => Err(BitcoinError::InvalidBitcoinHeight),
            Err(err) => Err(BitcoinError::ElectrsError(err)),
        }
    }

    async fn get_new_address(&self) -> Result<Address, BitcoinError> {
        Ok(self.get_change_address()?)
    }

    async fn get_new_public_key(&self) -> Result<PublicKey, BitcoinError> {
        Ok(self.private_key.public_key(&self.secp_ctx))
    }

    fn dump_private_key(&self, _: &Address) -> Result<PrivateKey, BitcoinError> {
        Err(Error::InvalidAddress.into())
    }

    fn import_private_key(&self, _private_key: &PrivateKey, _is_derivation_key: bool) -> Result<(), BitcoinError> {
        // nothing to do
        Ok(())
    }

    async fn add_new_deposit_key(&self, _public_key: PublicKey, secret_key: Vec<u8>) -> Result<(), BitcoinError> {
        fn mul_secret_key(vault_key: SecretKey, issue_key: SecretKey) -> Result<SecretKey, BitcoinError> {
            let mut deposit_key = vault_key;
            deposit_key = deposit_key.mul_tweak(&Scalar::from(issue_key))?;
            Ok(deposit_key)
        }

        self.wallet.put_p2wpkh_key(mul_secret_key(
            self.private_key.inner,
            SecretKey::from_slice(&secret_key)?,
        )?)?;

        Ok(())
    }

    async fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinError> {
        Ok(self.electrs.get_blocks_tip_hash().await?)
    }

    async fn get_pruned_height(&self) -> Result<u64, BitcoinError> {
        // nothing to do
        Ok(Default::default())
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinError> {
        Ok(self.electrs.get_block(hash).await?)
    }

    async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, BitcoinError> {
        Ok(self.electrs.get_block_header(hash).await?)
    }

    async fn get_mempool_transactions<'a>(
        &'a self,
    ) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send + 'a>, BitcoinError> {
        let txids = self.electrs.get_raw_mempool().await?;
        let txs = join_all(txids.iter().map(|txid| self.get_transaction(txid, None))).await;
        Ok(Box::new(txs.into_iter()))
    }

    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, BitcoinError> {
        let (block_height, block_hash, fee) = retry(get_exponential_backoff(), || async {
            Ok(match self.electrs.get_tx_info(&txid).await {
                Ok(electrs::TxInfo {
                    confirmations,
                    height,
                    hash,
                    fee,
                }) if confirmations >= num_confirmations => Ok((height, hash, fee)),
                Ok(_) => Err(BitcoinError::ConfirmationError),
                Err(_e) => Err(BitcoinError::ConnectionRefused),
            }?)
        })
        .await?;

        let proof = retry(get_exponential_backoff(), || async {
            let coinbase_txid = self.get_coinbase_txid(&block_hash).await?;

            let (coinbase_tx_proof, raw_coinbase_tx, user_tx_proof, raw_user_tx) = try_join4(
                self.get_proof(coinbase_txid, &block_hash),
                self.get_raw_tx(&coinbase_txid, &block_hash),
                self.get_proof(txid, &block_hash),
                self.get_raw_tx(&txid, &block_hash),
            )
            .await?;
            Ok(RawTransactionProof {
                coinbase_tx_proof,
                raw_coinbase_tx,
                user_tx_proof,
                raw_user_tx,
            })
        })
        .await?;

        Ok(TransactionMetadata {
            txid,
            proof,
            block_height,
            block_hash,
            fee: Some(fee),
        })
    }

    async fn bump_fee(&self, txid: &Txid, address: Address, fee_rate: SatPerVbyte) -> Result<Txid, BitcoinError> {
        let mut existing_transaction = self.get_transaction(txid, None).await?;
        let return_to_self = existing_transaction
            .extract_return_to_self_address(&address.payload)?
            .map(|(idx, payload)| {
                existing_transaction.output.remove(idx);
                Address::new(self.network(), payload)
            });

        // clear the witnesses for fee estimation
        existing_transaction
            .input
            .iter_mut()
            .for_each(|txin| txin.witness.clear());
        let tx = self
            .fund_and_sign_transaction(
                address,
                existing_transaction,
                return_to_self.unwrap(),
                fee_rate,
                Some(*txid),
            )
            .await?;
        let txid = self.send_transaction(tx).await?;
        Ok(txid)
    }

    async fn create_and_send_transaction(
        &self,
        address: Address,
        sat: u64,
        fee_rate: SatPerVbyte,
        request_id: Option<H256>,
    ) -> Result<Txid, BitcoinError> {
        let tx = self.create_transaction(address, sat, fee_rate, request_id).await?;
        let txid = self.send_transaction(tx).await?;
        Ok(txid)
    }

    async fn send_to_address(
        &self,
        address: Address,
        sat: u64,
        request_id: Option<H256>,
        fee_rate: SatPerVbyte,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, BitcoinError> {
        let txid = self
            .create_and_send_transaction(address, sat, fee_rate, request_id)
            .await?;

        Ok(self.wait_for_transaction_metadata(txid, num_confirmations).await?)
    }

    async fn create_or_load_wallet(&self) -> Result<(), BitcoinError> {
        // nothing to do
        Ok(())
    }

    async fn rescan_blockchain(&self, _start_height: usize, _end_height: usize) -> Result<(), BitcoinError> {
        // nothing to do
        Ok(())
    }

    async fn rescan_electrs_for_addresses(&self, _addresses: Vec<Address>) -> Result<(), BitcoinError> {
        // nothing to do
        Ok(())
    }

    fn get_utxo_count(&self) -> Result<usize, BitcoinError> {
        // TODO: implement
        Ok(Default::default())
    }

    async fn is_in_mempool(&self, txid: Txid) -> Result<bool, BitcoinError> {
        let txids = self.electrs.get_raw_mempool().await?;
        Ok(txids.into_iter().any(|mempool_txid| mempool_txid == txid))
    }

    async fn fee_rate(&self, txid: Txid) -> Result<SatPerVbyte, BitcoinError> {
        let tx = self.get_transaction(&txid, None).await?;
        let vsize = tx.weight().to_vbytes_ceil();
        let recipients_sum = tx.output.iter().map(|tx_out| tx_out.value).sum::<u64>();

        let inputs = try_join_all(tx.input.iter().map(|input| async move {
            let prev_tx = self.get_transaction(&input.previous_output.txid, None).await?;
            let prev_out = prev_tx
                .output
                .get(usize::try_from(input.previous_output.vout)?)
                .ok_or(Error::NoPrevOut)?;
            Ok::<u64, BitcoinError>(prev_out.value)
        }))
        .await?;
        let input_sum = inputs.iter().sum::<u64>();
        let fee = input_sum.saturating_sub(recipients_sum);

        let fee_rate = fee.checked_div(vsize).ok_or(BitcoinError::ArithmeticError)?;
        Ok(SatPerVbyte(fee_rate))
    }

    async fn get_tx_for_op_return(
        &self,
        address: Address,
        amount: u128,
        data: H256,
    ) -> Result<Option<Txid>, BitcoinError> {
        Ok(self.electrs.get_tx_for_op_return(address, amount, data).await?)
    }
}
