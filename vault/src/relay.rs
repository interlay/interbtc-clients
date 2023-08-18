use crate::Error;
use async_trait::async_trait;
use bitcoin::{
    relay::{Error as RelayError, Issuing, RandomDelay, Runner},
    sha256, DynBitcoinCoreApi, Hash,
};
use runtime::{BtcRelayPallet, Error as RuntimeError, H256Le, InterBtcParachain, RawBlockHeader};
use std::sync::Arc;

pub struct SubxtIssuer(InterBtcParachain);

impl From<InterBtcParachain> for SubxtIssuer {
    fn from(value: InterBtcParachain) -> Self {
        Self(value)
    }
}

#[async_trait]
impl Issuing for SubxtIssuer {
    type Error = RuntimeError;
    async fn is_initialized(&self) -> Result<bool, RuntimeError> {
        let hash = BtcRelayPallet::get_best_block(&self.0).await?;
        Ok(!hash.is_zero())
    }

    async fn initialize(&self, header: Vec<u8>, height: u32) -> Result<(), RuntimeError> {
        BtcRelayPallet::initialize_btc_relay(&self.0, RawBlockHeader(header), height)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "submit_block_header", skip(self, header))]
    async fn submit_block_header(
        &self,
        header: Vec<u8>,
        random_delay: Arc<Box<dyn RandomDelay<Error = Self::Error> + Send + Sync>>,
    ) -> Result<(), RuntimeError> {
        let raw_block_header = RawBlockHeader(header.clone());

        // wait a random amount of blocks, to avoid all vaults flooding the parachain with
        // this transaction
        (*random_delay)
            .delay(sha256::Hash::hash(header.as_slice()).as_byte_array())
            .await?;
        if self
            .is_block_stored(raw_block_header.hash().to_bytes_le().to_vec())
            .await?
        {
            return Ok(());
        }
        BtcRelayPallet::store_block_header(&self.0, raw_block_header)
            .await
            .map_err(Into::into)
    }

    #[tracing::instrument(name = "submit_block_header_batch", skip(self, headers))]
    async fn submit_block_header_batch(&self, headers: Vec<Vec<u8>>) -> Result<(), RuntimeError> {
        BtcRelayPallet::store_block_headers(
            &self.0,
            headers
                .iter()
                .map(|header| RawBlockHeader(header.to_vec()))
                .collect::<Vec<_>>(),
        )
        .await
        .map_err(Into::into)
    }

    async fn get_best_height(&self) -> Result<u32, RuntimeError> {
        BtcRelayPallet::get_best_block_height(&self.0).await.map_err(Into::into)
    }

    async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, RuntimeError> {
        let hash = BtcRelayPallet::get_block_hash(&self.0, height).await?;
        hex::decode(hash.to_hex_le()).map_err(|_| RuntimeError::HexDecodeError)
    }

    async fn is_block_stored(&self, hash_le: Vec<u8>) -> Result<bool, RuntimeError> {
        let head = BtcRelayPallet::get_block_header(&self.0, H256Le::from_bytes_le(&hash_le)).await?;
        Ok(head.block_height > 0)
    }
}

pub async fn run_relayer(runner: Runner<DynBitcoinCoreApi, SubxtIssuer>) -> Result<(), Error> {
    loop {
        match runner.submit_next().await {
            Ok(_) => (),
            Err(RelayError::RuntimeError(ref err)) if err.is_duplicate_block() => {
                tracing::info!("Attempted to submit block that already exists")
            }
            Err(RelayError::RuntimeError(ref err)) if err.is_rpc_disconnect_error() => {
                return Err(Error::ClientShutdown);
            }
            Err(RelayError::BitcoinError(err)) if err.is_transport_error() => {
                return Err(Error::ClientShutdown);
            }
            Err(err) => {
                tracing::error!("Failed to submit_next: {}", err);
            }
        }
    }
}
