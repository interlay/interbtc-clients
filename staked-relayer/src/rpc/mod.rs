use log::error;
use runtime::pallet_btc_relay::*;
use runtime::pallet_exchange_rate_oracle::*;
use runtime::pallet_security::*;
use runtime::pallet_staked_relayers::*;
use runtime::pallet_vault_registry::*;
use runtime::PolkaBTC;
use sp_core::crypto::{AccountId32, Pair};
use sp_core::sr25519::Pair as KeyPair;
use std::convert::TryInto;
use std::sync::Arc;
use substrate_subxt::{system::System, Client, EventSubscription, EventsDecoder, PairSigner};

// subxt doesn't decode errors
mod error;

pub use error::Error;

#[derive(Clone)]
pub struct Provider {
    client: Client<PolkaBTC>,
    signer: Arc<PairSigner<PolkaBTC, KeyPair>>,
}

fn bytes_to_address(id: &[u8]) -> Result<[u8; 32], std::array::TryFromSliceError> {
    id.try_into()
}

impl Provider {
    pub fn new(client: Client<PolkaBTC>, signer: Arc<PairSigner<PolkaBTC, KeyPair>>) -> Self {
        Self { client, signer }
    }

    pub fn get_address(&self) -> AccountId32 {
        self.signer.signer().public().into()
    }

    pub async fn get_best_block(&self) -> Result<H256Le, Error> {
        self.client
            .best_block(None)
            .await
            .map_err(|err| Error::BestBlock(err))
    }

    pub async fn get_best_block_height(&self) -> Result<u32, Error> {
        self.client
            .best_block_height(None)
            .await
            .map_err(|err| Error::BestBlockHeight(err))
    }

    pub async fn get_block_hash(&self, height: u32) -> Result<H256Le, Error> {
        // TODO: adjust chain index
        self.client
            .chains_hashes(0, height, None)
            .await
            .map_err(|err| Error::BlockHash(err))
    }

    pub async fn get_block_header(&self, hash: H256Le) -> Result<RichBlockHeader, Error> {
        self.client
            .block_headers(hash, None)
            .await
            .map_err(|err| Error::BlockHeader(err))
    }

    pub async fn get_parachain_status(&self) -> Result<StatusCode, Error> {
        self.client
            .parachain_status(None)
            .await
            .map_err(|err| Error::ParachainStatus(err))
    }

    pub async fn get_status_update(
        &self,
        id: u64,
    ) -> Result<
        StatusUpdate<
            <PolkaBTC as System>::AccountId,
            <PolkaBTC as System>::BlockNumber,
            <PolkaBTC as StakedRelayers>::DOT,
        >,
        Error,
    > {
        self.client
            .status_updates(id.into(), None)
            .await
            .map_err(|err| Error::StatusUpdate(err))
    }

    pub async fn get_vault(
        &self,
        id: Vec<u8>,
    ) -> Result<
        Vault<
            <PolkaBTC as System>::AccountId,
            <PolkaBTC as System>::BlockNumber,
            <PolkaBTC as VaultRegistry>::PolkaBTC,
        >,
        Error,
    > {
        self.client
            .vaults(bytes_to_address(&id)?.into(), None)
            .await
            .map_err(|err| Error::GetVault(err))
    }

    pub async fn get_exchange_rate_info(&self) -> Result<(u64, u64), Error> {
        let get_rate = self.client.exchange_rate(None);
        let get_time = self.client.last_exchange_rate_time(None);

        match tokio::try_join!(get_rate, get_time) {
            Ok((rate, time)) => Ok((rate.try_into()?, time.into())),
            Err(_) => Err(Error::ExchangeRateInfo),
        }
    }

    pub async fn initialize_btc_relay(
        &self,
        header: RawBlockHeader,
        height: BitcoinBlockHeight,
    ) -> Result<(), Error> {
        self.client
            .initialize_and_watch(&*self.signer, header, height)
            .await
            .map_err(|err| Error::Initialize(err))?;
        Ok(())
    }

    pub async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), Error> {
        self.client
            .store_block_header_and_watch(&*self.signer, header)
            .await
            .map_err(|err| Error::StoreBlockHeader(err))?;
        Ok(())
    }

    pub async fn register_staked_relayer(&self, stake: u128) -> Result<(), Error> {
        self.client
            .register_staked_relayer_and_watch(&*self.signer, stake)
            .await
            .map_err(|err| Error::RegisterStakedRelayer(err))?;
        Ok(())
    }

    pub async fn deregister_staked_relayer(&self) -> Result<(), Error> {
        self.client
            .deregister_staked_relayer_and_watch(&*self.signer)
            .await
            .map_err(|err| Error::DeregisterStakedRelayer(err))?;
        Ok(())
    }

    pub async fn suggest_status_update(
        &self,
        deposit: u128,
        status_code: StatusCode,
    ) -> Result<(), Error> {
        let result = self
            .client
            .suggest_status_update_and_watch(
                &*self.signer,
                deposit,
                status_code,
                Some(ErrorCode::InvalidBTCRelay),
                None,
                None,
            )
            .await
            .map_err(|err| Error::SuggestStatusUpdate(err))?;
        println!("{:?}", result);
        Ok(())
    }

    pub async fn on_proposal(&self) -> Result<(), Error> {
        let sub = self
            .client
            .subscribe_events()
            .await
            .map_err(|_| Error::SubscribeProposals)?;
        let decoder = EventsDecoder::<PolkaBTC>::new(self.client.metadata().clone());
        let mut sub = EventSubscription::<PolkaBTC>::new(sub, decoder);
        sub.filter_event::<StatusUpdateSuggestedEvent<_>>();
        while let Some(result) = sub.next().await {
            match result {
                Ok(raw_event) => println!("{:?}", raw_event),
                Err(err) => error!("{}", err.to_string()),
            };
        }

        Ok(())
    }
}
