use log::error;
use module_bitcoin::types::RawBlockHeader;
use runtime::pallet_btc_relay::*;
use runtime::pallet_collateral::*;
use runtime::pallet_security::*;
use runtime::pallet_staked_relayers::*;
use runtime::PolkaBTC;
use sp_core::crypto::{Pair, Public};
use sp_core::sr25519::Pair as KeyPair;
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::fmt;
use std::sync::Arc;
use substrate_subxt::balances::*;
use substrate_subxt::system::*;
use substrate_subxt::{
    system::System, Client, ClientBuilder, Error as XtError, EventSubscription, EventsDecoder,
    MetadataError, PairSigner, Runtime,
};

pub enum Error {
    BestBlockHeight(XtError),
    ParachainStatus(XtError),
    Initialize(XtError),
    StoreBlockHeader(XtError),
    RegisterStakedRelayer(XtError),
    DeregisterStakedRelayer(XtError),
    SuggestStatusUpdate(XtError),
    SubscribeProposals,
}

// subxt doesn't decode errors
impl Error {
    pub fn message(&self) -> String {
        match self {
            Error::BestBlockHeight(err) => format!("Read: BestBlockHeight: {}", err),
            Error::ParachainStatus(err) => format!("Read: ParachainStatus: {}", err),
            Error::Initialize(err) => format!("Write: Initialize: {}", err),
            Error::StoreBlockHeader(err) => format!("Write: StoreBlockHeader: {}", err),
            Error::RegisterStakedRelayer(err) => format!("Write: RegisterStakedRelayer: {}", err),
            Error::DeregisterStakedRelayer(err) => {
                format!("Write: DeregisterStakedRelayer: {}", err)
            }
            Error::SuggestStatusUpdate(err) => format!("Write: SuggestStatusUpdate: {}", err),
            Error::SubscribeProposals => "Failed to subscribe".to_string(),
        }
    }
}

impl std::error::Error for Error {}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

#[derive(Clone)]
pub struct Provider {
    client: Client<PolkaBTC>,
    signer: Arc<PairSigner<PolkaBTC, KeyPair>>,
}

impl<'a> Provider {
    pub fn new(client: Client<PolkaBTC>, signer: Arc<PairSigner<PolkaBTC, KeyPair>>) -> Self {
        Self { client, signer }
    }

    pub fn get_address(&self) -> String {
        hex::encode(self.signer.signer().public().to_raw_vec())
    }

    pub async fn get_best_block_height(&self) -> Result<u32, Error> {
        self.client
            .best_block_height(None)
            .await
            .map_err(|err| Error::BestBlockHeight(err))
    }

    pub async fn get_parachain_status(&self) -> Result<StatusCode, Error> {
        self.client
            .parachain_status(None)
            .await
            .map_err(|err| Error::ParachainStatus(err))
    }

    async fn initialize_btc_relay(
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

    async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), Error> {
        self.client
            .store_block_header_and_watch(&*self.signer, header)
            .await
            .map_err(|err| Error::StoreBlockHeader(err))?;
        Ok(())
    }

    async fn register_staked_relayer(&self, stake: u128) -> Result<(), Error> {
        self.client
            .register_staked_relayer_and_watch(&*self.signer, stake)
            .await
            .map_err(|err| Error::RegisterStakedRelayer(err))?;
        Ok(())
    }

    async fn deregister_staked_relayer(&self) -> Result<(), Error> {
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
            .suggest_status_update_and_watch(&*self.signer, deposit, status_code, None, None, None)
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
