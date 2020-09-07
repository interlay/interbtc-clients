use crate::rpc::Error as PolkaError;
use crate::rpc::Provider as PolkaRPC;
use runtime::StatusCode;
use sp_core::crypto::Ss58Codec;

use tonic::{Code, Request, Response, Status};

pub use polkabtc::staked_relayer_server::StakedRelayer;
pub use polkabtc::staked_relayer_server::StakedRelayerServer;
// use polkabtc::status_response::Status as ParachainStatus;
use polkabtc::{AddressRequest, AddressResponse};
use polkabtc::{BestBlockRequest, BestBlockResponse};
use polkabtc::{DeregisterRequest, DeregisterResponse};
use polkabtc::{RegisterRequest, RegisterResponse};
use polkabtc::{StatusRequest, StatusResponse};

pub mod polkabtc {
    tonic::include_proto!("polkabtc");
}

pub struct Service {
    pub(crate) rpc: PolkaRPC,
}

impl From<PolkaError> for Status {
    fn from(err: PolkaError) -> Self {
        Status::new(Code::Internal, err.to_string())
    }
}

#[tonic::async_trait]
impl StakedRelayer for Service {
    async fn get_address(
        &self,
        _request: Request<AddressRequest>,
    ) -> Result<Response<AddressResponse>, Status> {
        Ok(Response::new(AddressResponse {
            address: self.rpc.get_address().to_ss58check(),
        }))
    }

    async fn get_best_block(
        &self,
        _request: Request<BestBlockRequest>,
    ) -> Result<Response<BestBlockResponse>, Status> {
        Ok(Response::new(BestBlockResponse {
            height: self.rpc.get_best_block_height().await?,
        }))
    }

    async fn get_status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Ok(Response::new(StatusResponse {
            status: match self.rpc.get_parachain_status().await? {
                // TODO: use generated types, there is some weirdness here
                StatusCode::Running => 0,
                StatusCode::Error => 1,
                StatusCode::Shutdown => 2,
            },
        }))
    }

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        self.rpc
            .register_staked_relayer(request.into_inner().stake.into())
            .await?;
        Ok(Response::new(RegisterResponse {}))
    }

    async fn deregister(
        &self,
        _request: Request<DeregisterRequest>,
    ) -> Result<Response<DeregisterResponse>, Status> {
        self.rpc.deregister_staked_relayer().await?;
        Ok(Response::new(DeregisterResponse {}))
    }
}
