use crate::rpc::Error as PolkaError;
use crate::rpc::Provider as PolkaRPC;
use runtime::StatusCode;
use sp_core::crypto::Ss58Codec;

use tonic::{Code, Request, Response, Status};

pub use polkabtc::staked_relayer_server::StakedRelayer;
pub use polkabtc::staked_relayer_server::StakedRelayerServer;
// use polkabtc::status_response::Status as ParachainStatus;
use polkabtc::{DeregisterRequest, DeregisterResponse};
use polkabtc::{GetAddressRequest, GetAddressResponse};
use polkabtc::{GetBestBlockRequest, GetBestBlockResponse};
use polkabtc::{GetExchangeRateRequest, GetExchangeRateResponse};
use polkabtc::{GetStatusRequest, GetStatusResponse};
use polkabtc::{GetStatusUpdateRequest, GetStatusUpdateResponse};
use polkabtc::{GetVaultRequest, GetVaultResponse};
use polkabtc::{RegisterRequest, RegisterResponse};

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

fn serialize_status_code(status: StatusCode) -> i32 {
    // TODO: use generated types, there is some weirdness here
    match status {
        StatusCode::Running => 0,
        StatusCode::Error => 1,
        StatusCode::Shutdown => 2,
    }
}

#[tonic::async_trait]
impl StakedRelayer for Service {
    async fn get_address(
        &self,
        _request: Request<GetAddressRequest>,
    ) -> Result<Response<GetAddressResponse>, Status> {
        Ok(Response::new(GetAddressResponse {
            address: self.rpc.get_address().to_ss58check(),
        }))
    }

    async fn get_best_block(
        &self,
        _request: Request<GetBestBlockRequest>,
    ) -> Result<Response<GetBestBlockResponse>, Status> {
        Ok(Response::new(GetBestBlockResponse {
            height: self.rpc.get_best_block_height().await?,
        }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        Ok(Response::new(GetStatusResponse {
            status: serialize_status_code(self.rpc.get_parachain_status().await?),
        }))
    }

    async fn get_status_update(
        &self,
        request: Request<GetStatusUpdateRequest>,
    ) -> Result<Response<GetStatusUpdateResponse>, Status> {
        let update = self.rpc.get_status_update(request.into_inner().id).await?;
        Ok(Response::new(GetStatusUpdateResponse {
            new_status_code: serialize_status_code(update.new_status_code),
            old_status_code: serialize_status_code(update.old_status_code),
            block_number: update.time.into(),
            proposer: update.proposer.to_string(),
        }))
    }

    async fn get_vault(
        &self,
        request: Request<GetVaultRequest>,
    ) -> Result<Response<GetVaultResponse>, Status> {
        let vault = self.rpc.get_vault(request.into_inner().id).await?;
        Ok(Response::new(GetVaultResponse {
            btc_address: vault.btc_address.to_string(),
        }))
    }

    async fn get_exchange_rate(
        &self,
        _request: Request<GetExchangeRateRequest>,
    ) -> Result<Response<GetExchangeRateResponse>, Status> {
        let (rate, time) = self.rpc.get_exchange_rate_info().await?;
        Ok(Response::new(GetExchangeRateResponse { rate, time }))
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
