use crate::rpc::Error as PolkaError;
use crate::rpc::Provider as PolkaRPC;
use crate::Error;
use runtime::{ErrorCode, StatusCode};
use sp_core::crypto::Ss58Codec;
use sp_core::H160;

use tonic::{Code, Request, Response, Status};

pub use polkabtc::staked_relayer_server::StakedRelayer;
pub use polkabtc::staked_relayer_server::StakedRelayerServer;
use polkabtc::ErrorCode as UserErrorCode;
use polkabtc::StatusCode as UserStatusCode;
use polkabtc::{DeregisterRequest, DeregisterResponse};
use polkabtc::{GetAddressRequest, GetAddressResponse};
use polkabtc::{GetBestBlockRequest, GetBestBlockResponse};
use polkabtc::{GetExchangeRateRequest, GetExchangeRateResponse};
use polkabtc::{GetStatusRequest, GetStatusResponse};
use polkabtc::{GetStatusUpdateRequest, GetStatusUpdateResponse};
use polkabtc::{GetVaultRequest, GetVaultResponse};
use polkabtc::{RegisterRequest, RegisterResponse};
use polkabtc::{RegisterVaultRequest, RegisterVaultResponse};
use polkabtc::{SuggestStatusUpdateRequest, SuggestStatusUpdateResponse};

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

fn deserialize_status_code(status: StatusCode) -> i32 {
    match status {
        StatusCode::Running => UserStatusCode::Running as i32,
        StatusCode::Error => UserStatusCode::Error as i32,
        StatusCode::Shutdown => UserStatusCode::Shutdown as i32,
    }
}

fn serialize_status_code(code: i32) -> Result<StatusCode, Status> {
    if let Some(status) = UserStatusCode::from_i32(code) {
        Ok(match status {
            UserStatusCode::Running => StatusCode::Running,
            UserStatusCode::Error => StatusCode::Error,
            UserStatusCode::Shutdown => StatusCode::Shutdown,
        })
    } else {
        Err(Status::new(
            Code::InvalidArgument,
            Error::UnknownStatusCode.to_string(),
        ))
    }
}

fn serialize_error_code(code: i32) -> Result<Option<ErrorCode>, Status> {
    if let Some(err_code) = UserErrorCode::from_i32(code) {
        Ok(match err_code {
            UserErrorCode::None => None,
            UserErrorCode::NoDataBtcRelay => Some(ErrorCode::NoDataBTCRelay),
            UserErrorCode::InvalidBtcRelay => Some(ErrorCode::InvalidBTCRelay),
            UserErrorCode::Liquidation => Some(ErrorCode::Liquidation),
            UserErrorCode::OracleOffline => Some(ErrorCode::OracleOffline),
        })
    } else {
        Err(Status::new(
            Code::InvalidArgument,
            Error::UnknownErrorCode.to_string(),
        ))
    }
}

fn btc_address_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<H160, Status> {
    let slice = bytes.as_ref();
    if slice.len() != 20 {
        return Err(Status::new(
            Code::InvalidArgument,
            Error::InvalidBtcAddress.to_string(),
        ));
    }
    let mut result = [0u8; 20];
    result.copy_from_slice(slice);
    Ok(result.into())
}

#[tonic::async_trait]
impl StakedRelayer for Service {
    async fn get_address(
        &self,
        _request: Request<GetAddressRequest>,
    ) -> Result<Response<GetAddressResponse>, Status> {
        Ok(Response::new(GetAddressResponse {
            address: self.rpc.get_address().await.to_ss58check(),
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
            status: deserialize_status_code(self.rpc.get_parachain_status().await?),
        }))
    }

    async fn get_status_update(
        &self,
        request: Request<GetStatusUpdateRequest>,
    ) -> Result<Response<GetStatusUpdateResponse>, Status> {
        let update = self.rpc.get_status_update(request.into_inner().id).await?;
        Ok(Response::new(GetStatusUpdateResponse {
            new_status_code: deserialize_status_code(update.new_status_code),
            old_status_code: deserialize_status_code(update.old_status_code),
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
        let (rate, time, _delay) = self.rpc.get_exchange_rate_info().await?;
        Ok(Response::new(GetExchangeRateResponse { rate, time }))
    }

    async fn suggest_status_update(
        &self,
        request: Request<SuggestStatusUpdateRequest>,
    ) -> Result<Response<SuggestStatusUpdateResponse>, Status> {
        let message = request.into_inner();
        self.rpc
            .suggest_status_update(
                message.deposit.into(),
                serialize_status_code(message.status_code)?,
                serialize_error_code(message.add_error)?,
                serialize_error_code(message.remove_error)?,
            )
            .await?;
        Ok(Response::new(SuggestStatusUpdateResponse {}))
    }

    async fn register_vault(
        &self,
        request: Request<RegisterVaultRequest>,
    ) -> Result<Response<RegisterVaultResponse>, Status> {
        let message = request.into_inner();
        self.rpc
            .register_vault(
                message.collateral.into(),
                btc_address_from_bytes(message.address)?,
            )
            .await?;
        Ok(Response::new(RegisterVaultResponse {}))
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
