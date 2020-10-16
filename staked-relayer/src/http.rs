use super::Error;
use hex::FromHex;
use log::info;
use parity_scale_codec::{Decode, Encode};
use runtime::ErrorCode as PolkaBtcErrorCode;
use runtime::StatusCode as PolkaBtcStatusCode;
use runtime::{
    Error as RuntimeError, H256Le, PolkaBtcProvider, PolkaBtcStatusUpdate, SecurityPallet,
    StakedRelayerPallet,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use sp_core::crypto::Ss58Codec;
use std::convert::Infallible;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

impl std::convert::From<Error> for Rejection {
    fn from(_err: Error) -> Self {
        warp::reject::reject()
    }
}

#[derive(PartialEq, Debug, Clone, Deserialize, Serialize)]
pub enum Version {
    #[serde(rename = "2.0")]
    V2,
}

#[derive(Debug, Clone, Deserialize)]
struct RawBytes(#[serde(deserialize_with = "hex_to_buffer")] Vec<u8>);

#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    jsonrpc: Version,
    id: Option<String>,
    method: Methods,
    params: Option<Box<RawValue>>,
}

impl Request {
    pub fn deserialize_param<'de, T>(&'de self) -> Result<T, Error>
    where
        T: Deserialize<'de>,
    {
        match self.params.as_ref() {
            Some(params) => Ok(serde_json::from_str(params.get())?),
            None => Err(Error::ParamNotFound),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
enum Methods {
    #[serde(rename = "get_address")]
    GetAddress,
    #[serde(rename = "get_parachain_status")]
    GetParachainStatus,
    #[serde(rename = "get_status_update")]
    GetStatusUpdate,
    #[serde(rename = "register_staked_relayer")]
    RegisterStakedRelayer,
    #[serde(rename = "deregister_staked_relayer")]
    DeregisterStakedRelayer,
    #[serde(rename = "suggest_status_update")]
    SuggestStatusUpdate,
    #[serde(rename = "vote_on_status_update")]
    VoteOnStatusUpdate,
}

pub fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        Vec::from_hex(&string[2..]).map_err(|err| Error::custom(err.to_string()))
    })
}

#[derive(Serialize)]
struct Response {
    jsonrpc: Version,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(flatten)]
    content: ResponseContent,
}

impl Response {
    fn success_with<T: Encode>(id: Option<String>, data: &T) -> Self {
        Self {
            jsonrpc: Version::V2,
            id,
            content: ResponseContent::Success(Some(format!(
                "0x{}",
                hex::encode(Encode::encode(data))
            ))),
        }
    }

    fn success(id: Option<String>) -> Self {
        Self {
            jsonrpc: Version::V2,
            id,
            content: ResponseContent::Success(None),
        }
    }

    fn error(id: Option<String>, code: i32, message: String) -> Self {
        Self {
            jsonrpc: Version::V2,
            id,
            content: ResponseContent::Error(ResponseError {
                code,
                message,
                data: None,
            }),
        }
    }

    fn reply(&self) -> warp::reply::WithHeader<warp::reply::Json> {
        allow_origin(warp::reply::json(self), "*")
    }

    fn reply_error(
        id: Option<String>,
        err: RuntimeError,
    ) -> warp::reply::WithStatus<warp::reply::WithHeader<warp::reply::Json>> {
        warp::reply::with_status(
            Response::error(id, -32603, err.to_string()).reply(),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        )
    }
}

#[derive(Serialize)]
enum ResponseContent {
    #[serde(rename = "result")]
    Success(Option<String>),
    #[serde(rename = "error")]
    Error(ResponseError),
}

#[derive(Serialize)]
struct ResponseError {
    code: i32,
    message: String,
    data: Option<String>,
}

fn allow_origin<T: Reply, V>(reply: T, origin: V) -> warp::reply::WithHeader<T>
where
    warp::http::HeaderValue: TryFrom<V>,
    <warp::http::HeaderValue as TryFrom<V>>::Error: Into<warp::http::Error>,
{
    warp::reply::with_header(reply, "Access-Control-Allow-Origin", origin)
}

fn allow_headers<T: Reply, V>(reply: T, headers: V) -> warp::reply::WithHeader<T>
where
    warp::http::HeaderValue: TryFrom<V>,
    <warp::http::HeaderValue as TryFrom<V>>::Error: Into<warp::http::Error>,
{
    warp::reply::with_header(reply, "Access-Control-Allow-Headers", headers)
}

fn json_rpc() -> impl Filter<Extract = (Request,), Error = warp::Rejection> + Clone {
    warp::filters::method::post()
        .and(warp::filters::header::exact(
            "Content-Type",
            "application/json",
        ))
        .and(warp::filters::body::json::<Request>())
}

#[derive(Encode, Decode, Debug)]
struct GetAddressResponse {
    address: String,
}

async fn _get_address(
    req: Request,
    api: Arc<PolkaBtcProvider>,
) -> Result<Box<dyn Reply>, Rejection> {
    Ok(Box::new(
        Response::success_with(
            req.id,
            &GetAddressResponse {
                address: api.get_address().await.to_ss58check(),
            },
        )
        .reply(),
    ))
}

#[derive(Encode, Decode, Debug)]
struct GetParachainStatusResponse {
    status: PolkaBtcStatusCode,
}

async fn _get_parachain_status(
    req: Request,
    api: Arc<PolkaBtcProvider>,
) -> Result<Box<dyn Reply>, Rejection> {
    match api.get_parachain_status().await {
        Ok(status) => Ok(Box::new(
            Response::success_with(req.id, &GetParachainStatusResponse { status }).reply(),
        )),
        Err(e) => Ok(Box::new(Response::reply_error(req.id, e))),
    }
}

#[derive(Encode, Decode, Debug)]
struct GetStatusUpdateRequest {
    status_update_id: u64,
}

#[derive(Encode, Decode, Debug)]
struct GetStatusUpdateResponse {
    status: PolkaBtcStatusUpdate,
}

async fn _get_status_update(
    req: Request,
    api: Arc<PolkaBtcProvider>,
) -> Result<Box<dyn Reply>, Rejection> {
    let param = req.deserialize_param::<[RawBytes; 1]>()?;
    let data: GetStatusUpdateRequest =
        Decode::decode(&mut &param[0].0[..]).map_err(|err| Error::CodecError(err))?;
    match api.get_status_update(data.status_update_id).await {
        Ok(status) => Ok(Box::new(
            Response::success_with(req.id, &GetStatusUpdateResponse { status }).reply(),
        )),
        Err(e) => Ok(Box::new(Box::new(Response::reply_error(req.id, e)))),
    }
}

#[derive(Encode, Decode, Debug)]
struct RegisterStakedRelayerRequest {
    stake: u128,
}

async fn _register_staked_relayer(
    req: Request,
    api: Arc<PolkaBtcProvider>,
) -> Result<Box<dyn Reply>, Rejection> {
    let param = req.deserialize_param::<[RawBytes; 1]>()?;
    let data: RegisterStakedRelayerRequest =
        Decode::decode(&mut &param[0].0[..]).map_err(|err| Error::CodecError(err))?;
    match api.register_staked_relayer(data.stake).await {
        Ok(_) => Ok(Box::new(Response::success(req.id).reply())),
        Err(e) => Ok(Box::new(Box::new(Response::reply_error(req.id, e)))),
    }
}

async fn _deregister_staked_relayer(
    req: Request,
    api: Arc<PolkaBtcProvider>,
) -> Result<Box<dyn Reply>, Rejection> {
    match api.deregister_staked_relayer().await {
        Ok(_) => Ok(Box::new(Response::success(req.id).reply())),
        Err(e) => Ok(Box::new(Response::reply_error(req.id, e))),
    }
}

#[derive(Encode, Decode, Debug)]
struct SuggestStatusUpdateRequest {
    deposit: u128,
    status_code: PolkaBtcStatusCode,
    add_error: Option<PolkaBtcErrorCode>,
    remove_error: Option<PolkaBtcErrorCode>,
    block_hash: Option<H256Le>,
    message: String,
}

async fn _suggest_status_update(
    req: Request,
    api: Arc<PolkaBtcProvider>,
) -> Result<Box<dyn Reply>, Rejection> {
    let param = req.deserialize_param::<[RawBytes; 1]>()?;
    let data: SuggestStatusUpdateRequest =
        Decode::decode(&mut &param[0].0[..]).map_err(|err| Error::CodecError(err))?;
    match api
        .suggest_status_update(
            data.deposit,
            data.status_code,
            data.add_error,
            data.remove_error,
            data.block_hash,
            data.message,
        )
        .await
    {
        Ok(_) => Ok(Box::new(Response::success(req.id).reply())),
        Err(e) => Ok(Box::new(Box::new(Response::reply_error(req.id, e)))),
    }
}

#[derive(Encode, Decode, Debug)]
struct VoteOnStatusUpdateRequest {
    pub status_update_id: u64,
    pub approve: bool,
}

async fn _vote_on_status_update(
    req: Request,
    api: Arc<PolkaBtcProvider>,
) -> Result<Box<dyn Reply>, Rejection> {
    let param = req.deserialize_param::<[RawBytes; 1]>()?;
    let data: VoteOnStatusUpdateRequest =
        Decode::decode(&mut &param[0].0[..]).map_err(|err| Error::CodecError(err))?;
    match api
        .vote_on_status_update(data.status_update_id, data.approve)
        .await
    {
        Ok(_) => Ok(Box::new(Response::success(req.id).reply())),
        Err(e) => Ok(Box::new(Box::new(Response::reply_error(req.id, e)))),
    }
}

fn with_api(
    api: Arc<PolkaBtcProvider>,
) -> impl Filter<Extract = (Arc<PolkaBtcProvider>,), Error = Infallible> + Clone {
    warp::any().map(move || api.clone())
}

pub async fn start(api: Arc<PolkaBtcProvider>, addr: SocketAddr, origin: String) {
    let before = warp::any()
        .and(warp::filters::method::options())
        .map(move || allow_origin(warp::reply::reply(), origin.clone()))
        .map(|reply| allow_headers(reply, "*"));

    let after = warp::any().and(json_rpc()).and(with_api(api)).and_then(
        move |req: Request, api| async move {
            info!("Received rpc message: {:?}", req);
            match req.method {
                Methods::GetAddress => _get_address(req, api).await,
                Methods::GetParachainStatus => _get_parachain_status(req, api).await,
                Methods::GetStatusUpdate => _get_status_update(req, api).await,
                Methods::RegisterStakedRelayer => _register_staked_relayer(req, api).await,
                Methods::DeregisterStakedRelayer => _deregister_staked_relayer(req, api).await,
                Methods::SuggestStatusUpdate => _suggest_status_update(req, api).await,
                Methods::VoteOnStatusUpdate => _vote_on_status_update(req, api).await,
            }
        },
    );

    warp::serve(before.or(after)).run(addr).await;
}
