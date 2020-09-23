use log::error;
use parity_scale_codec::{Decode, Encode};
use runtime::ErrorCode as PolkaBtcErrorCode;
use runtime::StatusCode as PolkaBtcStatusCode;
use runtime::{PolkaBtcProvider, PolkaBtcStatusUpdate, SecurityPallet, StakedRelayerPallet};
use sp_core::crypto::Ss58Codec;
use std::convert::Infallible;
use std::sync::Arc;
use warp::Buf;
use warp::{http::Response, http::StatusCode, hyper::Body, Filter, Rejection, Reply};

fn decode_bytes<B: Buf, T: Decode>(buf: B) -> Result<T, Rejection> {
    Decode::decode(&mut buf.bytes()).map_err(|_| warp::reject::reject())
}

fn decode<T: Decode + Send>() -> impl Filter<Extract = (T,), Error = Rejection> + Copy {
    warp::any()
        .and(warp::filters::body::aggregate())
        .and_then(|buf| async move { decode_bytes(buf) })
}

pub fn encode<T: Encode>(val: &T) -> ReplyBytes {
    ReplyBytes(Encode::encode(val))
}

pub struct ReplyBytes(Vec<u8>);

impl Reply for ReplyBytes {
    #[inline]
    fn into_response(self) -> Response<Body> {
        let res = Response::new(self.0.into());
        res
    }
}

#[derive(Encode, Decode, Debug)]
struct GetAddressResponse {
    address: String,
}

async fn _get_address(api: Arc<PolkaBtcProvider>) -> Result<impl Reply, Infallible> {
    Ok(encode(&GetAddressResponse {
        address: api.get_address().await.to_ss58check(),
    }))
}

fn get_address(
    api: Arc<PolkaBtcProvider>,
) -> impl Filter<Extract = impl Reply, Error = warp::Rejection> + Clone {
    warp::path!("address")
        .map(move || api.clone())
        .and_then(_get_address)
}

#[derive(Encode, Decode, Debug)]
struct GetParachainStatusResponse {
    status: PolkaBtcStatusCode,
}

async fn _get_parachain_status(api: Arc<PolkaBtcProvider>) -> Result<impl Reply, Rejection> {
    match api.get_parachain_status().await {
        Ok(status) => Ok(encode(&GetParachainStatusResponse { status })),
        Err(e) => {
            error!("{}", e.to_string());
            Err(warp::reject::reject())
        }
    }
}

fn get_parachain_status(
    api: Arc<PolkaBtcProvider>,
) -> impl Filter<Extract = impl Reply, Error = warp::Rejection> + Clone {
    warp::path!("parachain-status")
        .map(move || api.clone())
        .and_then(_get_parachain_status)
}

#[derive(Encode, Decode, Debug)]
struct GetStatusUpdateResponse {
    status: PolkaBtcStatusUpdate,
}

async fn _get_status_update(
    (api, id): (Arc<PolkaBtcProvider>, u64),
) -> Result<impl Reply, Rejection> {
    match api.get_status_update(id).await {
        Ok(status) => Ok(encode(&GetStatusUpdateResponse { status })),
        Err(e) => {
            error!("{}", e.to_string());
            Err(warp::reject::reject())
        }
    }
}

fn get_status_update(
    api: Arc<PolkaBtcProvider>,
) -> impl Filter<Extract = impl Reply, Error = warp::Rejection> + Clone {
    warp::path!("status-update" / u64)
        .map(move |id| (api.clone(), id))
        .and_then(_get_status_update)
}

#[derive(Encode, Decode, Debug)]
struct PostRegisterStakedRelayerRequest {
    stake: u128,
}

async fn _post_register_staked_relayer(
    (api, body): (Arc<PolkaBtcProvider>, PostRegisterStakedRelayerRequest),
) -> Result<impl Reply, Rejection> {
    match api.register_staked_relayer(body.stake).await {
        Ok(_) => Ok(warp::http::StatusCode::OK),
        Err(e) => {
            error!("{}", e.to_string());
            Err(warp::reject::reject())
        }
    }
}

fn post_register_staked_relayer(
    api: Arc<PolkaBtcProvider>,
) -> impl Filter<Extract = impl Reply, Error = warp::Rejection> + Clone {
    warp::path!("register-staked-relayer")
        .and(warp::post())
        .and(decode::<PostRegisterStakedRelayerRequest>())
        .map(move |body| (api.clone(), body))
        .and_then(_post_register_staked_relayer)
}

async fn _post_deregister_staked_relayer(
    api: Arc<PolkaBtcProvider>,
) -> Result<impl Reply, Rejection> {
    match api.deregister_staked_relayer().await {
        Ok(_) => Ok(warp::http::StatusCode::OK),
        Err(e) => {
            error!("{}", e.to_string());
            Err(warp::reject::reject())
        }
    }
}

fn post_deregister_staked_relayer(
    api: Arc<PolkaBtcProvider>,
) -> impl Filter<Extract = impl Reply, Error = warp::Rejection> + Clone {
    warp::path!("deregister-staked-relayer")
        .and(warp::post())
        .map(move || api.clone())
        .and_then(_post_deregister_staked_relayer)
}

#[derive(Encode, Decode, Debug)]
struct PostSuggestStatusUpdateRequest {
    deposit: u128,
    status_code: PolkaBtcStatusCode,
    add_error: Option<PolkaBtcErrorCode>,
    remove_error: Option<PolkaBtcErrorCode>,
}

async fn _post_suggest_status_update(
    (api, body): (Arc<PolkaBtcProvider>, PostSuggestStatusUpdateRequest),
) -> Result<impl Reply, Rejection> {
    println!("{:?}", body);
    match api
        .suggest_status_update(
            body.deposit,
            body.status_code,
            body.add_error,
            body.remove_error,
        )
        .await
    {
        Ok(_) => Ok(warp::http::StatusCode::CREATED),
        Err(e) => {
            error!("{}", e.to_string());
            Err(warp::reject::reject())
        }
    }
}

fn post_suggest_status_update(
    api: Arc<PolkaBtcProvider>,
) -> impl Filter<Extract = impl Reply, Error = warp::Rejection> + Clone {
    warp::path!("suggest-status-update")
        .and(warp::post())
        .and(decode::<PostSuggestStatusUpdateRequest>())
        .map(move |body| (api.clone(), body))
        .and_then(_post_suggest_status_update)
}

pub async fn start(api: Arc<PolkaBtcProvider>) {
    let index = warp::path::end()
        .map(warp::reply)
        .map(|reply| warp::reply::with_status(reply, StatusCode::INTERNAL_SERVER_ERROR));

    warp::serve(
        index.or(get_address(api.clone())
            .or(get_parachain_status(api.clone()))
            .or(get_status_update(api.clone()))
            .or(post_register_staked_relayer(api.clone()))
            .or(post_deregister_staked_relayer(api.clone()))
            .or(post_suggest_status_update(api.clone()))),
    )
    .run(([127, 0, 0, 1], 3030))
    .await;
}
