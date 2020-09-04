use crate::rpc::Provider;
use crate::runtime::PolkaBTC;
use sp_core::Pair;
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::convert::Infallible;
use substrate_subxt::{system::System, Runtime};
use warp::{Filter, Rejection};

fn get_address(
    api: Provider,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("address").map(move || api.get_address())
}

async fn _get_best_block(api: Provider) -> Result<impl warp::Reply, Rejection> {
    match api.clone().get_best_block_height().await {
        Ok(height) => Ok(format!("{}", height)),
        Err(_) => Err(warp::reject::not_found()),
    }
}

fn get_best_block(
    api: Provider,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("best_block")
        .map(move || api.clone())
        .and_then(_get_best_block)
}

async fn _get_status(api: Provider) -> Result<impl warp::Reply, Rejection> {
    match api.get_parachain_status().await {
        Ok(status) => Ok(format!("{:?}", status)),
        Err(_) => Err(warp::reject::not_found()),
    }
}

fn get_status(
    api: Provider,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("status")
        .map(move || api.clone())
        .and_then(_get_status)
}

pub async fn start(api: Provider) {
    let index = warp::path::end().map(|| format!("Hello!"));

    warp::serve(
        index.or(get_address(api.clone())
            .or(get_best_block(api.clone()))
            .or(get_status(api.clone()))),
    )
    .run(([127, 0, 0, 1], 3030))
    .await;
}
