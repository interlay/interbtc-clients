use crate::rpc::Provider;
use log::error;
use sp_core::crypto::Ss58Codec;
use warp::{Filter, Rejection};

fn get_address(
    api: Provider,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("address").map(move || api.get_address().to_ss58check())
}

async fn _get_best_block(api: Provider) -> Result<impl warp::Reply, Rejection> {
    match api.clone().get_best_block_height().await {
        Ok(height) => Ok(format!("{}", height)),
        Err(_) => Err(warp::reject::reject()),
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
        Err(_) => Err(warp::reject::reject()),
    }
}

fn get_status(
    api: Provider,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("status")
        .map(move || api.clone())
        .and_then(_get_status)
}

async fn _post_register_staked_relayer(
    (api, stake): (Provider, u128),
) -> Result<impl warp::Reply, Rejection> {
    match api.register_staked_relayer(stake).await {
        Ok(_) => Ok(format!("Done!")),
        Err(e) => {
            error!("{}", e.to_string());
            Err(warp::reject::reject())
        }
    }
}

fn post_register_staked_relayer(
    api: Provider,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("register" / u128)
        .and(warp::post())
        .map(move |stake| (api.clone(), stake))
        .and_then(_post_register_staked_relayer)
}

async fn _post_deregister_staked_relayer(api: Provider) -> Result<impl warp::Reply, Rejection> {
    match api.deregister_staked_relayer().await {
        Ok(_) => Ok(format!("Done!")),
        Err(e) => {
            error!("{}", e.to_string());
            Err(warp::reject::reject())
        }
    }
}

fn post_deregister_staked_relayer(
    api: Provider,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("deregister")
        .and(warp::post())
        .map(move || api.clone())
        .and_then(_post_deregister_staked_relayer)
}

pub async fn start(api: Provider) {
    let index = warp::path::end().map(|| format!("Hello!"));

    warp::serve(
        index.or(get_address(api.clone())
            .or(get_best_block(api.clone()))
            .or(get_status(api.clone()))
            // TODO: use put / delete?
            .or(post_register_staked_relayer(api.clone()))
            .or(post_deregister_staked_relayer(api.clone()))),
    )
    .run(([127, 0, 0, 1], 3030))
    .await;
}
