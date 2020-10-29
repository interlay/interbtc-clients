use super::Error;
use futures::executor::block_on;
use hex::FromHex;
use jsonrpc_http_server::{
    jsonrpc_core::{serde_json::Value, Error as JsonRpcError, IoHandler, Params},
    DomainsValidation, ServerBuilder,
};
use log::info;
use parity_scale_codec::{Decode, Encode};
use runtime::{PolkaBtcProvider, ReplacePallet, VaultRegistryPallet};
use serde::{Deserialize, Deserializer};
use sp_core::{H160, H256};
use std::{net::SocketAddr, sync::Arc};

#[derive(Debug, Clone, Deserialize)]
struct RawBytes(#[serde(deserialize_with = "hex_to_buffer")] Vec<u8>);

pub fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        Vec::from_hex(&string[2..]).map_err(|err| Error::custom(err.to_string()))
    })
}

fn parse_params<T: Decode>(params: Params) -> Result<T, Error> {
    let raw: [RawBytes; 1] = params.parse()?;
    let req = Decode::decode(&mut &raw[0].0[..]).map_err(Error::CodecError)?;
    Ok(req)
}

fn handle_resp<T: Encode>(resp: Result<T, Error>) -> Result<Value, JsonRpcError> {
    match resp {
        Ok(data) => Ok(format!("0x{}", hex::encode(data.encode())).into()),
        Err(_) => Err(JsonRpcError::internal_error()),
    }
}

#[derive(Encode, Decode, Debug)]
struct ReplaceRequestJsonRpcRequest {
    amount: u128,
    griefing_collateral: u128,
}

fn _request_replace(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<ReplaceRequestJsonRpcRequest>(params)?;
    info!(
        "Requesting replace for amount = {} with griefing_collateral = {}",
        req.amount, req.griefing_collateral
    );
    block_on(api.request_replace(req.amount, req.griefing_collateral))?;
    Ok(())
}

#[derive(Encode, Decode, Debug)]
struct RegisterVaultJsonRpcRequest {
    collateral: u128,
    btc_address: H160,
}

fn _register_vault(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<RegisterVaultJsonRpcRequest>(params)?;
    info!(
        "Registering vault with bitcoind address {} and collateral = {}",
        req.btc_address, req.collateral
    );
    block_on(api.register_vault(req.collateral, req.btc_address))?;
    Ok(())
}

#[derive(Encode, Decode, Debug)]
struct ChangeCollateralJsonRpcRequest {
    amount: u128,
}

fn _lock_additional_collateral(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<ChangeCollateralJsonRpcRequest>(params)?;
    info!("Locking additional collateral; amount {}", req.amount);
    Ok(block_on(api.lock_additional_collateral(req.amount))?)
}

fn _withdraw_collateral(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<ChangeCollateralJsonRpcRequest>(params)?;
    info!("Withdrawing collateral; amount {}", req.amount);
    Ok(block_on(api.withdraw_collateral(req.amount))?)
}

#[derive(Encode, Decode, Debug)]
struct SetBtcAddressJsonRpcRequest {
    address: H160,
}

fn _set_btc_address(_api: &Arc<PolkaBtcProvider>, _params: Params) -> Result<(), Error> {
    unimplemented!();
}

#[derive(Encode, Decode, Debug)]
struct WithdrawReplaceJsonRpcRequest {
    replace_id: H256,
}

fn _withdraw_replace(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<WithdrawReplaceJsonRpcRequest>(params)?;
    info!("Withdrawing replace request {}", req.replace_id);
    Ok(block_on(api.withdraw_replace(req.replace_id))?)
}

pub async fn start(api: Arc<PolkaBtcProvider>, addr: SocketAddr, origin: String) {
    let mut io = IoHandler::default();
    {
        let api = api.clone();
        io.add_method("request_replace", move |params| {
            handle_resp(_request_replace(&api, params))
        });
    }
    {
        let api = api.clone();
        io.add_method("register_vault", move |params| {
            handle_resp(_register_vault(&api, params))
        });
    }
    {
        let api = api.clone();
        io.add_method("lock_additional_collateral", move |params| {
            handle_resp(_lock_additional_collateral(&api, params))
        });
    }
    {
        let api = api.clone();
        io.add_method("withdraw_collateral", move |params| {
            handle_resp(_withdraw_collateral(&api, params))
        });
    }
    {
        let api = api.clone();
        io.add_method("set_btc_address", move |params| {
            handle_resp(_set_btc_address(&api, params))
        });
    }
    {
        let api = api.clone();
        io.add_method("withdraw_replace", move |params| {
            handle_resp(_withdraw_replace(&api, params))
        });
    }

    let server = ServerBuilder::new(io)
        .rest_api(jsonrpc_http_server::RestApi::Unsecure)
        .cors(DomainsValidation::AllowOnly(vec![origin.into()]))
        .start_http(&addr)
        .expect("Unable to start RPC server");

    tokio::task::spawn_blocking(move || {
        server.wait();
    })
    .await
    .unwrap();
}
