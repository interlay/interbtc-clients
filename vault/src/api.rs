use super::Error;
use bitcoin::BitcoinCoreApi;
use futures::executor::block_on;
use hex::FromHex;
use jsonrpc_http_server::{
    jsonrpc_core::{serde_json::Value, Error as JsonRpcError, IoHandler, Params},
    DomainsValidation, ServerBuilder,
};
use log::info;
use parity_scale_codec::{Decode, Encode};
use runtime::{BtcPublicKey, PolkaBtcProvider, ReplacePallet, UtilFuncs, VaultRegistryPallet};
use serde::{Deserialize, Deserializer};
use sp_core::crypto::Ss58Codec;
use sp_core::H256;
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
struct AccountIdJsonRpcResponse {
    account_id: String,
}

fn _account_id(api: &Arc<PolkaBtcProvider>) -> Result<AccountIdJsonRpcResponse, Error> {
    Ok(AccountIdJsonRpcResponse {
        account_id: api.get_account_id().to_ss58check(),
    })
}

#[derive(Encode, Decode, Debug)]
struct ReplaceRequestJsonRpcRequest {
    amount: u128,
    griefing_collateral: u128,
}

fn _request_replace(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<ReplaceRequestJsonRpcRequest>(params)?;
    let result = block_on(api.request_replace(req.amount, req.griefing_collateral));
    info!(
        "Requesting replace for amount = {} with griefing_collateral = {}: {:?}",
        req.amount, req.griefing_collateral, result
    );
    Ok(result.map(|_| ())?)
}

#[derive(Encode, Decode, Debug)]
struct RegisterVaultJsonRpcRequest {
    collateral: u128,
}

#[derive(Encode, Decode, Debug)]
struct RegisterVaultJsonRpcResponse {
    public_key: BtcPublicKey,
}

fn _register_vault<B: BitcoinCoreApi>(
    api: &Arc<PolkaBtcProvider>,
    btc: &Arc<B>,
    params: Params,
) -> Result<RegisterVaultJsonRpcResponse, Error> {
    let req = parse_params::<RegisterVaultJsonRpcRequest>(params)?;
    let public_key: BtcPublicKey = btc.get_new_public_key()?;
    let result = block_on(api.register_vault(req.collateral, public_key.clone()));
    info!(
        "Registering vault with bitcoind public_key {:?} and collateral = {}: {:?}",
        public_key, req.collateral, result
    );
    Ok(result.map(|_| RegisterVaultJsonRpcResponse { public_key })?)
}

#[derive(Encode, Decode, Debug)]
struct ChangeCollateralJsonRpcRequest {
    amount: u128,
}

fn _lock_additional_collateral(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<ChangeCollateralJsonRpcRequest>(params)?;
    let result = block_on(api.lock_additional_collateral(req.amount));
    info!(
        "Locking additional collateral; amount {}: {:?}",
        req.amount, result
    );
    Ok(result?)
}

fn _withdraw_collateral(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<ChangeCollateralJsonRpcRequest>(params)?;
    let result = block_on(api.withdraw_collateral(req.amount));
    info!(
        "Withdrawing collateral with amount {}: {:?}",
        req.amount, result
    );
    Ok(result?)
}

#[derive(Encode, Decode, Debug)]
struct WithdrawReplaceJsonRpcRequest {
    replace_id: H256,
}

fn _withdraw_replace(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<WithdrawReplaceJsonRpcRequest>(params)?;
    let result = block_on(api.withdraw_replace(req.replace_id));
    info!(
        "Withdrawing replace request {}: {:?}",
        req.replace_id, result
    );
    Ok(result?)
}

pub async fn start<B: BitcoinCoreApi + Send + Sync + 'static>(
    api: Arc<PolkaBtcProvider>,
    btc: Arc<B>,
    addr: SocketAddr,
    origin: String,
) {
    let mut io = IoHandler::default();
    {
        let api = api.clone();
        io.add_method("account_id", move |_| handle_resp(_account_id(&api)));
    }
    {
        let api = api.clone();
        io.add_method("request_replace", move |params| {
            handle_resp(_request_replace(&api, params))
        });
    }
    {
        let api = api.clone();
        let btc = btc.clone();
        io.add_method("register_vault", move |params| {
            handle_resp(_register_vault(&api, &btc, params))
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
