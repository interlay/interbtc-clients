use super::Error;
use futures::executor::block_on;
use hex::FromHex;
use jsonrpc_http_server::jsonrpc_core::serde_json::Value;
use jsonrpc_http_server::jsonrpc_core::Error as JsonRpcError;
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Params};
use jsonrpc_http_server::{DomainsValidation, ServerBuilder};
use parity_scale_codec::{Decode, Encode};
use runtime::ErrorCode as PolkaBtcErrorCode;
use runtime::StatusCode as PolkaBtcStatusCode;
use runtime::{H256Le, PolkaBtcProvider, SecurityPallet, StakedRelayerPallet, UtilFuncs};
use serde::{Deserialize, Deserializer};
use sp_core::crypto::Ss58Codec;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawBytes(#[serde(deserialize_with = "hex_to_buffer")] pub(crate) Vec<u8>);

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

fn _system_health(api: &Arc<PolkaBtcProvider>) -> Result<(), Error> {
    block_on(api.get_parachain_status())?;
    Ok(())
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
struct RegisterStakedRelayerJsonRpcRequest {
    stake: u128,
}

fn _register_staked_relayer(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req: RegisterStakedRelayerJsonRpcRequest = parse_params(params)?;
    Ok(block_on(api.register_staked_relayer(req.stake))?)
}

fn _deregister_staked_relayer(api: &Arc<PolkaBtcProvider>) -> Result<(), Error> {
    Ok(block_on(api.deregister_staked_relayer())?)
}

#[derive(Encode, Decode, Debug)]
struct SuggestStatusUpdateJsonRpcRequest {
    deposit: u128,
    status_code: PolkaBtcStatusCode,
    add_error: Option<PolkaBtcErrorCode>,
    remove_error: Option<PolkaBtcErrorCode>,
    block_hash: Option<H256Le>,
    message: String,
}

fn _suggest_status_update(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req: SuggestStatusUpdateJsonRpcRequest = parse_params(params)?;
    Ok(block_on(api.suggest_status_update(
        req.deposit,
        req.status_code,
        req.add_error,
        req.remove_error,
        req.block_hash,
        req.message,
    ))?)
}

#[derive(Encode, Decode, Debug)]
struct VoteOnStatusUpdateJsonRpcRequest {
    pub status_update_id: u64,
    pub approve: bool,
}

fn _vote_on_status_update(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req: VoteOnStatusUpdateJsonRpcRequest = parse_params(params)?;
    Ok(block_on(
        api.vote_on_status_update(req.status_update_id, req.approve),
    )?)
}

pub async fn start(api: Arc<PolkaBtcProvider>, addr: SocketAddr, origin: String) {
    let mut io = IoHandler::default();
    {
        let api = api.clone();
        io.add_method("system_health", move |_| handle_resp(_system_health(&api)));
    }
    {
        let api = api.clone();
        io.add_method("account_id", move |_| handle_resp(_account_id(&api)));
    }
    {
        let api = api.clone();
        io.add_method("register_staked_relayer", move |params| {
            handle_resp(_register_staked_relayer(&api, params))
        });
    }
    {
        let api = api.clone();
        io.add_method("deregister_staked_relayer", move |_| {
            handle_resp(_deregister_staked_relayer(&api))
        });
    }
    {
        let api = api.clone();
        io.add_method("suggest_status_update", move |params| {
            handle_resp(_suggest_status_update(&api, params))
        });
    }
    {
        let api = api.clone();
        io.add_method("vote_on_status_update", move |params| {
            handle_resp(_vote_on_status_update(&api, params))
        });
    }

    let server = ServerBuilder::new(io)
        .health_api(("/health", "system_health"))
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
