use crate::Error;
use futures::executor::block_on;
use hex::FromHex;
use jsonrpc_http_server::jsonrpc_core::serde_json::Value;
use jsonrpc_http_server::jsonrpc_core::Error as JsonRpcError;
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Params};
use jsonrpc_http_server::{DomainsValidation, ServerBuilder};
use parity_scale_codec::{Decode, Encode};
use runtime::{PolkaBtcProvider, SecurityPallet};
use serde::{Deserialize, Deserializer};
use std::net::SocketAddr;
use std::sync::Arc;

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

fn _system_health(api: &Arc<PolkaBtcProvider>) -> Result<(), Error> {
    block_on(api.get_parachain_status())?;
    Ok(())
}

#[derive(Encode, Decode, Debug)]
struct FundAccountJsonRpcRequest {
    pub account_id: String,
    pub amount: u128,
}

// TODO: transfer DOT from configured account
fn _fund_account(api: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req: FundAccountJsonRpcRequest = parse_params(params)?;
    // Ok(block_on(
    //     api.transfer_dot(req.account_id, req.amount),
    // )?)
    Ok(())
}

pub async fn start(api: Arc<PolkaBtcProvider>, addr: SocketAddr, origin: String) {
    let mut io = IoHandler::default();
    {
        let api = api.clone();
        io.add_method("system_health", move |_| handle_resp(_system_health(&api)));
    }
    {
        let api = api.clone();
        io.add_method("fund_account", move |params| {
            handle_resp(_fund_account(&api, params))
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
