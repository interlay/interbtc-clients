use super::Error;
use hex::FromHex;
use jsonrpsee::{
    common::Params,
    http::{
        access_control::AccessControlBuilder, HttpRawServer, HttpRawServerEvent,
        HttpTransportServer,
    },
};
use log::info;
use parity_scale_codec::{Decode, Encode};
use runtime::{
    ErrorCode as PolkaBtcErrorCode, H256Le, PolkaBtcProvider, ReplacePallet, StakedRelayerPallet,
    StatusCode as PolkaBtcStatusCode,
};
use serde::{Deserialize, Deserializer};
use sp_core::crypto::Ss58Codec;
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

fn handle_resp<T: Encode>(
    resp: Result<T, Error>,
) -> Result<jsonrpsee::common::JsonValue, jsonrpsee::common::Error> {
    match resp {
        Ok(data) => Ok(format!("0x{}", hex::encode(data.encode())).into()),
        Err(_) => Err(jsonrpsee::common::Error::internal_error()),
    }
}

#[derive(Encode, Decode, Debug)]
struct ReplaceRequest {
    amount: u128,
    griefing_collateral: u128,
}

async fn _request_replace(api: &Arc<PolkaBtcProvider>, params: &Params) -> Result<(), Error> {
    println!("Received command from ui: request replace");
    match parse_params::<ReplaceRequest>(params.clone()) {
        Ok(req) => {
            println!(
                "Requesting replace for amount = {} with griefing_collateral = {}",
                req.amount, req.griefing_collateral
            );
            api.request_replace(req.amount, req.griefing_collateral)
                .await?;
            Ok(())
        }
        Err(e) => {
            println!("Error parsing params: {}", e.to_string());
            Err(e)
        }
    }
}

pub async fn start(api: Arc<PolkaBtcProvider>, addr: SocketAddr, origin: String) {
    let acl = AccessControlBuilder::new()
        .cors_allow_origin(origin.into())
        .cors_allow_header("content-type".to_string())
        .continue_on_invalid_cors(true)
        .build();

    let transport = HttpTransportServer::bind_with_acl(&addr, acl)
        .await
        .unwrap();
    let mut server = HttpRawServer::new(transport);

    loop {
        match server.next_event().await {
            HttpRawServerEvent::Request(rq) => {
                info!("Received rpc request: {:?}", rq);
                let resp = match rq.method() {
                    "request_replace" => {
                        handle_resp(_request_replace(&api, rq.params().as_ref()).await)
                    }
                    _ => Err(jsonrpsee::common::Error::method_not_found()),
                };

                rq.respond(resp);
            }
            _ => (),
        }
    }
}
