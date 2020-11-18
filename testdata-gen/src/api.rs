use crate::Error;
use hex::FromHex;
use jsonrpc_core::error::Error as JsonRpcError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Deserializer};

#[derive(serde::Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: [&'a str; 1],
    id: &'a str,
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

#[derive(serde::Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    result: Option<RawBytes>,
    error: Option<JsonRpcError>,
    #[allow(dead_code)]
    id: String,
}

pub async fn call<T, U>(url: String, method: &str, params: T) -> Result<U, Error>
where
    T: Encode,
    U: Decode,
{
    let params = format!("0x{}", hex::encode(params.encode()));

    let val = JsonRpcRequest {
        jsonrpc: "2.0",
        method,
        params: [&params],
        id: "testgen-data",
    };

    // make the request
    let result = reqwest::Client::new().post(&url).json(&val).send().await?;

    // partially parse the response
    let response = result.json::<JsonRpcResponse>().await?;

    // jsonrpc spec says that exactly one of [result, error] is defined.

    if let Some(x) = response.result {
        // decode the response
        return Ok(Decode::decode(&mut &x.0[..]).map_err(Error::CodecError)?);
    }

    if let Some(x) = response.error {
        return Err(x.into());
    }
    // either result or error should have been defined.
    Err(JsonRpcError::internal_error().into())
}
