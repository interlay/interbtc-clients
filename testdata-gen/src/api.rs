use crate::Error;
use parity_scale_codec::Encode;

#[derive(serde::Serialize)]
struct JsonRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: [&'a str; 1],
    id: &'a str,
}

pub async fn call<T>(url: String, method: &str, params: T) -> Result<(), Error>
where
    T: Encode,
{
    let params = format!("0x{}", hex::encode(params.encode()));

    let val = JsonRequest {
        jsonrpc: "2.0",
        method,
        params: [&params],
        id: "testgen-data",
    };

    reqwest::Client::new().post(&url).json(&val).send().await?;

    Ok(())
}
