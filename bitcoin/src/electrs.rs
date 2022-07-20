use crate::Error;

async fn get(base_path: &str, url: &str) -> Result<String, Error> {
    let response = reqwest::get(format!("{}/{}", base_path, url)).await?;
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        Err(Error::ElectrsQueryFailed)
    } else {
        Ok(response.text().await?)
    }
}

pub async fn get_tx_hex(base_path: &str, tx_id: &str) -> Result<String, Error> {
    get(base_path, &format!("tx/{}/hex", tx_id)).await
}

pub async fn get_tx_merkle_block_proof(base_path: &str, tx_id: &str) -> Result<String, Error> {
    get(base_path, &format!("tx/{}/merkleblock-proof", tx_id)).await
}
