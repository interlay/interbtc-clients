use crate::Error;
use esplora_btc_api::models::Transaction;

const ELECTRS_TRANSACTIONS_PER_PAGE: usize = 25;

async fn get(base_path: &str, url: &str) -> Result<String, Error> {
    let response = reqwest::get(format!("{}/{}", base_path, url)).await?;
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        Err(Error::ElectrsQueryFailed)
    } else {
        Ok(response.text().await?)
    }
}

// the esplora_btc_api lib breaks on these two because it tries to serde_json::from_str on a plain string value
pub async fn get_tx_hex(base_path: &str, tx_id: &str) -> Result<String, Error> {
    get(base_path, &format!("tx/{}/hex", tx_id)).await
}

pub async fn get_tx_merkle_block_proof(base_path: &str, tx_id: &str) -> Result<String, Error> {
    get(base_path, &format!("tx/{}/merkleblock-proof", tx_id)).await
}

// and it doesn't currently support the paged api call
pub async fn get_address_tx_history_full(base_path: &str, address: &str) -> Result<Vec<Transaction>, Error> {
    let mut last_seen_txid = "".to_owned();
    let mut ret = Vec::<Transaction>::default();
    loop {
        let mut transactions: Vec<Transaction> =
            serde_json::from_str(&get(base_path, &format!("address/{}/txs/chain/{}", address, last_seen_txid)).await?)?;
        let page_size = transactions.len();
        last_seen_txid = transactions.last().map_or("", |tx| &tx.txid).to_owned();
        ret.append(&mut transactions);
        if page_size < ELECTRS_TRANSACTIONS_PER_PAGE {
            // no further pages
            break;
        }
    }
    Ok(ret)
}
