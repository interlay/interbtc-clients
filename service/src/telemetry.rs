use std::time::Duration;

use crate::Error;
use hyper::{client::HttpConnector, Body, Client, Method, Request, StatusCode};
use hyper_tls::HttpsConnector;
use polkabtc_telemetry::{ClientInfo, Message, Payload};
use runtime::InterBtcSigner;
use sp_core::sr25519::Pair;
use tokio::time;

const TELEMETRY_PERIOD: Duration = Duration::from_secs(3600);

/// Wrapper over a HTTPS enabled Hyper client, with the
/// ability to sign outgoing messages.
pub(crate) struct TelemetryClient {
    uri: String,
    client: Client<HttpsConnector<HttpConnector>>,
    pair: Pair,
}

impl TelemetryClient {
    pub(crate) fn new(uri: String, signer: InterBtcSigner) -> Self {
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, Body>(https);

        let pair = signer.signer().clone();

        Self { uri, client, pair }
    }

    pub(crate) async fn update(&self, name: &str, version: &str) -> Result<(), Error> {
        let payload = Payload::UpdateClient(ClientInfo {
            name: name.to_string(),
            version: version.to_string(),
        });
        let message = Message::from_payload_and_signer(payload, &self.pair);

        let request = Request::builder()
            .method(Method::POST)
            .uri(&self.uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&message)?))?;
        let response = self.client.request(request).await?;

        if response.status() != StatusCode::OK {
            Err(Error::InvalidResponse)
        } else {
            Ok(())
        }
    }
}

/// Run recurring update to telemetry service.
pub(crate) async fn do_update(telemetry_client: &TelemetryClient, name: &str, version: &str) {
    let mut interval = time::interval(TELEMETRY_PERIOD);

    loop {
        interval.tick().await;
        tracing::info!("Updating telemetry");
        if let Err(err) = telemetry_client.update(name, version).await {
            tracing::error!("Failed to update telemetry: {}", err);
        }
    }
}
