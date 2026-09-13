use anchor_codec::hex;
use base64::prelude::*;
use serde::Deserialize;
use std::time::Duration;
use tendermint::block::signed_header::SignedHeader;

use crate::RpcError;

// The literal `"` characters are required by CometBFT's RPC server.
const IDENTITY_QUERY_PATH: &str = "\"/identity\"";
const IDENTITY_HISTORY_QUERY_PATH: &str = "\"/identity/history\"";

pub struct RpcClient {
    base_urls: Vec<String>,
    client: reqwest::Client,
}

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    result: Option<T>,
    error: Option<NodeError>,
}

#[derive(Debug, Deserialize)]
struct NodeError {
    message: String,
    #[serde(default)]
    data: String,
}

pub struct AbciInfo {
    pub height: u64,
    pub app_hash: Option<[u8; 32]>,
}

#[derive(Debug, Deserialize)]
struct RawAbciInfo {
    last_block_height: String,
    #[serde(default)]
    last_block_app_hash: String,
}

pub struct AbciQueryResponse {
    pub code: u32,
    pub log: String,
    pub value: Vec<u8>,
    pub proof: Option<Vec<u8>>,
    pub height: u64,
}

#[derive(Debug, Deserialize)]
struct RawAbciQueryResponse {
    code: u32,
    #[serde(default)]
    log: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(rename = "proofOps", default)]
    proof_ops: Option<RawProofOps>,
    height: String,
}

#[derive(Debug, Deserialize)]
struct RawProofOps {
    ops: Vec<RawProofOp>,
}

#[derive(Debug, Deserialize)]
struct RawProofOp {
    #[serde(default)]
    data: String,
}

pub struct TxOutcome {
    pub code: u32,
    pub log: String,
}

pub struct BroadcastTxCommitResponse {
    pub check_tx: TxOutcome,
    pub tx_result: TxOutcome,
    pub height: u64,
}

#[derive(Debug, Deserialize)]
struct RawTxOutcome {
    code: u32,
    #[serde(default)]
    log: String,
}

#[derive(Debug, Deserialize)]
struct RawBroadcastTxCommitResponse {
    check_tx: RawTxOutcome,
    tx_result: RawTxOutcome,
    height: String,
}

#[derive(Debug, Deserialize)]
struct RawCommitResponse {
    signed_header: SignedHeader,
    // `canonical` is intentionally ignored: verification below checks real
    // signatures over each vote's own sign bytes.
}

impl RpcClient {
    /// Creates a client talking to a single RPC endpoint.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_urls: vec![base_url.into()],
            client: http_client(),
        }
    }

    /// Creates a client backed by multiple RPC endpoints. Each request tries them in a random
    /// order and returns the first success.
    pub fn new_pool(
        base_urls: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, RpcError> {
        let base_urls: Vec<String> = base_urls.into_iter().map(Into::into).collect();

        if base_urls.is_empty() {
            return Err(RpcError::NoEndpoints);
        }

        Ok(Self {
            base_urls,
            client: http_client(),
        })
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        query: &[(&str, String)],
    ) -> Result<(String, T), RpcError> {
        self.with_endpoint(async |base_url| {
            self.get_from(base_url, method, query)
                .await
                .map(|value| (base_url.to_string(), value))
        })
        .await
    }

    async fn with_endpoint<T>(
        &self,
        mut attempt: impl AsyncFnMut(&str) -> Result<T, RpcError>,
    ) -> Result<T, RpcError> {
        use rand::seq::SliceRandom;

        let mut order: Vec<&String> = self.base_urls.iter().collect();
        order.shuffle(&mut rand::rng());

        let mut last_error = None;

        for base_url in order {
            match attempt(base_url).await {
                Ok(value) => return Ok(value),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.expect("base_urls is non-empty, checked at construction"))
    }

    async fn get_from<T: serde::de::DeserializeOwned>(
        &self,
        base_url: &str,
        method: &str,
        query: &[(&str, String)],
    ) -> Result<T, RpcError> {
        let url = format!("{}/{method}", base_url.trim_end_matches('/'));

        let text = self
            .client
            .get(&url)
            .query(query)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|source| RpcError::Http {
                url: url.clone(),
                source: Box::new(source),
            })?
            .text()
            .await
            .map_err(|source| RpcError::Http {
                url: url.clone(),
                source: Box::new(source),
            })?;

        let envelope: Envelope<T> =
            serde_json::from_str(&text).map_err(|source| RpcError::Json {
                url: url.clone(),
                source,
            })?;

        match envelope {
            Envelope {
                result: Some(result),
                ..
            } => Ok(result),
            Envelope {
                error: Some(error), ..
            } => Err(RpcError::Node {
                url,
                message: if error.data.is_empty() {
                    error.message
                } else {
                    format!("{}: {}", error.message, error.data)
                },
            }),
            Envelope { .. } => Err(RpcError::Node {
                url,
                message: "empty response".to_string(),
            }),
        }
    }

    /// Returns the node's committed height and app hash.
    pub async fn abci_info(&self) -> Result<AbciInfo, RpcError> {
        self.with_endpoint(async |base_url| self.abci_info_from(base_url).await)
            .await
    }

    async fn abci_info_from(&self, base_url: &str) -> Result<AbciInfo, RpcError> {
        #[derive(Deserialize)]
        struct Wrapper {
            response: RawAbciInfo,
        }

        let raw: Wrapper = self.get_from(base_url, "abci_info", &[]).await?;
        let raw = raw.response;
        let height = raw
            .last_block_height
            .parse()
            .map_err(|_| RpcError::InvalidHeight(raw.last_block_height.clone()))?;

        let app_hash = if raw.last_block_app_hash.is_empty() {
            None
        } else {
            Some(Self::decode_root(base_url, &raw.last_block_app_hash)?)
        };

        Ok(AbciInfo { height, app_hash })
    }

    fn decode_root(url: &str, base64: &str) -> Result<[u8; 32], RpcError> {
        let bytes = Self::decode_base64(url, base64)?;
        let len = bytes.len();

        bytes.try_into().map_err(|_| RpcError::Base64 {
            url: url.to_string(),
            source: base64::DecodeError::InvalidLength(len),
        })
    }

    fn decode_base64(url: &str, value: &str) -> Result<Vec<u8>, RpcError> {
        BASE64_STANDARD
            .decode(value)
            .map_err(|source| RpcError::Base64 {
                url: url.to_string(),
                source,
            })
    }

    /// Queries an identity's raw state at `height`, optionally with a Merkle proof.
    pub async fn abci_query(
        &self,
        identity_id: [u8; 32],
        height: u64,
        prove: bool,
    ) -> Result<AbciQueryResponse, RpcError> {
        self.abci_query_raw(IDENTITY_QUERY_PATH, &identity_id, height, prove)
            .await
    }

    /// Queries a page of an identity's raw event log, starting at sequence `from`.
    pub async fn abci_history(
        &self,
        identity_id: [u8; 32],
        from: u64,
        limit: u32,
    ) -> Result<AbciQueryResponse, RpcError> {
        let mut data = [0; 44];
        data[..32].copy_from_slice(&identity_id);
        data[32..40].copy_from_slice(&from.to_be_bytes());
        data[40..].copy_from_slice(&limit.to_be_bytes());

        self.abci_query_raw(IDENTITY_HISTORY_QUERY_PATH, &data, 0, false)
            .await
    }

    async fn abci_query_raw(
        &self,
        path: &str,
        data: &[u8],
        height: u64,
        prove: bool,
    ) -> Result<AbciQueryResponse, RpcError> {
        self.with_endpoint(async |base_url| {
            self.abci_query_raw_from(base_url, path, data, height, prove)
                .await
        })
        .await
    }

    async fn abci_query_raw_from(
        &self,
        base_url: &str,
        path: &str,
        data: &[u8],
        height: u64,
        prove: bool,
    ) -> Result<AbciQueryResponse, RpcError> {
        #[derive(Deserialize)]
        struct Wrapper {
            response: RawAbciQueryResponse,
        }

        let query = [
            ("path", path.to_string()),
            ("data", format!("0x{}", hex::encode(data))),
            ("height", height.to_string()),
            ("prove", prove.to_string()),
        ];

        let raw: Wrapper = self.get_from(base_url, "abci_query", &query).await?;
        let raw = raw.response;

        let value = raw
            .value
            .filter(|value| !value.is_empty())
            .map(|value| Self::decode_base64(base_url, &value))
            .transpose()?
            .unwrap_or_default();

        let proof = raw
            .proof_ops
            .and_then(|ops| ops.ops.into_iter().next())
            .map(|op| Self::decode_base64(base_url, &op.data))
            .transpose()?;

        let height = raw
            .height
            .parse()
            .map_err(|_| RpcError::InvalidHeight(raw.height))?;

        Ok(AbciQueryResponse {
            code: raw.code,
            log: raw.log,
            value,
            proof,
            height,
        })
    }

    /// Broadcasts a transaction and waits for it to be checked and committed. The response carries
    /// separate codes for check_tx and tx_result because mempool admission and execution are
    /// distinct phases; a transaction can pass one and fail the other.
    pub async fn broadcast_tx_commit(
        &self,
        tx: &[u8],
    ) -> Result<BroadcastTxCommitResponse, RpcError> {
        let query = [("tx", format!("0x{}", hex::encode(tx)))];
        let (_url, raw): (String, RawBroadcastTxCommitResponse) =
            self.get("broadcast_tx_commit", &query).await?;

        let height = raw
            .height
            .parse()
            .map_err(|_| RpcError::InvalidHeight(raw.height))?;

        Ok(BroadcastTxCommitResponse {
            check_tx: TxOutcome {
                code: raw.check_tx.code,
                log: raw.check_tx.log,
            },
            tx_result: TxOutcome {
                code: raw.tx_result.code,
                log: raw.tx_result.log,
            },
            height,
        })
    }

    async fn signed_header_from(
        &self,
        base_url: &str,
        height: Option<u64>,
    ) -> Result<SignedHeader, RpcError> {
        let response: RawCommitResponse = match height {
            Some(height) => {
                let query = [("height", height.to_string())];

                self.get_from(base_url, "commit", &query).await?
            }
            None => self.get_from(base_url, "commit", &[]).await?,
        };

        Ok(response.signed_header)
    }

    pub(crate) async fn identity_state_at_latest_verifiable_height(
        &self,
        identity_id: [u8; 32],
    ) -> Result<(SignedHeader, AbciQueryResponse), RpcError> {
        self.with_endpoint(async |base_url| {
            let signed_header = self.signed_header_from(base_url, None).await?;
            let header_height = signed_header.header.height.value();

            let state_height = header_height
                .checked_sub(1)
                .filter(|height| *height > 0)
                .ok_or(RpcError::NoVerifiableApplicationHeight)?;

            let response = self
                .abci_query_raw_from(
                    base_url,
                    IDENTITY_QUERY_PATH,
                    &identity_id,
                    state_height,
                    true,
                )
                .await?;

            if response.height != state_height {
                return Err(RpcError::UnexpectedQueryHeight {
                    expected: state_height,
                    actual: response.height,
                });
            }

            Ok((signed_header, response))
        })
        .await
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .expect("reqwest client configuration is valid")
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use mockito::{Matcher, Server};
    use serde_json::json;

    use super::*;

    fn commit_response(header_height: u64) -> Result<String> {
        let mut signed_header: serde_json::Value =
            serde_json::from_str(include_str!("../../../vectors/signed-header.json"))?;
        signed_header["header"]["height"] = header_height.to_string().into();
        signed_header["commit"]["height"] = header_height.to_string().into();
        if header_height == 1 {
            signed_header["header"]["last_block_id"] = serde_json::Value::Null;
        }

        Ok(json!({
            "jsonrpc": "2.0",
            "id": -1,
            "result": {
                "signed_header": signed_header,
                "canonical": false
            }
        })
        .to_string())
    }

    fn query_response(height: u64) -> String {
        json!({
            "jsonrpc": "2.0",
            "id": -1,
            "result": {
                "response": {
                    "code": 0,
                    "log": "",
                    "value": "",
                    "proofOps": { "ops": [{ "data": "" }] },
                    "height": height.to_string()
                }
            }
        })
        .to_string()
    }

    #[test]
    fn new_pool_rejects_an_empty_endpoint_list() {
        let result = RpcClient::new_pool(Vec::<String>::new());

        assert!(matches!(result, Err(RpcError::NoEndpoints)));
    }

    #[test]
    fn new_pool_accepts_one_or_more_endpoints() {
        let client = RpcClient::new_pool(["http://127.0.0.1:26657", "http://127.0.0.1:26667"]);

        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn latest_verifiable_state_rejects_a_header_at_height_one() -> Result<()> {
        let mut server = Server::new_async().await;
        let commit = server
            .mock("GET", "/commit")
            .with_body(commit_response(1)?)
            .create_async()
            .await;
        let client = RpcClient::new(server.url());

        let result = client
            .identity_state_at_latest_verifiable_height([0; 32])
            .await;

        match result {
            Err(RpcError::NoVerifiableApplicationHeight) => {}
            Err(error) => anyhow::bail!("expected no verifiable height, got: {error}"),
            Ok(_) => anyhow::bail!("height-one header unexpectedly produced a query result"),
        }

        commit.assert_async().await;

        Ok(())
    }

    #[tokio::test]
    async fn latest_verifiable_state_rejects_a_different_query_height() -> Result<()> {
        let header_height = 10;
        let mut server = Server::new_async().await;
        let commit = server
            .mock("GET", "/commit")
            .with_body(commit_response(header_height)?)
            .create_async()
            .await;
        let query = server
            .mock("GET", "/abci_query")
            .match_query(Matcher::UrlEncoded("height".into(), "9".into()))
            .with_body(query_response(header_height))
            .create_async()
            .await;
        let client = RpcClient::new(server.url());

        let result = client
            .identity_state_at_latest_verifiable_height([0; 32])
            .await;

        assert!(matches!(
            result,
            Err(RpcError::UnexpectedQueryHeight {
                expected: 9,
                actual: 10
            })
        ));
        commit.assert_async().await;
        query.assert_async().await;

        Ok(())
    }

    #[tokio::test]
    async fn latest_verifiable_state_fetches_header_and_proof_from_one_endpoint() -> Result<()> {
        let header_height = 10;
        let mut server = Server::new_async().await;
        let commit = server
            .mock("GET", "/commit")
            .with_body(commit_response(header_height)?)
            .create_async()
            .await;
        let query = server
            .mock("GET", "/abci_query")
            .match_query(Matcher::UrlEncoded("height".into(), "9".into()))
            .with_body(query_response(header_height - 1))
            .create_async()
            .await;
        let client = RpcClient::new(server.url());

        let (signed_header, response) = client
            .identity_state_at_latest_verifiable_height([0; 32])
            .await?;

        assert_eq!(signed_header.header.height.value(), header_height);
        assert_eq!(response.height, header_height - 1);
        commit.assert_async().await;
        query.assert_async().await;

        Ok(())
    }
}
