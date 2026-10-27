//! CometBFT RPC and LCD broadcast used when gRPC resets the stream.
//!
//! The HTTP response body is kept in the error so a rejected transaction
//! shows the chain log instead of only `h2 protocol error`.

use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::proto::tendermint::abci::Event;
use cosmrs::proto::tendermint::abci::EventAttribute;
use serde_json::Value;

use crate::error::DaemonError;
use crate::tx_resp::CosmTxResponse;

const FALLBACK_GAS: u64 = 20_000_000;

pub fn is_transport_error(err: &DaemonError) -> bool {
    let text = err.to_string().to_lowercase();
    text.contains("h2")
        || text.contains("transport")
        || text.contains("connection")
        || text.contains("reset")
        || text.contains("stream")
        || text.contains("error reading a body")
}

pub async fn simulate_or_fallback(
    tx_bytes: &[u8],
    lcd_url: Option<&str>,
    grpc_error: &DaemonError,
) -> Result<u64, DaemonError> {
    println!("grpc simulate failed: {grpc_error}");
    if let Some(lcd) = lcd_url {
        match lcd_simulate(lcd, tx_bytes).await {
            Ok(gas) => {
                println!("lcd simulate gas {gas}");
                return Ok(gas);
            }
            Err(err) => {
                println!("lcd simulate failed: {err}");
                if !is_transport_error(&err) {
                    return Err(err);
                }
            }
        }
    }
    println!("using fallback gas {FALLBACK_GAS} so rpc or lcd can report the chain error");
    Ok(FALLBACK_GAS)
}

pub async fn broadcast(
    tx_bytes: &[u8],
    rpc_urls: &[String],
    lcd_url: Option<&str>,
    grpc_error: &DaemonError,
) -> Result<TxResponse, DaemonError> {
    println!("grpc broadcast failed: {grpc_error}");
    let mut errors = Vec::new();
    for url in rpc_urls {
        println!("broadcast via rpc {url}");
        match rpc_broadcast(url, tx_bytes).await {
            Ok(response) => {
                println!(
                    "rpc broadcast code {} log {}",
                    response.code, response.raw_log
                );
                return Ok(response);
            }
            Err(err) => {
                println!("rpc broadcast failed: {err}");
                errors.push(err.to_string());
            }
        }
    }
    if let Some(lcd) = lcd_url {
        println!("broadcast via lcd {lcd}");
        match lcd_broadcast(lcd, tx_bytes).await {
            Ok(response) => {
                println!(
                    "lcd broadcast code {} log {}",
                    response.code, response.raw_log
                );
                return Ok(response);
            }
            Err(err) => {
                println!("lcd broadcast failed: {err}");
                errors.push(err.to_string());
            }
        }
    }
    if errors.is_empty() {
        return Err(DaemonError::StdErr(
            "grpc broadcast failed and no rpc or lcd url is configured".into(),
        ));
    }
    Err(DaemonError::StdErr(errors.join("; ")))
}

/// Waits for `hash` over gRPC, then over the CometBFT RPC urls and the LCD.
/// Any gRPC error falls back (a dead channel can surface as "tx not found").
pub async fn find_tx_with_fallback(
    channel: tonic::transport::Channel,
    hash: &str,
    rpc_urls: &[String],
    lcd_url: Option<&str>,
) -> Result<CosmTxResponse, DaemonError> {
    let node = crate::queriers::Node::new_async(channel);
    if rpc_urls.is_empty() && lcd_url.is_none() {
        return node._find_tx(hash.to_string()).await;
    }
    // Few gRPC tries only: a broken channel would otherwise back off for minutes.
    match node._find_tx_with_retries(hash.to_string(), 3).await {
        Ok(response) => Ok(response),
        Err(err) => {
            println!("grpc tx query failed: {err}");
            find_tx(hash, rpc_urls, lcd_url).await
        }
    }
}

/// Polls the rpc urls then the lcd until the tx is in a block.
/// `CW_ORCH_HTTP_TX_WAIT_SECS` sets the wait (default 60s, polled every 3s).
pub async fn find_tx(
    hash: &str,
    rpc_urls: &[String],
    lcd_url: Option<&str>,
) -> Result<CosmTxResponse, DaemonError> {
    let mut last = None;
    let wait: u64 = std::env::var("CW_ORCH_HTTP_TX_WAIT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(60);
    for attempt in 0..(wait / 3).max(1) {
        match find_tx_once(hash, rpc_urls, lcd_url).await {
            Ok(response) => return Ok(response),
            Err(err) => {
                if rpc_urls.is_empty() && lcd_url.is_none() {
                    return Err(err);
                }
                if attempt == 0 {
                    println!("tx {hash} not found over rpc/lcd yet, retrying: {err}");
                }
                last = Some(err);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    Err(last.unwrap())
}

async fn find_tx_once(
    hash: &str,
    rpc_urls: &[String],
    lcd_url: Option<&str>,
) -> Result<CosmTxResponse, DaemonError> {
    let mut errors = Vec::new();
    for url in rpc_urls {
        println!("query tx via rpc {url}");
        match rpc_find(url, hash).await {
            Ok(response) => return Ok(response),
            Err(err) => errors.push(err.to_string()),
        }
    }
    if let Some(lcd) = lcd_url {
        println!("query tx via lcd {lcd}");
        match lcd_find(lcd, hash).await {
            Ok(response) => return Ok(response),
            Err(err) => errors.push(err.to_string()),
        }
    }
    Err(DaemonError::StdErr(if errors.is_empty() {
        format!("tx {hash} was not found and no rpc or lcd url is configured")
    } else {
        errors.join("; ")
    }))
}

async fn post_json(url: &str, body: Value) -> Result<Value, DaemonError> {
    let response = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|err| DaemonError::StdErr(format!("{url}: {err}")))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| DaemonError::StdErr(format!("{url}: {err}")))?;
    if !status.is_success() {
        return Err(DaemonError::StdErr(format!("{url} {status}: {text}")));
    }
    serde_json::from_str(&text).map_err(|err| DaemonError::StdErr(format!("{url}: {err}: {text}")))
}

async fn get_json(url: &str) -> Result<Value, DaemonError> {
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|err| DaemonError::StdErr(format!("{url}: {err}")))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| DaemonError::StdErr(format!("{url}: {err}")))?;
    if !status.is_success() {
        return Err(DaemonError::StdErr(format!("{url} {status}: {text}")));
    }
    serde_json::from_str(&text).map_err(|err| DaemonError::StdErr(format!("{url}: {err}: {text}")))
}

async fn rpc_broadcast(url: &str, tx_bytes: &[u8]) -> Result<TxResponse, DaemonError> {
    let endpoint = format!("{}/", url.trim_end_matches('/'));
    let value = post_json(
        &endpoint,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "broadcast_tx_sync",
            "params": { "tx": b64(tx_bytes) }
        }),
    )
    .await?;
    if let Some(error) = value.get("error") {
        return Err(DaemonError::StdErr(format!("rpc {url}: {error}")));
    }
    let result = value
        .get("result")
        .ok_or_else(|| DaemonError::StdErr(format!("rpc {url}: {value}")))?;
    Ok(TxResponse {
        height: result.get("height").and_then(Value::as_i64).unwrap_or(0),
        txhash: result
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        codespace: result
            .get("codespace")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        code: result.get("code").and_then(Value::as_u64).unwrap_or(0) as u32,
        data: result
            .get("data")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        raw_log: result
            .get("log")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        ..Default::default()
    })
}

async fn lcd_broadcast(url: &str, tx_bytes: &[u8]) -> Result<TxResponse, DaemonError> {
    let endpoint = format!(
        "{}/cosmos/tx/v1beta1/txs",
        url.trim_end_matches('/')
    );
    let value = post_json(
        &endpoint,
        serde_json::json!({
            "tx_bytes": b64(tx_bytes),
            "mode": "BROADCAST_MODE_SYNC"
        }),
    )
    .await?;
    let response = value
        .get("tx_response")
        .ok_or_else(|| DaemonError::StdErr(format!("lcd {url}: {value}")))?;
    Ok(tx_response_from_json(response))
}

async fn lcd_simulate(url: &str, tx_bytes: &[u8]) -> Result<u64, DaemonError> {
    let endpoint = format!(
        "{}/cosmos/tx/v1beta1/simulate",
        url.trim_end_matches('/')
    );
    let value = post_json(
        &endpoint,
        serde_json::json!({ "tx_bytes": b64(tx_bytes) }),
    )
    .await?;
    value
        .pointer("/gas_info/gas_used")
        .and_then(json_u64)
        .ok_or_else(|| DaemonError::StdErr(format!("lcd simulate {url}: {value}")))
}

async fn rpc_find(url: &str, hash: &str) -> Result<CosmTxResponse, DaemonError> {
    let endpoint = format!(
        "{}/tx?hash=0x{}&prove=false",
        url.trim_end_matches('/'),
        hash.trim_start_matches("0x")
    );
    let value = get_json(&endpoint).await?;
    if let Some(error) = value.get("error") {
        return Err(DaemonError::StdErr(format!("rpc tx {url}: {error}")));
    }
    let result = value
        .get("result")
        .ok_or_else(|| DaemonError::StdErr(format!("rpc tx {url}: {value}")))?;
    let tx_result = result.get("tx_result").unwrap_or(result);
    Ok(cosm_from_parts(
        hash,
        result.get("height").and_then(json_u64).unwrap_or(0),
        tx_result.get("code").and_then(json_u64).unwrap_or(0) as usize,
        tx_result
            .get("log")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        tx_result.get("events"),
    ))
}

async fn lcd_find(url: &str, hash: &str) -> Result<CosmTxResponse, DaemonError> {
    let endpoint = format!(
        "{}/cosmos/tx/v1beta1/txs/{}",
        url.trim_end_matches('/'),
        hash
    );
    let value = get_json(&endpoint).await?;
    let response = value
        .get("tx_response")
        .ok_or_else(|| DaemonError::StdErr(format!("lcd tx {url}: {value}")))?;
    let proto = tx_response_from_json(response);
    Ok(cosm_from_parts(
        &proto.txhash,
        proto.height.max(0) as u64,
        proto.code as usize,
        proto.raw_log,
        response.get("events"),
    ))
}

fn tx_response_from_json(value: &Value) -> TxResponse {
    TxResponse {
        height: value.get("height").and_then(json_u64).unwrap_or(0) as i64,
        txhash: value
            .get("txhash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        codespace: value
            .get("codespace")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        code: value.get("code").and_then(json_u64).unwrap_or(0) as u32,
        data: value
            .get("data")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        raw_log: value
            .get("raw_log")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        gas_wanted: value.get("gas_wanted").and_then(json_u64).unwrap_or(0) as i64,
        gas_used: value.get("gas_used").and_then(json_u64).unwrap_or(0) as i64,
        ..Default::default()
    }
}

fn cosm_from_parts(
    hash: &str,
    height: u64,
    code: usize,
    raw_log: String,
    events: Option<&Value>,
) -> CosmTxResponse {
    CosmTxResponse {
        height,
        txhash: hash.to_string(),
        code,
        raw_log,
        events: events.map(events_from_json).unwrap_or_default(),
        timestamp: chrono::Utc::now(),
        ..Default::default()
    }
}

fn events_from_json(value: &Value) -> Vec<Event> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|event| Event {
            r#type: event
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            attributes: event
                .get("attributes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|attr| EventAttribute {
                    key: attr
                        .get("key")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    value: attr
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    index: false,
                })
                .collect(),
        })
        .collect()
}

fn json_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

fn b64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let chunk = u32::from_be_bytes([0, bytes[index], bytes[index + 1], bytes[index + 2]]);
        out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 6) & 63) as usize] as char);
        out.push(TABLE[(chunk & 63) as usize] as char);
        index += 3;
    }
    let rest = bytes.len() - index;
    if rest == 1 {
        let chunk = u32::from(bytes[index]) << 16;
        out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rest == 2 {
        let chunk = (u32::from(bytes[index]) << 16) | (u32::from(bytes[index + 1]) << 8);
        out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}
