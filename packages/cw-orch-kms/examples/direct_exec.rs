//! Direct-sign MsgExecuteContract batch (LEGACY_AMINO_JSON) from the cold key itself.
//! Env: FROM MSGS_FILE(json array of {"contract","msg"}) MEMO LCD CHAIN_ID GAS(optional; else simulate*1.4) ZIGNER_ACCOUNT CW_ORCH_KMS_PORT
use cosmrs::proto::traits::Message;
use cosmrs::tx::{Body, Fee, ModeInfo, Raw, SignMode, SignerInfo};
use cw_orch_kms::{listen_sign_doc, page_addr, set_approval_chain_id, SigningRequest, TerminalOutcome};
use serde_json::Value;
use std::process::Command;
use base64::Engine;

fn env(k: &str, d: &str) -> String { std::env::var(k).unwrap_or_else(|_| d.to_string()) }
fn curl(args: &[&str]) -> Value {
    let out = Command::new("curl").arg("-s").args(args).output().expect("curl");
    serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
}
fn canon(v: &Value) -> String {
    match v {
        Value::Object(m) => { let mut k: Vec<_> = m.keys().collect(); k.sort();
            format!("{{{}}}", k.iter().map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canon(&m[*k]))).collect::<Vec<_>>().join(",")) }
        Value::Array(a) => format!("[{}]", a.iter().map(canon).collect::<Vec<_>>().join(",")),
        o => serde_json::to_string(o).unwrap(),
    }
}
fn tx_b64(anys: &[cosmrs::Any], memo: &str, pk: cosmrs::crypto::PublicKey, seq: u64, fee: u128, gas: u64, sig: Vec<u8>) -> String {
    let body = Body::new(anys.to_vec(), memo, 0u32).into_bytes().unwrap();
    let feec = Fee::from_amount_and_gas(cosmrs::Coin { denom: "uthiol".parse().unwrap(), amount: fee }, gas);
    let auth = SignerInfo { public_key: Some(pk.into()), mode_info: ModeInfo::single(SignMode::LegacyAminoJson), sequence: seq }.auth_info(feec).into_bytes().unwrap();
    let raw = Raw::from(cosmrs::proto::cosmos::tx::v1beta1::TxRaw { body_bytes: body, auth_info_bytes: auth, signatures: vec![sig] });
    base64::engine::general_purpose::STANDARD.encode(raw.to_bytes().unwrap())
}

#[tokio::main]
async fn main() {
    let from = env("FROM", "");
    let lcd = env("LCD", "http://127.0.0.1:11317"); let chain_id = env("CHAIN_ID", "morocco-1");
    let memo = env("MEMO", "");
    let account_index: u32 = env("ZIGNER_ACCOUNT", "0").parse().unwrap();
    let list: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(env("MSGS_FILE", "")).unwrap()).unwrap();
    set_approval_chain_id(&chain_id).expect("chain id");
    let acct = curl(&[&format!("{lcd}/cosmos/auth/v1beta1/account_info/{from}")]);
    let info = &acct["info"];
    let account_number = info["account_number"].as_str().expect("account").to_string();
    let sequence: u64 = info["sequence"].as_str().unwrap().parse().unwrap();
    let chain_pk = base64::engine::general_purpose::STANDARD.decode(info["pub_key"]["key"].as_str().expect("pubkey")).unwrap();
    let chain_pk = cosmrs::crypto::PublicKey::from(k256::ecdsa::VerifyingKey::from_sec1_bytes(&chain_pk).unwrap());
    let mut anys = vec![]; let mut aminos = vec![]; let mut reqs = vec![];
    for m in &list {
        let contract = m["contract"].as_str().unwrap();
        let msg = canon(&m["msg"]);
        let amino = format!(r#"{{"type":"wasm/MsgExecuteContract","value":{{"contract":"{contract}","funds":[],"msg":{msg},"sender":"{from}"}}}}"#);
        let p = cosmrs::proto::cosmwasm::wasm::v1::MsgExecuteContract { sender: from.clone(), contract: contract.into(), msg: msg.into_bytes(), funds: vec![] };
        anys.push(cosmrs::Any { type_url: "/cosmwasm.wasm.v1.MsgExecuteContract".into(), value: p.encode_to_vec() });
        reqs.push(SigningRequest::new("/cosmwasm.wasm.v1.MsgExecuteContract").body(amino.clone()));
        aminos.push(amino);
    }
    let gas: u64 = match std::env::var("GAS") { Ok(g) => g.parse().unwrap(), Err(_) => {
        let b = tx_b64(&anys, &memo, chain_pk, sequence, 0, 10_000_000, vec![0u8; 64]);
        let r = curl(&["-X","POST","-H","content-type: application/json","-d",&serde_json::json!({"tx_bytes": b}).to_string(), &format!("{lcd}/cosmos/tx/v1beta1/simulate")]);
        let used: u64 = r["gas_info"]["gas_used"].as_str().unwrap_or_else(|| { eprintln!("SIMULATE FAILED {r}"); std::process::exit(6) }).parse().unwrap();
        println!("SIMULATED gas_used={used}"); used * 14 / 10 + 20_000 } };
    let fee: u128 = (gas as u128 * 5 + 99) / 100;
    let bal: u128 = curl(&[&format!("{lcd}/cosmos/bank/v1beta1/balances/{from}/by_denom?denom=uthiol")])["balance"]["amount"].as_str().unwrap_or("0").parse().unwrap();
    if bal < fee { eprintln!("INSUFFICIENT balance={bal} fee={fee}"); std::process::exit(7) }
    let doc = format!(r#"{{"account_number":"{account_number}","chain_id":"{chain_id}","fee":{{"amount":[{{"amount":"{fee}","denom":"uthiol"}}],"gas":"{gas}"}},"memo":{},"msgs":[{}],"sequence":"{sequence}"}}"#, serde_json::to_string(&memo).unwrap(), aminos.join(","));
    std::fs::write(env("DOC_OUT", "/dev/null"), &doc).ok();
    let mut term = listen_sign_doc(page_addr(), &from, doc.into_bytes(), reqs, account_index).await.expect("listen");
    println!("PAGE http://{}/ from={from} msgs={} gas={gas} fee={fee}uthiol balance={bal} acct#={account_number} seq={sequence} zigner_account={account_index}", term.addr(), anys.len());
    let (pubkey, sig) = match term.outcome().await.expect("outcome") {
        TerminalOutcome::Signed { signer, pubkey, signature } => { assert_eq!(signer, from); (pubkey, signature) }
        o => { eprintln!("REFUSED {o:?}"); std::process::exit(2) }
    };
    let pk = cosmrs::crypto::PublicKey::from(k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).unwrap());
    let b64 = tx_b64(&anys, &memo, pk, sequence, fee, gas, sig);
    let req = serde_json::json!({"tx_bytes": b64, "mode": "BROADCAST_MODE_SYNC"}).to_string();
    let res = curl(&["-X","POST","-H","content-type: application/json","-d",&req,&format!("{lcd}/cosmos/tx/v1beta1/txs")]);
    let r = &res["tx_response"];
    println!("BROADCAST code={} hash={} log={}", r["code"], r["txhash"], r["raw_log"]);
    term.note(&format!("ok broadcast {}", r["txhash"]));
    if r["code"].as_u64() != Some(0) { std::process::exit(3) }
    let hash = r["txhash"].as_str().unwrap().to_string();
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let t = curl(&[&format!("{lcd}/cosmos/tx/v1beta1/txs/{hash}")]);
        if let Some(c) = t["tx_response"]["code"].as_u64() {
            println!("COMMITTED code={c} height={} hash={hash} log={}", t["tx_response"]["height"], t["tx_response"]["raw_log"]);
            std::process::exit(if c == 0 { 0 } else { 4 });
        }
    }
    println!("TIMEOUT waiting for {hash}"); std::process::exit(5)
}
