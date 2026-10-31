//! Direct-sign bank send: the cold key (Zigner) signs a LEGACY_AMINO_JSON
//! MsgSend from its own account, pays its own fee. No authz, no feegrant.
//! Env: FROM TO AMOUNT DENOM LCD CHAIN_ID GAS FEE ZIGNER_ACCOUNT CW_ORCH_KMS_PORT
use cosmrs::proto::traits::Message;
use cosmrs::tx::{Body, Fee, ModeInfo, Raw, SignMode, SignerInfo};
use cw_orch_kms::{listen_sign_doc, page_addr, set_approval_chain_id, SigningRequest, TerminalOutcome};
use std::process::Command;

fn env(k: &str, d: &str) -> String { std::env::var(k).unwrap_or_else(|_| d.to_string()) }
fn curl(args: &[&str]) -> serde_json::Value {
    let out = Command::new("curl").arg("-s").args(args).output().expect("curl");
    serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null)
}

#[tokio::main]
async fn main() {
    let from = env("FROM", ""); let to = env("TO", "");
    let amount = env("AMOUNT", "1000000"); let denom = env("DENOM", "uthiol");
    let lcd = env("LCD", "http://127.0.0.1:11317"); let chain_id = env("CHAIN_ID", "morocco-1");
    let gas: u64 = env("GAS", "120000").parse().unwrap();
    let fee: u128 = env("FEE", "6000").parse().unwrap();
    let account_index: u32 = env("ZIGNER_ACCOUNT", "0").parse().unwrap();
    set_approval_chain_id(&chain_id).expect("chain id");
    let acct = curl(&[&format!("{lcd}/cosmos/auth/v1beta1/accounts/{from}")]);
    let a = &acct["account"];
    let account_number = a["account_number"].as_str().expect("account not found on chain").to_string();
    let sequence: u64 = a["sequence"].as_str().unwrap_or("0").parse().unwrap();
    let memo = "key-soundness-test";
    let msg_amino = format!(r#"{{"type":"cosmos-sdk/MsgSend","value":{{"amount":[{{"amount":"{amount}","denom":"{denom}"}}],"from_address":"{from}","to_address":"{to}"}}}}"#);
    let doc = format!(r#"{{"account_number":"{account_number}","chain_id":"{chain_id}","fee":{{"amount":[{{"amount":"{fee}","denom":"{denom}"}}],"gas":"{gas}"}},"memo":"{memo}","msgs":[{msg_amino}],"sequence":"{sequence}"}}"#);
    let msgs = vec![SigningRequest::new("/cosmos.bank.v1beta1.MsgSend").body(msg_amino.clone())];
    let mut term = listen_sign_doc(page_addr(), &from, doc.into_bytes(), msgs, account_index).await.expect("listen");
    println!("PAGE http://{}/ from={from} to={to} amount={amount}{denom} acct#={account_number} seq={sequence} zigner_account={account_index}", term.addr());
    let (pubkey, sig) = match term.outcome().await.expect("outcome") {
        TerminalOutcome::Signed { signer, pubkey, signature } => {
            assert_eq!(signer, from, "wrong signer"); (pubkey, signature) }
        o => { eprintln!("REFUSED {o:?}"); std::process::exit(2) }
    };
    let send = cosmrs::proto::cosmos::bank::v1beta1::MsgSend {
        from_address: from.clone(), to_address: to.clone(),
        amount: vec![cosmrs::proto::cosmos::base::v1beta1::Coin { denom: denom.clone(), amount: amount.clone() }],
    };
    let any = cosmrs::Any { type_url: "/cosmos.bank.v1beta1.MsgSend".into(), value: send.encode_to_vec() };
    let body = Body::new(vec![any], memo, 0u32).into_bytes().unwrap();
    let pk = cosmrs::crypto::PublicKey::from(k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).unwrap());
    let feec = Fee::from_amount_and_gas(cosmrs::Coin { denom: denom.parse().unwrap(), amount: fee }, gas);
    let auth = SignerInfo { public_key: Some(pk.into()), mode_info: ModeInfo::single(SignMode::LegacyAminoJson), sequence }.auth_info(feec).into_bytes().unwrap();
    let raw = Raw::from(cosmrs::proto::cosmos::tx::v1beta1::TxRaw { body_bytes: body, auth_info_bytes: auth, signatures: vec![sig] });
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw.to_bytes().unwrap());
    let req = serde_json::json!({"tx_bytes": b64, "mode": "BROADCAST_MODE_SYNC"}).to_string();
    let res = curl(&["-X", "POST", "-H", "content-type: application/json", "-d", &req, &format!("{lcd}/cosmos/tx/v1beta1/txs")]);
    let r = &res["tx_response"];
    println!("BROADCAST code={} hash={} log={}", r["code"], r["txhash"], r["raw_log"]);
    term.note(&format!("ok broadcast {}", r["txhash"]));
    if r["code"].as_u64() != Some(0) { std::process::exit(3) }
    let hash = r["txhash"].as_str().unwrap().to_string();
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let t = curl(&[&format!("{lcd}/cosmos/tx/v1beta1/txs/{hash}")]);
        if let Some(c) = t["tx_response"]["code"].as_u64() {
            println!("COMMITTED code={c} height={} hash={hash}", t["tx_response"]["height"]);
            std::process::exit(if c == 0 { 0 } else { 4 });
        }
    }
    println!("TIMEOUT waiting for {hash}"); std::process::exit(5)
}
