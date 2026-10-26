//! Mock Zigner phone for local e2e tests.
//!
//! Generates a throwaway 24-word mnemonic in memory at start (never printed or
//! written), then answers one command per stdin line:
//!   addr <prefix>      -> `addr <bech32>` (account 0, address 0, coin 118)
//!   sign <qr_hex>      -> `ok <pubkey_b64> <sig_b64> <signer_addr>` or `err <msg>`
//! Signing mirrors zigner/rust/signer/src/lib.rs `cosmos_resolve_chain` +
//! `cosmos_key_for_signers` (private there), built from Zigner's public
//! `transaction_signing::cosmos` and `db_handling::cosmos` functions.
use base64::Engine;
use db_handling::cosmos::{
    bech32_prefix_of, coin_type_for_network, derive_cosmos_key, is_valid_bech32_prefix,
    prefix_for_network, pubkey_to_bech32_with_prefix, CosmosKeyPair, SLIP0044_COSMOS,
};
use std::io::{BufRead, Write};
use transaction_signing::cosmos::{
    extract_signers, granter_binding, sign_cosmos_amino, CosmosQrExtension, CosmosSignRequest,
};

fn resolve(hex: &str, chain_name: &str, signers: &[String]) -> Result<(String, Vec<u32>), String> {
    let ext = CosmosQrExtension::from_qr_hex(hex).map_err(|e| format!("Failed to re-parse QR: {e}"))?.unwrap_or_default();
    let hrps: Vec<Option<String>> = signers.iter().map(|a| bech32_prefix_of(a)).collect();
    let signer_prefix = match hrps.first() {
        Some(Some(f)) if hrps.iter().all(|h| h.as_deref() == Some(f.as_str())) => Some(f.clone()),
        _ => None,
    };
    let prefix = ext.bech32_prefix.clone().or(signer_prefix).filter(|p| is_valid_bech32_prefix(p))
        .unwrap_or_else(|| prefix_for_network(chain_name).to_string());
    let coins = match ext.coin_type {
        Some(c) => vec![c],
        None => {
            let c = coin_type_for_network(chain_name);
            if c == SLIP0044_COSMOS { vec![c] } else { vec![c, SLIP0044_COSMOS] }
        }
    };
    Ok((prefix, coins))
}

fn key_for(seed: &str, prefix: &str, coin: u32, ha: u32, hb: u32, signers: &[String]) -> Result<CosmosKeyPair, String> {
    let mut cands = vec![(ha, hb)];
    for a in 0..16 { for b in 0..4 { if (a, b) != (ha, hb) { cands.push((a, b)); } } }
    let mut hinted = None;
    for (a, b) in cands {
        let key = derive_cosmos_key(seed, coin, a, b).map_err(|e| format!("Key derivation failed: {e}"))?;
        let dev = pubkey_to_bech32_with_prefix(&key.public_key, prefix).map_err(|e| format!("Address derivation failed: {e}"))?;
        if hinted.is_none() { hinted = Some(dev.clone()); }
        if signers.is_empty() || signers.iter().all(|s| s == &dev) { return Ok(key); }
    }
    Err(format!("Source mismatch: this key is {}, but the transaction spends from {}",
        hinted.unwrap_or_default(), signers.first().map(String::as_str).unwrap_or("")))
}

fn sign(seed: &str, hex: &str) -> Result<String, String> {
    let req = CosmosSignRequest::from_qr_hex(hex).map_err(|e| format!("Failed to parse QR: {e}"))?;
    let signers = if granter_binding(&req.sign_doc_bytes).map_err(|e| format!("bad doc: {e}"))?.is_some() {
        Vec::new()
    } else {
        extract_signers(&req.sign_doc_bytes).map_err(|e| format!("bad doc: {e}"))?
    };
    let (prefix, coins) = resolve(hex, &req.chain_name, &signers)?;
    let mut first = None;
    for coin in coins {
        match key_for(seed, &prefix, coin, req.account_index, req.address_index, &signers) {
            Ok(key) => {
                let sig = sign_cosmos_amino(&key.secret_key, &req.sign_doc_bytes).map_err(|e| format!("Signing failed: {e}"))?;
                let addr = pubkey_to_bech32_with_prefix(&key.public_key, &prefix).map_err(|e| e.to_string())?;
                let b = base64::engine::general_purpose::STANDARD;
                return Ok(format!("ok {} {} {}", b.encode(key.public_key), b.encode(sig), addr));
            }
            Err(e) => { if first.is_none() { first = Some(e); } }
        }
    }
    Err(first.unwrap_or_else(|| "no coin type".into()))
}

fn main() {
    let seed = bip39::Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English).into_phrase();
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let mut it = line.splitn(2, ' ');
        let reply = match (it.next(), it.next()) {
            (Some("addr"), Some(p)) => derive_cosmos_key(&seed, SLIP0044_COSMOS, 0, 0)
                .map_err(|e| e.to_string())
                .and_then(|k| pubkey_to_bech32_with_prefix(&k.public_key, p.trim()).map_err(|e| e.to_string()))
                .map(|a| format!("addr {a}")).unwrap_or_else(|e| format!("err {e}")),
            (Some("sign"), Some(h)) => sign(&seed, h.trim()).unwrap_or_else(|e| format!("err {e}")),
            _ => "err unknown command".into(),
        };
        let _ = writeln!(out, "{reply}");
        let _ = out.flush();
    }
}
