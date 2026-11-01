//! Zigner-scan replay for the granter challenge (no phone, no chain, throwaway key).
//!
//! A fresh random secp256k1 key plays the cold key. It signs the exact bytes the
//! page's Zigner QR carries (`zigner_request` = header + len + sign doc) the way
//! Zigner direct-sign does: ECDSA over sha256(sign doc), low-s, r||s. The test
//! then delivers the payload exactly as the page JS does over `/ws`:
//! `sigonly <128 hex>` for a bare signature (onFrame), or
//! `check <b64 pubkey> <b64 sig>` for the 97-byte envelope (acceptBytes -> submit).
//! The browser replay (`browser_replay_*`, ignored unless CW_ORCH_KMS_REPLAY_PY
//! is set) drives the real page JS with an injected QR decode result.

use crate::progress::{self, Status, TEST_LOCK};
use crate::terminal::{set_approval_chain_id, zigner_qr_hex};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::Digest;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

const CHAIN: &str = "terp-replay-1";

pub(crate) struct ThrowawayKey {
    sk: k256::ecdsa::SigningKey,
}

impl ThrowawayKey {
    pub(crate) fn new() -> Self {
        use rand::RngCore;
        loop {
            let mut b = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(&b) {
                return Self { sk };
            }
        }
    }
    pub(crate) fn pubkey(&self) -> Vec<u8> {
        self.sk.verifying_key().to_encoded_point(true).as_bytes().to_vec()
    }
    pub(crate) fn address(&self) -> String {
        let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(self.pubkey()));
        crate::chain::approval_chain().address(hash.as_slice()).unwrap()
    }
    /// Zigner direct-sign: secp256k1 over sha256(doc), low-s, 64-byte r||s.
    pub(crate) fn zigner_sign(&self, doc: &[u8]) -> Vec<u8> {
        let hash = sha2::Sha256::digest(doc);
        let sig: k256::ecdsa::Signature = self.sk.sign_prehash(&hash).unwrap();
        sig.normalize_s().unwrap_or(sig).to_bytes().to_vec()
    }
    pub(crate) fn secret_hex(&self) -> String {
        hex(&self.sk.to_bytes())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

async fn get(port: u16, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(mut s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            s.write_all(req.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).await.unwrap();
            return String::from_utf8_lossy(&out).into_owned();
        }
        assert!(Instant::now() < deadline, "page never answered");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The challenge binding as the page shows it; the sign doc is `v1\n` + binding.
pub(crate) fn binding_from_html(html: &str) -> String {
    let start = html.find("cw-orch-granter:v2 ").expect("challenge on page");
    let rest = &html[start..];
    let end = rest.find(" is the granter").expect("binding end");
    rest[..end].to_string()
}

fn expires_of(binding: &str) -> u64 {
    let at = binding.find("expires=").unwrap() + 8;
    binding[at..].split_whitespace().next().unwrap().parse().unwrap()
}

/// Waits for the page, returns (binding, sign doc).
async fn page_doc(port: u16) -> (String, Vec<u8>) {
    let html = loop {
        let h = get(port, "/").await;
        if h.contains("cw-orch-granter:v2 ") { break h; }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let binding = binding_from_html(&html);
    let doc = format!("cw-orch-granter:v1\n{binding}").into_bytes();
    // What Zigner reads: the page QR payload ends with the length-prefixed doc.
    let qr = zigner_qr_hex(0, &doc);
    assert!(qr.ends_with(&hex(&doc)), "the QR carries the exact sign doc");
    (binding, doc)
}

async fn ws_send(port: u16, frames: &[String]) -> Vec<String> {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws")).await.unwrap();
    let mut replies = Vec::new();
    for f in frames {
        ws.send(Message::Text(f.clone().into())).await.unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
                Ok(Some(Ok(Message::Text(t)))) => {
                    let t = t.to_string();
                    if t.starts_with("digest=") || t.starts_with("log ") { continue; }
                    replies.push(t);
                    break;
                }
                Ok(Some(Ok(_))) => continue,
                _ => { replies.push("<socket closed>".into()); return replies; }
            }
        }
    }
    replies
}

fn spawn_capture(port: u16, ttl: u64, expected: Option<String>) -> std::thread::JoinHandle<(Result<String, String>, Instant)> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    std::thread::spawn(move || {
        let r = crate::terminal::capture_granter_for_chain_opts_sync(addr, 0, "fiab-bounty-escrow", CHAIN, ttl, expected.as_deref());
        (r, Instant::now())
    })
}

fn fresh() -> u16 {
    progress::stop_standby();
    progress::reset();
    set_approval_chain_id(CHAIN).unwrap();
    crate::port::free_port(None)
}

fn after_challenge_is_authorize(signer: &str, key: &ThrowawayKey) {
    assert_eq!(signer, key.address());
    let steps = progress::steps();
    assert_eq!(steps[0].label, "granter challenge");
    assert_eq!(steps[0].status, Status::Signed);
    let cur = progress::current_step();
    assert_eq!(steps[cur - 1].label, "authorize", "the page advances to authorize");
    progress::stop_standby();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zigner_bare_signature_is_accepted_and_expiry_is_30_min() {
    let _g = TEST_LOCK.lock().await;
    let port = fresh();
    let key = ThrowawayKey::new();
    let t0 = crate::policy::now_unix();
    let h = spawn_capture(port, crate::policy::DEFAULT_CHALLENGE_TTL_SECS, Some(key.address()));
    let (binding, doc) = page_doc(port).await;
    let ttl = expires_of(&binding) - t0;
    assert!((1799..=1801).contains(&ttl), "challenge ttl {ttl}s, want 1800");
    let sig = key.zigner_sign(&doc);
    assert_eq!(sig.len(), 64);
    let replies = ws_send(port, &[format!("sigonly {}", hex(&sig))]).await;
    assert_eq!(replies[0], format!("valid {}", key.address()), "{replies:?}");
    let (r, _) = h.join().unwrap();
    after_challenge_is_authorize(&r.unwrap(), &key);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zigner_97_byte_envelope_is_accepted() {
    let _g = TEST_LOCK.lock().await;
    let port = fresh();
    let key = ThrowawayKey::new();
    let h = spawn_capture(port, crate::policy::DEFAULT_CHALLENGE_TTL_SECS, None);
    let (_, doc) = page_doc(port).await;
    let mut env = key.pubkey();
    env.extend(key.zigner_sign(&doc));
    assert_eq!(env.len(), 97);
    // acceptBytes: pk = bytes[0..33], sig = bytes[33..97]; submit sends base64.
    let b = base64::engine::general_purpose::STANDARD;
    let replies = ws_send(port, &[format!("check {} {}", b.encode(&env[..33]), b.encode(&env[33..]))]).await;
    assert_eq!(replies[0], format!("valid {}", key.address()));
    let (r, _) = h.join().unwrap();
    after_challenge_is_authorize(&r.unwrap(), &key);
}

/// Tonight's failure: no expected granter, Zigner sent a bare signature. The
/// page must say why and stay usable, and a following envelope still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bare_signature_without_expected_granter_is_refused_clearly_and_rearms() {
    let _g = TEST_LOCK.lock().await;
    let port = fresh();
    let key = ThrowawayKey::new();
    let h = spawn_capture(port, crate::policy::DEFAULT_CHALLENGE_TTL_SECS, None);
    let (_, doc) = page_doc(port).await;
    let sig = key.zigner_sign(&doc);
    let b = base64::engine::general_purpose::STANDARD;
    let replies = ws_send(port, &[
        format!("sigonly {}", hex(&sig)),
        format!("check {} {}", b.encode(key.pubkey()), b.encode(&sig)),
    ]).await;
    assert!(replies[0].starts_with("invalid: a bare signature has no pubkey"), "{replies:?}");
    assert_eq!(replies[1], format!("valid {}", key.address()));
    let (r, _) = h.join().unwrap();
    after_challenge_is_authorize(&r.unwrap(), &key);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_key_bare_signature_is_refused() {
    let _g = TEST_LOCK.lock().await;
    let port = fresh();
    let key = ThrowawayKey::new();
    let other = ThrowawayKey::new();
    let h = spawn_capture(port, crate::policy::DEFAULT_CHALLENGE_TTL_SECS, Some(key.address()));
    let (_, doc) = page_doc(port).await;
    let replies = ws_send(port, &[
        format!("sigonly {}", hex(&other.zigner_sign(&doc))),
        format!("sigonly {}", hex(&key.zigner_sign(&doc))),
    ]).await;
    assert!(replies[0].starts_with("invalid: bare signature does not recover"), "{replies:?}");
    assert_eq!(replies[1], format!("valid {}", key.address()));
    let (r, _) = h.join().unwrap();
    after_challenge_is_authorize(&r.unwrap(), &key);
}

/// The capture returns at the expiry (plus the short page notice), not minutes later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_challenge_exits_promptly_and_shows_it() {
    let _g = TEST_LOCK.lock().await;
    let port = fresh();
    let key = ThrowawayKey::new();
    let start = Instant::now();
    let h = spawn_capture(port, 2, Some(key.address()));
    let _ = page_doc(port).await;
    // While the notice is up the tab's /state shows the error.
    let mut saw_error = false;
    while !h.is_finished() {
        let s = get(port, "/state").await;
        if s.contains("\"error\":true") && s.contains("expired") { saw_error = true; }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (r, done) = h.join().unwrap();
    let err = r.unwrap_err();
    assert!(err.contains("expired"), "{err}");
    let took = done - start;
    assert!(took < Duration::from_secs(2 + 1 + crate::terminal::EXIT_NOTICE_MS / 1000 + 1), "took {took:?}");
    assert!(saw_error, "the page showed the expiry before the exit");
    progress::stop_standby();
}

/// Real page JS in headless Chromium: the QR decode result is injected where
/// zxing would deliver it. Needs CW_ORCH_KMS_REPLAY_PY=<python with playwright+ecdsa>
/// and CW_ORCH_KMS_REPLAY_CHROME=<chrome-headless-shell>.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn browser_replay_bare_and_envelope() {
    let py = std::env::var("CW_ORCH_KMS_REPLAY_PY").expect("CW_ORCH_KMS_REPLAY_PY");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/zigner_replay_browser.py");
    let _g = TEST_LOCK.lock().await;
    for (mode, expect) in [("bare", true), ("envelope194", false), ("pframes", false), ("bare-nokey-then-envelope", false)] {
        let port = fresh();
        let key = ThrowawayKey::new();
        let expected = if expect { Some(key.address()) } else { None };
        let h = spawn_capture(port, crate::policy::DEFAULT_CHALLENGE_TTL_SECS, expected);
        let _ = page_doc(port).await;
        let out = tokio::process::Command::new(&py)
            .arg(script)
            .arg(format!("http://127.0.0.1:{port}/"))
            .arg(mode)
            .env("REPLAY_THROWAWAY_KEY_HEX", key.secret_hex())
            .output()
            .await
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        println!("[{mode}] {stdout}{}", String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "browser replay {mode} failed");
        assert!(stdout.contains("PAGE-ADVANCED-TO authorize"), "{mode}: {stdout}");
        let (r, _) = h.join().unwrap();
        after_challenge_is_authorize(&r.unwrap(), &key);
    }
}
