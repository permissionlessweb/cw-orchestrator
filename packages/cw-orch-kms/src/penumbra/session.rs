//! Scoped, time-limited **view session** for the cold (Zigner) wallet.
//!
//! The FVK is never stored by default. A session starts with the run's page
//! ([`page`], the shared cw-orch-kms page) on loopback asking for Zigner's
//! *FVK export* QR; the same page then shows every plan that needs the phone. The FVK is accepted
//! only if it owns the pinned address. It is then held in memory and written
//! into an ephemeral, 0700 pcli home (config.toml 0600 + pcli's view DB) whose
//! custody backend is `Remote` → this process's loopback CustodyService, so
//! every signature still needs a Zigner scan and no soft-KMS exists anywhere.
//! When the TTL expires, the page's "end session" is pressed, or the process
//! gets Ctrl-C, the home is overwritten with zeros and removed, and the
//! pointer file is deleted. Stale homes from a crash are wiped on next start.
//! Mirrors cw-orch-kms's session/revoke model.

use super::{custody, page, policy::Policy, PinnedAccount};
use anyhow::{anyhow, bail, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use penumbra_sdk_keys::{Address, FullViewingKey};
use std::{
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{watch, Mutex};

const FVK_HRP: &str = "penumbrafullviewingkey1";

/// Decode whatever Zigner's FVK export QR yielded:
/// * bech32m `penumbrafullviewingkey1…`
/// * Zigner binary `53 03 01 | account u32LE | label_len label | fvk64 | wallet_id32 [| 01 zid32]`
///   (raw bytes, hex text, or latin-1 text as zxing returns byte-mode QR)
/// * UR `ur:penumbra-accounts/…` (single part; multi-part via [`UrCollector`])
pub fn parse_fvk_export(input: &[u8]) -> Result<FullViewingKey> {
    let text = std::str::from_utf8(input).ok().map(str::trim);
    if let Some(t) = text {
        if t.starts_with(FVK_HRP) {
            return Ok(FullViewingKey::from_str(t)?);
        }
        if t.len() > 3 && t[..3].eq_ignore_ascii_case("ur:") {
            let (kind, bytes) = ur::ur::decode(&t.to_ascii_lowercase()).map_err(|e| anyhow!("ur decode: {e:?}"))?;
            if !matches!(kind, ur::ur::Kind::SinglePart) {
                bail!("multi-part UR: feed parts to UrCollector");
            }
            return fvk_from_ur_payload(&bytes);
        }
        if t.len() >= 208 && t.len() % 2 == 0 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return fvk_from_zigner_binary(&hex::decode(t)?);
        }
        // zxing gives byte-mode QR as latin-1 text
        let latin1: Option<Vec<u8>> = t.chars().map(|c| u8::try_from(c as u32).ok()).collect();
        if let Some(b) = latin1 {
            if b.starts_with(&[0x53, 0x03, 0x01]) {
                return fvk_from_zigner_binary(&b);
            }
        }
    }
    if input.starts_with(&[0x53, 0x03, 0x01]) {
        return fvk_from_zigner_binary(input);
    }
    bail!("not a Zigner FVK export (expected bech32m, 53 03 01 binary, or ur:penumbra-accounts)")
}

fn fvk_from_zigner_binary(d: &[u8]) -> Result<FullViewingKey> {
    if d.len() < 104 || d[..3] != [0x53, 0x03, 0x01] {
        bail!("bad Zigner FVK export prelude/length");
    }
    let mut o = 3 + 4;
    let label_len = d[o] as usize;
    o += 1 + label_len;
    let fvk_bytes = d.get(o..o + 64).ok_or_else(|| anyhow!("truncated fvk"))?;
    let wid = d.get(o + 64..o + 96).ok_or_else(|| anyhow!("truncated wallet id"))?;
    let fvk = FullViewingKey::try_from(penumbra_sdk_proto::core::keys::v1::FullViewingKey { inner: fvk_bytes.to_vec() })?;
    if fvk.wallet_id().0.as_slice() != wid {
        bail!("wallet id in export does not match the FVK");
    }
    Ok(fvk)
}

/// The UR CBOR holds the FVK as a bech32m text string; pull it out without a
/// full CBOR parser (bech32m charset is lowercase alnum).
fn fvk_from_ur_payload(b: &[u8]) -> Result<FullViewingKey> {
    let pat = FVK_HRP.as_bytes();
    let start = b.windows(pat.len()).position(|w| w == pat).ok_or_else(|| anyhow!("no FVK in UR payload"))?;
    let end = b[start..].iter().position(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit()).map(|n| start + n).unwrap_or(b.len());
    Ok(FullViewingKey::from_str(std::str::from_utf8(&b[start..end])?)?)
}

/// Accumulates animated (multi-part) UR frames.
#[derive(Default)]
pub struct UrCollector(ur::Decoder);
impl UrCollector {
    /// `Ok(Some(fvk))` when complete, `Ok(None)` when more parts are needed.
    pub fn receive(&mut self, part: &str) -> Result<Option<FullViewingKey>> {
        self.0.receive(&part.trim().to_ascii_lowercase()).map_err(|e| anyhow!("ur: {e:?}"))?;
        if !self.0.complete() {
            return Ok(None);
        }
        let m = self.0.message().map_err(|e| anyhow!("ur: {e:?}"))?.ok_or_else(|| anyhow!("ur incomplete"))?;
        Ok(Some(fvk_from_ur_payload(&m)?))
    }
}

/// Accept the FVK only if it owns the pinned address.
pub fn pin(fvk: FullViewingKey, pinned: &Address) -> Result<PinnedAccount> {
    if fvk.address_index(pinned).is_none() {
        bail!("scanned FVK does not own the pinned wallet address — refusing");
    }
    Ok(PinnedAccount { fvk })
}

fn check_toml_value(s: &str) -> Result<&str> {
    if s.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
        bail!("refusing unsafe characters in config value");
    }
    Ok(s)
}

/// Write the ephemeral pcli home. Custody is always `Remote` on loopback; the
/// template has no spend key and no SoftKms/Encrypted/Threshold block.
pub fn write_pcli_home(dir: &Path, fvk: &FullViewingKey, node_grpc_url: &str, custody: SocketAddr) -> Result<()> {
    anyhow::ensure!(custody.ip().is_loopback(), "custody must be loopback");
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new().mode(0o700).recursive(true).create(dir)?;
    let body = format!(
        "grpc_url = \"{}\"\nfull_viewing_key = \"{}\"\n\n[custody]\nbackend = \"Remote\"\ngrpc_url = \"http://{}/\"\n",
        check_toml_value(node_grpc_url)?,
        fvk,
        custody
    );
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(dir.join("config.toml"))?;
    f.write_all(body.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// Overwrite every file under `dir` with zeros, then remove it.
pub fn wipe(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    fn walk(p: &Path) -> std::io::Result<()> {
        for e in std::fs::read_dir(p)? {
            let e = e?;
            let t = e.file_type()?;
            if t.is_dir() {
                walk(&e.path())?;
            } else if t.is_file() {
                let len = e.metadata()?.len() as usize;
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(e.path()) {
                    let zeros = vec![0u8; 1 << 16];
                    let mut left = len;
                    while left > 0 {
                        let n = left.min(zeros.len());
                        f.write_all(&zeros[..n])?;
                        left -= n;
                    }
                    let _ = f.sync_all();
                }
            }
        }
        Ok(())
    }
    let _ = walk(dir);
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

pub struct SessionConfig {
    pub pinned_address: String,
    pub policy: Policy,
    pub node_grpc_url: String,
    /// The run's page: FVK import, status, end and every approval.
    /// Default 127.0.0.1:8743.
    pub page: SocketAddr,
    /// Custody gRPC pcli talks to. Default 127.0.0.1:8742.
    pub custody: SocketAddr,
    pub ttl: Duration,
    pub approval_timeout: Duration,
    /// Parent dir for ephemeral homes; a pointer file `current-home` lives here too.
    pub state_dir: PathBuf,
}

#[derive(Default)]
struct Live {
    account: Option<PinnedAccount>,
    home: Option<PathBuf>,
    expires: Option<Instant>,
    ur: Option<UrCollector>,
    ended: bool,
}

struct Shared {
    cfg_pinned: Address,
    approvals: Arc<page::Approvals>,
    live: Mutex<Live>,
    import_tx: watch::Sender<bool>,
    end_tx: watch::Sender<bool>,
}

fn authed(s: &Shared, h: &HeaderMap) -> bool {
    page::authed(s.approvals.token(), h)
}

async fn import_fvk(State(s): State<Arc<Shared>>, h: HeaderMap, body: axum::body::Bytes) -> Response {
    if !authed(&s, &h) {
        return (StatusCode::FORBIDDEN, "bad token").into_response();
    }
    let mut live = s.live.lock().await;
    if live.account.is_some() || live.ended {
        return (StatusCode::CONFLICT, "session already active or ended").into_response();
    }
    let text = String::from_utf8_lossy(&body).trim().to_string();
    let parsed = if text.to_ascii_lowercase().starts_with("ur:") && text.contains('/') && text.matches('/').count() >= 2 {
        let c = live.ur.get_or_insert_with(UrCollector::default);
        match c.receive(&text) {
            Ok(None) => return (StatusCode::ACCEPTED, "UR part received, keep scanning").into_response(),
            Ok(Some(f)) => Ok(f),
            Err(e) => Err(e),
        }
    } else {
        parse_fvk_export(&body)
    };
    // never echo key material in errors
    let account = match parsed.and_then(|f| pin(f, &s.cfg_pinned)) {
        Ok(a) => a,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("rejected: {e:#}")).into_response(),
    };
    live.account = Some(account);
    live.ur = None;
    drop(live);
    let _ = s.import_tx.send(true);
    (StatusCode::OK, "FVK accepted for the pinned wallet; starting view session").into_response()
}

async fn status(State(s): State<Arc<Shared>>, h: HeaderMap) -> Response {
    if !authed(&s, &h) {
        return (StatusCode::FORBIDDEN, "bad token").into_response();
    }
    let live = s.live.lock().await;
    let state = if live.ended { "ended" } else if live.home.is_some() { "active" } else if live.account.is_some() { "starting" } else { "waiting_for_fvk" };
    let j = serde_json::json!({
        "state": state,
        "wallet_id": live.account.as_ref().map(|a| a.wallet_id()),
        "home": live.home.as_ref().map(|p| p.display().to_string()),
        "expires_in_secs": live.expires.map(|e| e.saturating_duration_since(Instant::now()).as_secs()),
        "pending_approval": s.approvals.is_pending(),
    });
    ([("content-type", "application/json")], j.to_string()).into_response()
}

async fn end(State(s): State<Arc<Shared>>, h: HeaderMap) -> Response {
    if !authed(&s, &h) {
        return (StatusCode::FORBIDDEN, "bad token").into_response();
    }
    let _ = s.end_tx.send(true);
    (StatusCode::OK, "ending session: view home will be wiped").into_response()
}

fn token() -> String {
    crate::ui_shared::approval_token()
}

/// Handle returned by [`start`]: page URL and a future that runs the session.
pub struct Running {
    pub page_url: String,
    pub token: String,
    pub done: tokio::task::JoinHandle<Result<()>>,
}

/// Bring up the session page; once an FVK for the pinned wallet is imported,
/// write the ephemeral home, serve custody, and wipe on TTL/end/Ctrl-C.
pub async fn start(cfg: SessionConfig) -> Result<Running> {
    page::check_bind(cfg.page)?;
    page::check_bind(cfg.custody)?;
    let pinned = Address::from_str(cfg.pinned_address.trim()).context("pinned address")?;
    std::fs::create_dir_all(&cfg.state_dir)?;
    // crash recovery: wipe a home left by a previous run
    let pointer = cfg.state_dir.join("current-home");
    if let Ok(old) = std::fs::read_to_string(&pointer) {
        let _ = wipe(Path::new(old.trim()));
        let _ = std::fs::remove_file(&pointer);
    }
    let approvals = page::Approvals::new();
    let tok = approvals.token().to_string();
    let (import_tx, mut import_rx) = watch::channel(false);
    let (end_tx, mut end_rx) = watch::channel(false);
    let shared = Arc::new(Shared {
        cfg_pinned: pinned,
        approvals: approvals.clone(),
        live: Mutex::new(Live::default()),
        import_tx,
        end_tx,
    });
    let session_routes = Router::new()
        .route("/fvk", post(import_fvk))
        .route("/status", get(status))
        .route("/end", post(end))
        .with_state(shared.clone());
    let card = page::session_card(cfg.pinned_address.trim());
    let app = page::router(approvals.clone(), Some(&card), session_routes);
    let (page_url, stop_tx, page_srv) = page::serve(cfg.page, app).await?;
    println!("penumbra session page {page_url}");
    let deadline = tokio::time::Instant::now() + cfg.ttl;

    let done = tokio::spawn(async move {
        let ended_early = tokio::select! {
            _ = import_rx.wait_for(|v| *v) => false,
            _ = end_rx.wait_for(|v| *v) => true,
            _ = tokio::signal::ctrl_c() => true,
            _ = tokio::time::sleep_until(deadline) => true,
        };
        let mut home: Option<PathBuf> = None;
        let result: Result<()> = async {
            if ended_early {
                return Ok(());
            }
            let account = shared.live.lock().await.account.clone().ok_or_else(|| anyhow!("no account"))?;
            let dir = cfg.state_dir.join(format!("home-{}", &token()[..12]));
            write_pcli_home(&dir, &account.fvk, &cfg.node_grpc_url, cfg.custody)?;
            std::fs::write(&pointer, dir.display().to_string())?;
            home = Some(dir.clone());
            let custody_listener = tokio::net::TcpListener::bind(cfg.custody).await.with_context(|| format!("binding {}", cfg.custody))?;
            let zc = custody::ZignerCustody::new(account, cfg.policy.clone(), approvals.clone(), cfg.approval_timeout);
            {
                let mut l = shared.live.lock().await;
                l.home = Some(dir.clone());
                l.expires = Some(deadline.into_std());
            }
            println!("ok view session active for {}s\n  pcli --home {} view balance", deadline.saturating_duration_since(tokio::time::Instant::now()).as_secs(), dir.display());
            tokio::select! {
                r = custody::serve_listener(zc, custody_listener) => r?,
                _ = end_rx.wait_for(|v| *v) => {},
                _ = tokio::signal::ctrl_c() => {},
                _ = tokio::time::sleep_until(deadline) => {},
            }
            Ok(())
        }
        .await;
        // teardown: always wipe
        {
            let mut l = shared.live.lock().await;
            l.account = None;
            l.home = None;
            l.ended = true;
        }
        if let Some(d) = &home {
            wipe(d)?;
        }
        let _ = std::fs::remove_file(&pointer);
        let _ = stop_tx.send(());
        let _ = page_srv.await;
        println!("ok view session ended; ephemeral home wiped");
        result
    });
    Ok(Running { page_url, token: tok, done })
}
