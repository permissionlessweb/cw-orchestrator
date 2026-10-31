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
//!
//! Exception (on by default, `--ephemeral-view` to disable): pcli's view DB
//! (`pcli-view.sqlite`, sync height + decrypted notes, which also embeds the
//! FVK) is moved out of the home into `SessionConfig::view_cache` before the
//! wipe and restored on the next session, so later runs resume syncing from
//! the local pd instead of from genesis. Cache dir 0700, files 0600, keyed by
//! wallet id + node so another wallet/chain never resumes foreign state.
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
use penumbra_sdk_keys::{keys::AddressIndex, Address, FullViewingKey};
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
    parse_fvk_export_info(input).map(|(fvk, _)| fvk)
}

/// Public facts about a scanned export (never the key itself).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportInfo {
    /// "bech32m", "zigner-binary", "zigner-hex", "zigner-latin1" or "ur".
    pub format: &'static str,
    /// The account field of Zigner's binary export (its BIP44 account), if present.
    pub zigner_account: Option<u32>,
}

/// [`parse_fvk_export`] plus which format it was and Zigner's account field.
pub fn parse_fvk_export_info(input: &[u8]) -> Result<(FullViewingKey, ExportInfo)> {
    let info = |format, zigner_account| ExportInfo { format, zigner_account };
    let text = std::str::from_utf8(input).ok().map(str::trim);
    if let Some(t) = text {
        if t.starts_with("penumbrawalletid1") {
            bail!("{WALLET_ID_ONLY}");
        }
        if t.starts_with(FVK_HRP) {
            return Ok((FullViewingKey::from_str(t)?, info("bech32m", None)));
        }
        if t.len() > 3 && t[..3].eq_ignore_ascii_case("ur:") {
            let (kind, bytes) = ur::ur::decode(&t.to_ascii_lowercase()).map_err(|e| anyhow!("ur decode: {e:?}"))?;
            if !matches!(kind, ur::ur::Kind::SinglePart) {
                bail!("multi-part UR: feed parts to UrCollector");
            }
            let (f, a) = fvk_from_ur_payload_info(&bytes)?;
            return Ok((f, info("ur", a)));
        }
        if t.len() >= 208 && t.len() % 2 == 0 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            let (f, a) = fvk_from_zigner_binary(&hex::decode(t)?)?;
            return Ok((f, info("zigner-hex", Some(a))));
        }
        // zxing gives byte-mode QR as latin-1 text
        let latin1: Option<Vec<u8>> = t.chars().map(|c| u8::try_from(c as u32).ok()).collect();
        if let Some(b) = latin1 {
            if b.starts_with(&[0x53, 0x03, 0x01]) {
                let (f, a) = fvk_from_zigner_binary(&b)?;
                return Ok((f, info("zigner-latin1", Some(a))));
            }
        }
    }
    if input.starts_with(&[0x53, 0x03, 0x01]) {
        let (f, a) = fvk_from_zigner_binary(input)?;
        return Ok((f, info("zigner-binary", Some(a))));
    }
    bail!("not a Zigner FVK export (expected bech32m, 53 03 01 binary, or ur:penumbra-accounts)")
}

fn fvk_from_zigner_binary(d: &[u8]) -> Result<(FullViewingKey, u32)> {
    if d.len() < 104 || d[..3] != [0x53, 0x03, 0x01] {
        bail!("bad Zigner FVK export prelude/length");
    }
    let account = u32::from_le_bytes([d[3], d[4], d[5], d[6]]);
    let mut o = 3 + 4;
    let label_len = d[o] as usize;
    o += 1 + label_len;
    let fvk_bytes = d.get(o..o + 64).ok_or_else(|| anyhow!("truncated fvk"))?;
    let wid = d.get(o + 64..o + 96).ok_or_else(|| anyhow!("truncated wallet id"))?;
    let fvk = FullViewingKey::try_from(penumbra_sdk_proto::core::keys::v1::FullViewingKey { inner: fvk_bytes.to_vec() })?;
    if fvk.wallet_id().0.as_slice() != wid {
        bail!("wallet id in export does not match the FVK");
    }
    Ok((fvk, account))
}

/// The UR CBOR holds the FVK as a bech32m text string; pull it out without a
/// full CBOR parser (bech32m charset is lowercase alnum).
const WALLET_ID_ONLY: &str = "this QR is the wallet id, not the viewing key; in Zigner open the Penumbra key, then Export viewing key (FVK) and scan that QR";

fn fvk_from_ur_payload(b: &[u8]) -> Result<FullViewingKey> {
    fvk_from_ur_payload_info(b).map(|(f, _)| f)
}

/// Zigner `ur:penumbra-accounts` CBOR: {1: bytes32 wallet_id, 2: [#49302({1: tstr fvk, 2: uint index, ?3: name, ?4: zid})]}.
/// The embedded wallet id must equal the FVK hash, so a mangled key can never pass.
fn fvk_from_ur_payload_info(b: &[u8]) -> Result<(FullViewingKey, Option<u32>)> {
    let pat = FVK_HRP.as_bytes();
    let Some(start) = b.windows(pat.len()).position(|w| w == pat) else {
        bail!("{WALLET_ID_ONLY} (UR has no penumbrafullviewingkey)");
    };
    let end = b[start..].iter().position(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit()).map(|n| start + n).unwrap_or(b.len());
    let fvk = FullViewingKey::from_str(std::str::from_utf8(&b[start..end])?)?;
    if b.len() >= 36 && b[..4] == [0xa2, 0x01, 0x58, 0x20] && b[4..36] != fvk.wallet_id().0 {
        bail!("wallet id in UR export does not match the FVK");
    }
    let index = match b.get(end..) {
        Some([0x02, n, ..]) if *n < 24 => Some(*n as u32),
        Some([0x02, 0x18, n, ..]) => Some(*n as u32),
        Some([0x02, 0x19, h, l, ..]) => Some(u16::from_be_bytes([*h, *l]) as u32),
        _ => None,
    };
    Ok((fvk, index))
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

/// Who owns `address`, decided by the FVK's incoming viewing key
/// (`FullViewingKey::address_index`: `ivk.views_address` + diversifier
/// decryption). Works for any account and for randomized/ephemeral addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ownership {
    /// Short public wallet id (hash of the FVK), safe to show.
    pub wallet_id: String,
    pub index: Option<AddressIndex>,
}

impl Ownership {
    pub fn of(fvk: &FullViewingKey, address: &Address) -> Self {
        Self { wallet_id: short_wallet_id(fvk), index: fvk.address_index(address) }
    }
    pub fn owned(&self) -> bool {
        self.index.is_some()
    }
    pub fn account(&self) -> Option<u32> {
        self.index.map(|i| i.account)
    }
    /// The address is a randomized (ephemeral / IBC deposit) one.
    pub fn randomized(&self) -> Option<bool> {
        self.index.map(|i| i.randomizer != [0u8; 12])
    }
    pub fn describe(&self) -> String {
        match self.index {
            Some(_) => format!(
                "wallet {}: owns the pinned address (account {}, {} address)",
                self.wallet_id,
                self.account().unwrap_or_default(),
                if self.randomized() == Some(true) { "randomized" } else { "plain" }
            ),
            None => format!("wallet {}: does NOT own the pinned address", self.wallet_id),
        }
    }
}

/// `penumbrawalletid1` plus the first 12 characters of the id (public hash).
pub fn short_wallet_id(fvk: &FullViewingKey) -> String {
    let id = fvk.wallet_id().to_string();
    let n = id.char_indices().nth("penumbrawalletid1".len() + 12).map(|(i, _)| i).unwrap_or(id.len());
    format!("{}…", &id[..n])
}

/// Accept the FVK only if it owns the pinned address.
pub fn pin(fvk: FullViewingKey, pinned: &Address) -> Result<PinnedAccount> {
    let own = Ownership::of(&fvk, pinned);
    if !own.owned() {
        bail!("scanned FVK ({}) does not own the pinned wallet address — refusing. A different seed/wallet than the one that holds the address", own.wallet_id);
    }
    Ok(PinnedAccount { fvk })
}

fn export_note(i: &ExportInfo) -> String {
    match i.zigner_account {
        Some(a) => format!("export {} (Zigner account {a})", i.format),
        None => format!("export {}", i.format),
    }
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

/// pcli's view database inside a home (`pcli::VIEW_FILE_NAME`).
pub const VIEW_FILE: &str = "pcli-view.sqlite";
const VIEW_SIDECARS: [&str; 3] = ["", "-wal", "-shm"];

/// Where the persistent view DB for `fvk` synced from `node_grpc_url` lives
/// under `dir`. Keyed by the public wallet id and the node, so a different
/// wallet or chain never resumes someone else's sync state.
pub fn view_cache_file(dir: &Path, fvk: &FullViewingKey, node_grpc_url: &str) -> PathBuf {
    let wid = fvk.wallet_id().to_string();
    let wid_tail: String = wid.chars().rev().take(16).collect::<Vec<_>>().into_iter().rev().collect();
    let node: String = node_grpc_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(64)
        .collect();
    dir.join(format!("{wid_tail}-{node}.sqlite"))
}

fn move_file(from: &Path, to: &Path) -> Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    // different filesystem: copy, then zero and remove the source
    std::fs::copy(from, to).with_context(|| format!("copying {}", from.display()))?;
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(from) {
        let len = std::fs::metadata(from).map(|m| m.len() as usize).unwrap_or(0);
        let _ = f.write_all(&vec![0u8; len]);
        let _ = f.sync_all();
    }
    std::fs::remove_file(from)?;
    Ok(())
}

fn set_private(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}

/// Move a cached view DB (and its sqlite sidecars) into `home` so pcli resumes
/// from the last synced height. `Ok(false)` when there is nothing cached yet.
pub fn restore_view_db(cache_file: &Path, home: &Path) -> Result<bool> {
    if !cache_file.exists() {
        return Ok(false);
    }
    for sfx in VIEW_SIDECARS {
        let from = PathBuf::from(format!("{}{sfx}", cache_file.display()));
        if from.exists() {
            let to = home.join(format!("{VIEW_FILE}{sfx}"));
            move_file(&from, &to)?;
            set_private(&to);
        }
    }
    Ok(true)
}

/// Move `home`'s view DB back into the persistent cache (before the home is
/// wiped). The DB holds the FVK and decrypted notes, so the cache is 0700/0600.
pub fn save_view_db(home: &Path, cache_file: &Path) -> Result<bool> {
    if !home.join(VIEW_FILE).exists() {
        return Ok(false);
    }
    if let Some(dir) = cache_file.parent() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).recursive(true).create(dir)?;
    }
    for sfx in VIEW_SIDECARS {
        let to = PathBuf::from(format!("{}{sfx}", cache_file.display()));
        let _ = std::fs::remove_file(&to);
        let from = home.join(format!("{VIEW_FILE}{sfx}"));
        if from.exists() {
            move_file(&from, &to)?;
            set_private(&to);
        }
    }
    Ok(true)
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
    /// The binary defaults to a random 18700-18999 port (env
    /// `CW_ORCH_KMS_PENUMBRA_PAGE_PORT` pins it).
    pub page: SocketAddr,
    /// Custody gRPC pcli talks to. The binary defaults to a random 18700-18999
    /// port (env `CW_ORCH_KMS_PENUMBRA_GRPC_PORT` pins it); the pcli home gets
    /// the port actually bound.
    pub custody: SocketAddr,
    pub ttl: Duration,
    pub approval_timeout: Duration,
    /// Parent dir for ephemeral homes; a pointer file `current-home` lives here too.
    pub state_dir: PathBuf,
    /// Persistent directory for pcli's view DB (sync state). `Some`: the DB is
    /// moved into the ephemeral home at start and back here at teardown (also
    /// rescued from a crashed run), so the next run resumes from the last
    /// synced height. `None`: the DB is wiped with the home.
    pub view_cache: Option<PathBuf>,
}

#[derive(Default)]
struct Live {
    account: Option<PinnedAccount>,
    home: Option<PathBuf>,
    expires: Option<Instant>,
    ur: Option<UrCollector>,
    ended: bool,
    /// Public facts about the last scan (format, wallet id, ownership). Never the FVK.
    last_scan: Option<String>,
    /// "resumed <file>", "new <file>" or "ephemeral".
    view_db: Option<String>,
}

struct Shared {
    cfg_pinned: Address,
    node: String,
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
        parse_fvk_export_info(&body).map(|(f, i)| (f, i))
            .map(|(f, i)| { live.last_scan = Some(export_note(&i)); f })
    };
    // never echo key material in errors or logs: only format, wallet id, ownership
    let fvk = match parsed {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("rejected: could not read the FVK export: {e:#}");
            println!("penumbra fvk scan {msg}");
            live.last_scan = Some(msg.clone());
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }
    };
    let own = Ownership::of(&fvk, &s.cfg_pinned);
    let note = format!("{}{}", live.last_scan.take().map(|n| n + "; ").unwrap_or_default(), own.describe());
    println!("penumbra fvk scan: {note}");
    live.last_scan = Some(note.clone());
    let account = match pin(fvk, &s.cfg_pinned) {
        Ok(a) => a,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("rejected: {e:#} [{note}]")).into_response(),
    };
    live.account = Some(account);
    live.ur = None;
    drop(live);
    let _ = s.import_tx.send(true);
    (StatusCode::OK, format!("FVK accepted for the pinned wallet; starting view session [{note}]")).into_response()
}

async fn status(State(s): State<Arc<Shared>>, h: HeaderMap) -> Response {
    if !authed(&s, &h) {
        return (StatusCode::FORBIDDEN, "bad token").into_response();
    }
    let live = s.live.lock().await;
    let state = if live.ended { "ended" } else if live.home.is_some() { "active" } else if live.account.is_some() { "starting" } else { "waiting_for_fvk" };
    let pending = s.approvals.pending_id();
    // The page's stepper reads this; it advances as soon as the import lands.
    let step = match (state, pending) {
        ("ended", _) => "ended",
        ("waiting_for_fvk", _) => "auth",
        ("starting", _) => "starting",
        (_, Some(_)) => "sign",
        _ => "action",
    };
    let j = serde_json::json!({
        "state": state,
        "step": step,
        "approval_id": pending,
        "node": s.node,
        "view_db": live.view_db,
        "wallet_id": live.account.as_ref().map(|a| a.wallet_id()),
        "home": live.home.as_ref().map(|p| p.display().to_string()),
        "expires_in_secs": live.expires.map(|e| e.saturating_duration_since(Instant::now()).as_secs()),
        "pending_approval": s.approvals.is_pending(),
        "last_scan": live.last_scan,
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
    let cache_pointer = cfg.state_dir.join("current-view-cache");
    if let Ok(old) = std::fs::read_to_string(&pointer) {
        // rescue the synced view DB of a crashed run before wiping its home
        if let Ok(cache) = std::fs::read_to_string(&cache_pointer) {
            match save_view_db(Path::new(old.trim()), Path::new(cache.trim())) {
                Ok(true) => println!("rescued view DB from a previous run into {}", cache.trim()),
                Ok(false) => {}
                Err(e) => eprintln!("warn could not rescue view DB: {e:#}"),
            }
        }
        let _ = wipe(Path::new(old.trim()));
        let _ = std::fs::remove_file(&pointer);
    }
    let _ = std::fs::remove_file(&cache_pointer);
    let approvals = page::Approvals::new();
    let tok = approvals.token().to_string();
    let (import_tx, mut import_rx) = watch::channel(false);
    let (end_tx, mut end_rx) = watch::channel(false);
    let shared = Arc::new(Shared {
        cfg_pinned: pinned,
        node: cfg.node_grpc_url.clone(),
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
    let view_mode = match &cfg.view_cache {
        Some(d) => format!("persistent view DB in {}", d.display()),
        None => "ephemeral view DB (wiped at the end)".to_string(),
    };
    let card = page::session_card_with(cfg.pinned_address.trim(), &cfg.node_grpc_url, &view_mode);
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
        let mut cache_file: Option<PathBuf> = None;
        let result: Result<()> = async {
            if ended_early {
                return Ok(());
            }
            let account = shared.live.lock().await.account.clone().ok_or_else(|| anyhow!("no account"))?;
            let dir = cfg.state_dir.join(format!("home-{}", &token()[..12]));
            let custody_listener = crate::port::bind_loopback_quiet(cfg.custody)
                .await
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("binding {}", cfg.custody))?;
            let custody_addr = custody_listener.local_addr()?;
            page::check_bind(custody_addr)?;
            println!("custody gRPC on {custody_addr}");
            write_pcli_home(&dir, &account.fvk, &cfg.node_grpc_url, custody_addr)?;
            std::fs::write(&pointer, dir.display().to_string())?;
            home = Some(dir.clone());
            let view_db = match &cfg.view_cache {
                Some(cdir) => {
                    let f = view_cache_file(cdir, &account.fvk, &cfg.node_grpc_url);
                    std::fs::write(&cache_pointer, f.display().to_string())?;
                    cache_file = Some(f.clone());
                    if restore_view_db(&f, &dir)? {
                        println!("resuming view sync from {}", f.display());
                        format!("resumed {}", f.display())
                    } else {
                        println!("no cached view DB yet; first sync will be saved to {}", f.display());
                        format!("new {}", f.display())
                    }
                }
                None => "ephemeral".to_string(),
            };
            let zc = custody::ZignerCustody::new(account, cfg.policy.clone(), approvals.clone(), cfg.approval_timeout);
            {
                let mut l = shared.live.lock().await;
                l.home = Some(dir.clone());
                l.expires = Some(deadline.into_std());
                l.view_db = Some(view_db);
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
        if let (Some(d), Some(f)) = (&home, &cache_file) {
            match save_view_db(d, f) {
                Ok(true) => println!("view DB kept for the next run: {}", f.display()),
                Ok(false) => {}
                Err(e) => eprintln!("warn could not keep the view DB ({e:#}); it is wiped with the home"),
            }
        }
        if let Some(d) = &home {
            wipe(d)?;
        }
        let _ = std::fs::remove_file(&pointer);
        let _ = std::fs::remove_file(&cache_pointer);
        let _ = stop_tx.send(());
        let _ = page_srv.await;
        println!("ok view session ended; ephemeral home wiped{}", if cache_file.is_some() { " (view DB kept)" } else { "" });
        result
    });
    Ok(Running { page_url, token: tok, done })
}
