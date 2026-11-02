//! Run progress shared by every approval page in this process.
//!
//! The granter challenge, the session authorization and the tx sets the
//! session key broadcasts (simulate, broadcast, revoke) are separate page
//! servers, and a run may open several of them in a row (one per batch). The
//! browser tab cannot know when one server closes and the next one binds, so
//! every page polls `/state` (right after each POST/scan, then every second)
//! and follows the run:
//!
//! - `instance` changes whenever a new page server starts serving on the port
//!   (another phase, the next batch, or the next process). A page that sees a
//!   different `instance` reloads itself, which re-arms the scanner for the
//!   new step without a manual refresh or relaunch.
//! - `step`/`total`/`steps` are the explicit per-step state the page renders:
//!   step N of M, batch k/K, waiting/signed/broadcast/confirmed/error, tx hash.
//!
//! Between two page servers (the daemon builds, the chain is queried) a small
//! standby server keeps answering `/` and `/state` on the same port, so the
//! tab shows "waiting for the next step" instead of a dead connection.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// One step's state as the page shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Waiting,
    Running,
    Signed,
    Broadcast,
    Confirmed,
    Error,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Waiting => "waiting",
            Status::Running => "running",
            Status::Signed => "signed",
            Status::Broadcast => "broadcast",
            Status::Confirmed => "confirmed",
            Status::Error => "error",
        }
    }
    fn finished(self) -> bool {
        matches!(self, Status::Signed | Status::Broadcast | Status::Confirmed)
    }
}

/// The plan used when the caller set none: one session from challenge to revoke.
pub const DEFAULT_PLAN: [&str; 5] = ["granter challenge", "authorize", "simulate", "broadcast", "revoke"];

/// One planned step: `label` within batch `batch` of `batches`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub label: String,
    pub batch: u32,
    pub batches: u32,
    pub status: Status,
    pub tx_hash: Option<String>,
    pub detail: Option<String>,
}

#[derive(Default)]
struct State {
    steps: Vec<Step>,
    batch: u32,
    batches: u32,
    phase: String,
    /// Set while no page server is up (between phases, or after the run).
    standby: bool,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);
static SERVED: AtomicU64 = AtomicU64::new(0);

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut guard = STATE.lock().unwrap_or_else(|p| p.into_inner());
    f(guard.get_or_insert_with(|| State { batch: 1, batches: 1, ..State::default() }))
}

fn process_salt() -> u64 {
    static SALT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SALT.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        (u64::from(std::process::id()) << 32) ^ nanos ^ rand::random::<u64>()
    })
}

/// A fresh page-server instance id, unique across phases and processes.
pub(crate) fn next_instance() -> String {
    let n = SERVED.fetch_add(1, Ordering::SeqCst) + 1;
    format!("{:016x}-{n}", process_salt())
}

/// Which batch of how many this process runs (shown as "batch k/K").
pub fn set_batch(batch: u32, batches: u32) {
    with(|s| {
        s.batch = batch.max(1);
        s.batches = batches.max(batch).max(1);
        for step in s.steps.iter_mut().filter(|st| st.status == Status::Waiting) {
            step.batch = s.batch;
            step.batches = s.batches;
        }
    });
}

/// Replace the plan with `labels` (all waiting) for the current batch.
pub fn plan(labels: &[&str]) {
    with(|s| {
        let (batch, batches) = (s.batch, s.batches);
        s.steps = labels
            .iter()
            .map(|label| Step {
                label: (*label).to_string(),
                batch,
                batches,
                status: Status::Waiting,
                tx_hash: None,
                detail: None,
            })
            .collect();
    });
}

/// Set `label`'s status in the current batch (appended when it was not planned).
pub fn update(label: &str, status: Status, tx_hash: Option<&str>) {
    update_detail(label, status, tx_hash, None);
}

/// [`update`] with a short detail line (an error, gas, a count). Never pass secrets.
pub fn update_detail(label: &str, status: Status, tx_hash: Option<&str>, detail: Option<&str>) {
    with(|s| {
        let (batch, batches) = (s.batch, s.batches);
        let index = match s.steps.iter().position(|st| st.label == label && st.batch == batch) {
            Some(index) => index,
            None => {
                s.steps.push(Step {
                    label: label.to_string(),
                    batch,
                    batches,
                    status: Status::Waiting,
                    tx_hash: None,
                    detail: None,
                });
                s.steps.len() - 1
            }
        };
        let step = &mut s.steps[index];
        step.status = status;
        if let Some(hash) = tx_hash {
            step.tx_hash = Some(hash.to_string());
        }
        if let Some(detail) = detail {
            step.detail = Some(detail.to_string());
        }
    });
}

pub(crate) fn set_phase(phase: &str, standby: bool) {
    with(|s| {
        s.phase = phase.to_string();
        s.standby = standby;
    });
}

/// A copy of the steps, in order.
pub fn steps() -> Vec<Step> {
    with(|s| s.steps.clone())
}

/// The 1-based step the run is on: the first step that is not finished.
pub fn current_step() -> usize {
    with(|s| current(&s.steps))
}

fn current(steps: &[Step]) -> usize {
    match steps.iter().position(|st| !st.status.finished()) {
        Some(index) => index + 1,
        None => steps.len(),
    }
}

/// Forget the plan (tests, or a script that starts a fresh run in-process).
pub fn reset() {
    let mut guard = STATE.lock().unwrap_or_else(|p| p.into_inner());
    *guard = None;
}

fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '<' => out.push_str("\\u003c"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The `/state` body for the page server `instance`.
pub(crate) fn state_json(instance: &str) -> String {
    with(|s| {
        let mut steps = String::from("[");
        for (index, st) in s.steps.iter().enumerate() {
            if index > 0 {
                steps.push(',');
            }
            steps.push_str(&format!(
                "{{\"label\":{},\"batch\":{},\"batches\":{},\"status\":{},\"tx_hash\":{},\"detail\":{}}}",
                esc(&st.label),
                st.batch,
                st.batches,
                esc(st.status.as_str()),
                st.tx_hash.as_deref().map(esc).unwrap_or_else(|| "null".into()),
                st.detail.as_deref().map(esc).unwrap_or_else(|| "null".into()),
            ));
        }
        steps.push(']');
        let error = s.steps.iter().any(|st| st.status == Status::Error);
        let done = !s.steps.is_empty() && s.steps.iter().all(|st| st.status.finished());
        format!(
            "{{\"instance\":{},\"phase\":{},\"standby\":{},\"step\":{},\"total\":{},\"batch\":{},\"batches\":{},\"error\":{},\"done\":{},\"steps\":{}}}",
            esc(instance),
            esc(&s.phase),
            s.standby,
            current(&s.steps),
            s.steps.len(),
            s.batch,
            s.batches,
            error,
            done,
            steps,
        )
    })
}

// ---- standby server ---------------------------------------------------------

struct Standby {
    port: u16,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

static STANDBY: Mutex<Option<Standby>> = Mutex::new(None);

const STANDBY_HTML: &str = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>cw-orch run</title>\
<style>body{background:#0D0D12;color:#E0E0E4;font:15px system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px}.ok{color:#50C878}.err{color:#C05050}.wait{color:#F4A31E}code{word-break:break-all}</style></head>\
<body><p>ZAFU · SESSION</p><h1>Waiting for the next step</h1><p>This tab follows the run and opens the next step by itself. Keep it open.</p>\
<div id=\"run-progress\"></div>";

/// Keep `/` and `/state` answering on `port` until the next page binds it.
/// Runs on its own thread so it outlives the runtime that served the last page.
pub(crate) fn start_standby(port: u16) {
    stop_standby();
    // The page that just closed may release the socket a moment later.
    let mut tries = 0;
    let std_listener = loop {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => break listener,
            Err(_) if tries < 40 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(_) => return,
        }
    };
    let _ = std_listener.set_nonblocking(true);
    let instance = next_instance();
    set_phase("waiting for the next step", true);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let thread = std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
            return;
        };
        runtime.block_on(async move {
            let Ok(listener) = tokio::net::TcpListener::from_std(std_listener) else {
                return;
            };
            let state_instance = instance.clone();
            let html = format!("{STANDBY_HTML}{}<script>cwOrchFollow({});</script></body></html>", crate::ui_shared::FOLLOW_SCRIPT, esc(&instance));
            let app = axum::Router::new()
                .route("/", axum::routing::get(move || {
                    let html = html.clone();
                    async move { axum::response::Html(html) }
                }))
                .route("/state", axum::routing::get(move || {
                    let body = state_json(&state_instance);
                    async move { state_response(body) }
                }));
            // Not a graceful shutdown: a polling tab keeps a keep-alive
            // connection open, and the next page must get the port now.
            tokio::select! {
                _ = axum::serve(listener, app) => {}
                _ = stop_rx => {}
            }
        });
    });
    *STANDBY.lock().unwrap_or_else(|p| p.into_inner()) =
        Some(Standby { port, stop: Some(stop_tx), thread: Some(thread) });
}

/// Release the standby port (called before a page binds). Waits for the socket to close.
pub(crate) fn stop_standby() {
    let taken = STANDBY.lock().unwrap_or_else(|p| p.into_inner()).take();
    if let Some(mut standby) = taken {
        if let Some(stop) = standby.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = standby.thread.take() {
            let _ = thread.join();
        }
        let _ = standby.port;
    }
}

/// The port the standby server holds, if any.
pub fn standby_port() -> Option<u16> {
    STANDBY.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(|s| s.port)
}

pub(crate) fn state_response(body: String) -> axum::response::Response {
    axum::response::Response::builder()
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(axum::body::Body::from(body))
        .expect("state response")
}

/// Tests share the process-global plan; they serialize on this.
#[cfg(test)]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::SigningRequest;
    use crate::terminal::{capture_granter_sync, listen_bundles, set_approval_chain_id, PageBundle};
    use futures_util::{SinkExt, StreamExt};
    use sha2::Digest;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn signed(message: &[u8]) -> (String, String, String) {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let sk = k256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let pk = sk.verifying_key().to_sec1_point(true);
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&sha2::Sha256::digest(message)).unwrap();
        let addr = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("terp").unwrap(),
            ripemd::Ripemd160::digest(sha2::Sha256::digest(pk.as_bytes())).as_slice(),
        )
        .unwrap();
        let b64 = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b);
        (addr, b64(pk.as_bytes()), b64(&sig.to_bytes()))
    }

    async fn get(addr: SocketAddr, path: &str) -> Option<(u16, String)> {
        let mut stream = TcpStream::connect(addr).await.ok()?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.ok()?;
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.ok()?;
        let code = raw.split_whitespace().nth(1)?.parse().ok()?;
        Some((code, raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string()))
    }

    /// What the page's poller sees on `/state` (waits for a server to answer).
    async fn state(addr: SocketAddr) -> serde_json::Value {
        for _ in 0..200 {
            if let Some((200, body)) = get(addr, "/state").await {
                return serde_json::from_str(&body).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no page server answered /state on {addr}");
    }

    /// Wait until `/state` is served by a server other than `old`.
    async fn next_instance_state(addr: SocketAddr, old: &str) -> serde_json::Value {
        for _ in 0..200 {
            let s = state(addr).await;
            if s["instance"] != old {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the page server on {addr} never changed");
    }

    fn status(s: &serde_json::Value, label: &str) -> String {
        s["steps"].as_array().unwrap().iter().find(|st| st["label"] == label).unwrap()["status"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn ws(addr: SocketAddr) -> tokio_tungstenite::WebSocketStream<TcpStream> {
        let (mut socket, _) = tokio_tungstenite::client_async(format!("ws://{addr}/ws"), TcpStream::connect(addr).await.unwrap())
            .await
            .unwrap();
        let _prompt = socket.next().await.unwrap().unwrap();
        socket
    }

    async fn reply(socket: &mut tokio_tungstenite::WebSocketStream<TcpStream>) -> String {
        loop {
            match socket.next().await.unwrap().unwrap() {
                tokio_tungstenite::tungstenite::Message::Text(t) if !t.starts_with("log ") => return t.to_string(),
                _ => {}
            }
        }
    }

    /// The session challenge is approved, then the same tab (same port, no
    /// reload by hand, no relaunch) follows the session authorization and the
    /// tx sets simulate -> broadcast -> revoke, for three batches in a row.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_the_challenge_the_page_walks_the_tx_sets_across_batches() {
        let _guard = TEST_LOCK.lock().await;
        set_approval_chain_id("morocco-1").unwrap();
        reset();
        let port = crate::port::free_port(None);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut last_instance = String::new();
        for batch in 1..=3u32 {
            set_batch(batch, 3);
            plan(&DEFAULT_PLAN);

            // 1. granter challenge page.
            let binding = format!("purpose=test batch={batch}");
            let doc = format!("cw-orch-granter:v1\n{binding}");
            let capture = tokio::task::spawn_blocking(move || capture_granter_sync(addr, 0, &binding));
            let challenge = next_instance_state(addr, &last_instance).await;
            assert_eq!(challenge["step"], 1);
            assert_eq!(challenge["total"], 5);
            assert_eq!(challenge["batch"], batch);
            assert_eq!(challenge["batches"], 3);
            assert_eq!(status(&challenge, "granter challenge"), "running");
            let (_, html) = get(addr, "/").await.unwrap();
            assert!(html.contains("run-progress") && html.contains("cwOrchFollow("), "page follows the run");
            assert!(html.contains("ws.onclose"), "a closed step waits for the next one");
            let (signer, pk, sig) = signed(doc.as_bytes());
            let mut socket = ws(addr).await;
            socket.send(tokio_tungstenite::tungstenite::Message::Text(format!("check {pk} {sig}").into())).await.unwrap();
            assert_eq!(reply(&mut socket).await, format!("valid {signer}"));
            assert_eq!(capture.await.unwrap().unwrap(), signer);
            if std::env::var(crate::port::PORT_ENV).is_err() {
                assert_eq!(crate::port::page_addr().port(), port, "the session page opens on the challenge port");
            }

            // 2. Between pages the standby answers on the same port with a new
            // instance (the tab reloads) and the plan is on step 2.
            let standby = next_instance_state(addr, challenge["instance"].as_str().unwrap()).await;
            assert_eq!(standby["standby"], true);
            assert_eq!(status(&standby, "granter challenge"), "signed");
            assert_eq!(standby["step"], 2);
            let (_, html) = get(addr, "/").await.unwrap();
            assert!(html.contains("<script>cwOrchFollow(") && !html.contains("<script><script>"), "standby runs its follow script");

            // 3. Session authorization page binds the same port (standby released).
            let auth_doc = format!("authorize batch {batch}").into_bytes();
            let bundles = vec![
                PageBundle { title: "authorize 1/1".into(), sign_doc: auth_doc.clone(), messages: vec![SigningRequest::new("grant")] },
                PageBundle { title: "session key".into(), sign_doc: Vec::new(), messages: vec![SigningRequest::new("session-key")] },
            ];
            update(crate::approval::AUTHORIZE_STEP, Status::Running, None);
            let (terminal, authorized, _revoked) = listen_bundles(addr, &signer, bundles, 0, 1).await.unwrap();
            assert_eq!(terminal.addr().port(), port);
            let session = next_instance_state(addr, standby["instance"].as_str().unwrap()).await;
            assert_eq!(session["standby"], false);
            assert_eq!(session["step"], 2);
            let (_, pk, sig) = signed(&auth_doc);
            let mut socket = ws(addr).await;
            socket.send(tokio_tungstenite::tungstenite::Message::Text(format!("check 0 {pk} {sig}").into())).await.unwrap();
            let answer = reply(&mut socket).await;
            assert!(answer.starts_with("authorized") || answer.starts_with("session-ready"), "{answer}");
            assert_eq!(authorized.await.unwrap().len(), 1);
            // What open_authz_session records after the grant broadcast.
            update(crate::approval::AUTHORIZE_STEP, Status::Broadcast, Some("GRANTHASH"));

            // 4. tx sets on the same open page: simulate, broadcast, revoke.
            let s = state(addr).await;
            assert_eq!(s["instance"], session["instance"], "no reload inside the session page");
            assert_eq!(s["step"], 3);
            assert_eq!(s["steps"][2]["label"], "simulate");
            update_detail("simulate", Status::Confirmed, None, Some("gas=1"));
            let s = state(addr).await;
            assert_eq!(s["step"], 4);
            assert_eq!(s["steps"][3]["label"], "broadcast");
            update("broadcast", Status::Broadcast, Some(&format!("TX{batch}")));
            let s = state(addr).await;
            assert_eq!(s["step"], 5);
            assert_eq!(s["steps"][3]["tx_hash"], format!("TX{batch}"));
            update(crate::approval::REVOKE_STEP, Status::Broadcast, Some("REVOKEHASH"));
            let s = state(addr).await;
            assert_eq!(s["done"], true);
            assert_eq!(s["error"], false);
            assert!(s["steps"].as_array().unwrap().iter().all(|st| st["batch"] == batch));

            // 5. What AuthzSession::close does with its page: the port stays
            // answered until the next batch's challenge binds it.
            drop(terminal);
            start_standby(port);
            let after = next_instance_state(addr, session["instance"].as_str().unwrap()).await;
            assert_eq!(after["standby"], true);
            assert_eq!(after["done"], true);
            last_instance = after["instance"].as_str().unwrap().to_string();
        }
        stop_standby();
        reset();
    }

    #[test]
    fn errors_show_as_the_current_step() {
        let _guard = TEST_LOCK.blocking_lock();
        reset();
        set_batch(2, 3);
        plan(&DEFAULT_PLAN);
        update("granter challenge", Status::Signed, None);
        update_detail("authorize", Status::Error, None, Some("session refused: grpc"));
        let s: serde_json::Value = serde_json::from_str(&state_json("x")).unwrap();
        assert_eq!(s["step"], 2);
        assert_eq!(s["error"], true);
        assert_eq!(s["batch"], 2);
        assert_eq!(s["steps"][1]["detail"], "session refused: grpc");
        reset();
    }
}
