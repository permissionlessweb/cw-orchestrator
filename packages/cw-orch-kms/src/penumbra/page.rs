//! The Penumbra page, built on the shared cw-orch-kms page ([`crate::ui_shared`]):
//! same layout, run log, animated Zigner frames and zxing camera scanner
//! (`/zxing/index.min.js`, read from the zafu checkout like every other page).
//!
//! One page serves a whole run: the view session's FVK import and status, and
//! every pending [`Approvals`] request (plan summary, request QR, the phone's
//! answer). Loopback only, never port 8741.

use super::{auth, qr, summary::summarize};
use crate::ui_shared;
use anyhow::{bail, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use penumbra_sdk_keys::FullViewingKey;
use penumbra_sdk_transaction::{AuthorizationData, TransactionPlan};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;

/// cw-orch-kms's Cosmos approval page; never bind it from here.
pub const RESERVED_PORT: u16 = 8741;

pub fn check_bind(addr: SocketAddr) -> Result<()> {
    if !addr.ip().is_loopback() {
        bail!("page binds loopback only, refusing {addr}");
    }
    if addr.port() == RESERVED_PORT {
        bail!("port {RESERVED_PORT} belongs to the cw-orch-kms Cosmos approval page");
    }
    Ok(())
}

struct Pending {
    id: u64,
    plan: TransactionPlan,
    fvk: FullViewingKey,
    view: serde_json::Value,
    done: Option<oneshot::Sender<Result<AuthorizationData, String>>>,
}

/// Plans waiting for the phone. One phone, one approval at a time.
pub struct Approvals {
    token: String,
    next: Mutex<u64>,
    pending: Mutex<Option<Pending>>,
    /// How the last request ended (public facts only), for the page's broadcast step.
    last: Mutex<Option<serde_json::Value>>,
    gate: tokio::sync::Mutex<()>,
}

impl Approvals {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            token: ui_shared::approval_token(),
            next: Mutex::new(0),
            pending: Mutex::new(None),
            last: Mutex::new(None),
            gate: tokio::sync::Mutex::new(()),
        })
    }

    /// Page token: every POST and `/approval`, `/status` read must carry it.
    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn is_pending(&self) -> bool {
        self.pending.lock().unwrap().is_some()
    }

    /// Id of the request waiting for the phone, if any.
    pub fn pending_id(&self) -> Option<u64> {
        self.pending.lock().unwrap().as_ref().map(|p| p.id)
    }

    fn finish(&self, id: u64, result: &str, message: &str) {
        *self.last.lock().unwrap() = Some(serde_json::json!({ "id": id, "result": result, "message": message }));
    }

    /// Put `plan` on the page and wait until Zigner's answer verifies against
    /// the pinned FVK, the page refuses it, or `timeout` passes.
    pub async fn approve(
        &self,
        plan: &TransactionPlan,
        fvk: &FullViewingKey,
        asset_names: Vec<String>,
        timeout: Duration,
    ) -> Result<AuthorizationData> {
        let _one = self.gate.lock().await;
        let summary = summarize(plan, fvk);
        let request = qr::ZignerRequest::from_plan(plan, fvk, asset_names)?.encode()?;
        let frames = ui_shared::zigner_frames(&request).map_err(anyhow::Error::msg)?;
        let svgs: Vec<String> = frames.iter().map(|f| ui_shared::frame_svg(f)).collect();
        let id = {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            *n
        };
        let view = serde_json::json!({
            "id": id,
            "chain": summary.chain_id,
            "expiry": summary.expiry_height,
            "fee": summary.fee,
            "effect_hash": summary.effect_hash,
            "wallet": fvk.wallet_id().to_string(),
            "actions": summary.actions,
            "warnings": summary.warnings,
            "frames": svgs,
        });
        let (tx, rx) = oneshot::channel();
        *self.pending.lock().unwrap() = Some(Pending { id, plan: plan.clone(), fvk: fvk.clone(), view, done: Some(tx) });
        println!("penumbra approval {id} waiting on the page ({} frame{})", frames.len(), if frames.len() == 1 { "" } else { "s" });
        for line in summary.actions.iter() {
            println!("  {line}");
        }
        for line in summary.warnings.iter() {
            println!("  warn {line}");
        }
        let out = tokio::time::timeout(timeout, rx).await;
        *self.pending.lock().unwrap() = None;
        match out {
            Err(_) => {
                eprintln!("penumbra approval {id} timed out");
                self.finish(id, "timed_out", "the approval timed out before a valid signature was scanned");
                bail!("approval timed out")
            }
            Ok(Err(_)) => {
                self.finish(id, "closed", "the approval page closed");
                bail!("approval page closed")
            }
            Ok(Ok(Err(e))) => {
                eprintln!("penumbra approval {id} refused: {e}");
                self.finish(id, "refused", &e);
                bail!(e)
            }
            Ok(Ok(Ok(d))) => {
                println!("penumbra approval {id} verified");
                self.finish(id, "verified", "signature verified; handed back to pcli to build and broadcast");
                Ok(d)
            }
        }
    }
}

fn loopback_host(h: &HeaderMap) -> bool {
    let host = h.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    let name = host.rsplit_once(':').map(|(a, _)| a).unwrap_or(host);
    matches!(name, "127.0.0.1" | "localhost" | "[::1]")
}

/// Loopback Host header and the page token.
pub fn authed(token: &str, h: &HeaderMap) -> bool {
    loopback_host(h) && h.get("x-approval-token").and_then(|v| v.to_str().ok()) == Some(token)
}

struct PageState {
    html: String,
    zxing: Vec<u8>,
    approvals: Arc<Approvals>,
}

async fn index(State(s): State<Arc<PageState>>, h: HeaderMap) -> Response {
    if !loopback_host(&h) {
        return (StatusCode::FORBIDDEN, "loopback only").into_response();
    }
    Html(s.html.clone()).into_response()
}

async fn zxing_js(State(s): State<Arc<PageState>>) -> Response {
    ui_shared::vendor_response(&s.zxing, "text/javascript")
}

async fn approval(State(s): State<Arc<PageState>>, h: HeaderMap) -> Response {
    if !authed(&s.approvals.token, &h) {
        return (StatusCode::FORBIDDEN, "bad token").into_response();
    }
    let view = s.approvals.pending.lock().unwrap().as_ref().map(|p| p.view.clone());
    ([("content-type", "application/json")], view.unwrap_or(serde_json::Value::Null).to_string()).into_response()
}

async fn outcome(State(s): State<Arc<PageState>>, h: HeaderMap) -> Response {
    if !authed(&s.approvals.token, &h) {
        return (StatusCode::FORBIDDEN, "bad token").into_response();
    }
    let last = s.approvals.last.lock().unwrap().clone();
    ([("content-type", "application/json")], last.unwrap_or(serde_json::Value::Null).to_string()).into_response()
}

async fn response(State(s): State<Arc<PageState>>, h: HeaderMap, body: axum::body::Bytes) -> Response {
    if !authed(&s.approvals.token, &h) {
        return (StatusCode::FORBIDDEN, "bad token").into_response();
    }
    let mut slot = s.approvals.pending.lock().unwrap();
    let Some(p) = slot.as_mut() else {
        return (StatusCode::CONFLICT, "err nothing is waiting for approval").into_response();
    };
    match auth::ZignerResponse::decode_text_or_bytes(&body).and_then(|r| auth::verify_response(&p.plan, &p.fvk, &r)) {
        Ok(data) => {
            if let Some(tx) = p.done.take() {
                let _ = tx.send(Ok(data));
            }
            (StatusCode::OK, format!("ok approval {} verified against the pinned account", p.id)).into_response()
        }
        // A bad scan can be retried.
        Err(e) => (StatusCode::BAD_REQUEST, format!("err {e:#}")).into_response(),
    }
}

async fn refuse(State(s): State<Arc<PageState>>, h: HeaderMap) -> Response {
    if !authed(&s.approvals.token, &h) {
        return (StatusCode::FORBIDDEN, "bad token").into_response();
    }
    let mut slot = s.approvals.pending.lock().unwrap();
    match slot.as_mut().and_then(|p| p.done.take()) {
        Some(tx) => {
            let _ = tx.send(Err("refused on the approval page".into()));
            (StatusCode::OK, "err refused").into_response()
        }
        None => (StatusCode::CONFLICT, "err nothing is waiting for approval").into_response(),
    }
}

/// The page router: `/`, `/zxing/index.min.js`, `/approval`, `/outcome`, `/response`,
/// `/refuse`, plus `extra` (the session's `/fvk`, `/status`, `/end`).
pub fn router(approvals: Arc<Approvals>, session_card: Option<&str>, extra: Router) -> Router {
    let html = html(approvals.token(), session_card);
    let state = Arc::new(PageState { html, zxing: ui_shared::zxing_js_bytes(), approvals });
    Router::new()
        .route("/", get(index))
        .route("/zxing/index.min.js", get(zxing_js))
        .route("/approval", get(approval))
        .route("/outcome", get(outcome))
        .route("/response", post(response))
        .route("/refuse", post(refuse))
        .with_state(state)
        .merge(extra)
        .layer(middleware::from_fn(ui_shared::isolate))
}

/// Bind `addr` (loopback, not 8741; a taken 18700-18999 port is re-picked)
/// and serve `app` until `stop` fires. Prints the URL and the tunnel line.
pub async fn serve(
    addr: SocketAddr,
    app: Router,
) -> Result<(String, oneshot::Sender<()>, tokio::task::JoinHandle<()>)> {
    check_bind(addr)?;
    let listener = crate::port::bind_loopback_quiet(addr).await.map_err(anyhow::Error::msg).with_context(|| format!("binding {addr}"))?;
    let bound = listener.local_addr()?;
    check_bind(bound)?;
    crate::port::announce("penumbra page", bound);
    let url = format!("http://{bound}/");
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stop_rx.await;
            })
            .await;
    });
    Ok((url, stop_tx, task))
}

/// Status header: connection to this process, session state, wallet, TTL.
const STATUS_BAR: &str = "<section class=\"statusbar\" id=\"statusbar\" aria-live=\"polite\">\
<span class=\"conn\"><span class=\"dot wait\" id=\"conn-dot\"></span><span id=\"conn-text\">connecting</span></span>\
<span class=\"badge wait\" id=\"state-badge\">starting</span>\
<span class=\"chip\" id=\"wallet-chip\" hidden></span>\
<span class=\"ttl\" id=\"ttl\"></span>\
</section>";

/// Auth → Action → Sign → Broadcast. Steps the run does not have are hidden.
const STEPPER: &str = "<ol class=\"stepper\" id=\"stepper\">\
<li data-step=\"auth\"><span class=\"num\">1</span><span class=\"name\">Auth</span><span class=\"sub\">viewing key</span></li>\
<li data-step=\"action\"><span class=\"num\">2</span><span class=\"name\">Action</span><span class=\"sub\">review the plan</span></li>\
<li data-step=\"sign\"><span class=\"num\">3</span><span class=\"name\">Sign</span><span class=\"sub\">Zigner</span></li>\
<li data-step=\"broadcast\"><span class=\"num\">4</span><span class=\"name\">Broadcast</span><span class=\"sub\">pcli</span></li>\
</ol>";

/// One panel per step, one at a time.
const STEP_PANEL: &str = "<section class=\"card\" id=\"step-panel\">\
<div id=\"panel-auth\" hidden>\
<p class=\"kicker\">Step 1 · Auth</p><h2>Import the viewing key</h2>\
<p class=\"lede\">On Zigner: open the Penumbra key, choose Export viewing key, and scan it with the scanner below. Only a key that owns the pinned address is accepted.</p>\
</div>\
<div id=\"panel-starting\" hidden>\
<p class=\"kicker\">Step 1 · Auth</p><h2>Viewing key accepted</h2>\
<p class=\"lede\">Starting the view session and custody service…</p>\
</div>\
<div id=\"panel-action\" hidden>\
<p class=\"kicker\">Step 2 · Action</p><h2>Waiting for a transaction</h2>\
<p class=\"lede\">Run a pcli command against this session. Its plan appears here for review and signing.</p>\
<pre class=\"cmd\" id=\"session-run\"></pre>\
</div>\
<div id=\"panel-approval\" hidden>\
<p class=\"kicker\" id=\"approval-kicker\">Step 3 · Sign</p><h2 id=\"approval-title\">Review and sign</h2>\
<dl class=\"facts\" id=\"plan-meta\"></dl>\
<div class=\"actions\" id=\"action-cards\"></div>\
<div id=\"plan-warnings\"></div>\
<p class=\"lede\">Scan this code with Zigner, check the transaction on the phone, then scan Zigner's signature with the scanner below.</p>\
<div id=\"zigner-qr\"></div>\
<div class=\"row\"><button class=\"btn ghost danger\" id=\"refuse\" type=\"button\">Refuse</button></div>\
</div>\
<div id=\"panel-broadcast\" hidden>\
<p class=\"kicker\">Step 4 · Broadcast</p><h2 id=\"outcome-title\">Signed</h2>\
<div class=\"alert\" id=\"outcome\"></div>\
</div>\
<div id=\"panel-ended\" hidden>\
<p class=\"kicker\">Session</p><h2>Session ended</h2>\
<p class=\"lede\">The view home was wiped. Start a new session to continue.</p>\
</div>\
</section>";

/// The one scanner: same place for every step; its target follows the step.
const SCANNER: &str = "<section class=\"card scanner\" id=\"scanner\">\
<p class=\"kicker\">Scanner</p><h2 id=\"scan-title\">Scanner</h2>\
<p class=\"lede\" id=\"scan-hint\"></p>\
<video id=\"camera\" hidden playsinline muted></video>\
<p id=\"scan-status\"></p>\
<div class=\"row\"><button class=\"btn\" id=\"scan\" type=\"button\">Start camera</button></div>\
<details><summary>Paste instead</summary>\
<label>What Zigner shows (hex, ur:, or penumbrafullviewingkey1…)<input id=\"paste\" autocomplete=\"off\" spellcheck=\"false\"></label>\
<button class=\"btn ghost\" id=\"check\" type=\"button\">Check</button>\
</details>\
<div class=\"alert\" id=\"check-result\" role=\"status\" hidden></div>\
</section>";

/// Session details (pinned address, node, view DB) and End. Public data only.
pub fn session_card(pinned_address: &str) -> String {
    session_card_with(pinned_address, "", "")
}

/// [`session_card`] with the node and view-DB mode shown.
pub fn session_card_with(pinned_address: &str, node: &str, view_mode: &str) -> String {
    let mut facts = format!("<dt>pinned address</dt><dd>{}</dd>", ui_shared::escape(pinned_address));
    if !node.is_empty() {
        facts += &format!("<dt>penumbra node</dt><dd>{}</dd>", ui_shared::escape(node));
    }
    if !view_mode.is_empty() {
        facts += &format!("<dt>view sync</dt><dd id=\"view-db\">{}</dd>", ui_shared::escape(view_mode));
    }
    format!(
        "<section class=\"card\" id=\"session-card\">\
<p class=\"kicker\">View session</p>\
<dl class=\"facts\">{facts}</dl>\
<p class=\"meta\" id=\"session-state\"></p>\
<div class=\"row\"><button class=\"btn ghost danger\" id=\"end\" type=\"button\">End session (wipe)</button></div>\
</section>"
    )
}

fn html(token: &str, session: Option<&str>) -> String {
    let body = format!(
        "<script type=\"application/json\" id=\"page-token\">{}</script>{STATUS_BAR}{STEPPER}{STEP_PANEL}{SCANNER}{}",
        ui_shared::json_string(token),
        session.unwrap_or("")
    );
    ui_shared::page_shell(
        "PENUMBRA",
        if session.is_some() { "Cold wallet session" } else { "Approve with Zigner" },
        "The phone holds the spend key. This page shows the plan, the request code and checks the phone's answer against the pinned account.",
        &body,
        PAGE_SCRIPT,
    )
}

const PAGE_SCRIPT: &str = r##"<script>
(function () {
  var T = JSON.parse(document.getElementById("page-token").textContent);
  var H = { "x-approval-token": T };
  var $ = function (id) { return document.getElementById(id); };
  var video = $("camera"), scanStatus = $("scan-status"), result = $("check-result");
  var session = !!$("session-card");
  // ui: one source of truth, rendered by render()
  var ui = { step: session ? "auth" : "action", status: null, view: null, outcome: null, online: null, busy: false };
  var scan = { reader: null, gen: 0, wanted: false, lastSent: "", target: null };
  var shownApproval = 0, seenOutcome = 0;

  function kind(text) { return /^(ok|FVK accepted)/.test(text) ? "ok" : /^(err|rejected|bad|session already)/.test(text) ? "err" : "wait"; }
  function alertBox(el, k, text) { el.hidden = !text; el.className = "alert " + k; el.textContent = text || ""; }
  function note(text, k) { k = k || kind(text); alertBox(result, k, text); cwOrchLog(k, text); }

  // ---- scanner: one reader at a time; callbacks from a stopped reader are dropped ----
  function targetFor(step) { return step === "auth" ? "/fvk" : step === "sign" ? "/response" : null; }
  function stopScan() {
    scan.gen++;
    if (scan.reader) cwOrchScan.stop(scan.reader, video);
    scan.reader = null;
    scanStatus.textContent = "";
    $("scan").textContent = "Start camera";
  }
  function startScan() {
    stopScan();
    var gen = scan.gen;
    scan.lastSent = "";
    scan.wanted = true;
    scan.reader = cwOrchScan.start(video, scanStatus, function (text) { if (gen === scan.gen) onText(text); });
    if (scan.reader) $("scan").textContent = "Stop camera";
  }
  // zxing returns byte-mode codes as latin-1 text; send them as hex.
  function enc(s) {
    if (/^(penumbrafullviewingkey1|ur:)/i.test(s) || /^[0-9a-f]+$/i.test(s)) return s;
    var h = "";
    for (var i = 0; i < s.length; i++) h += ("0" + (s.charCodeAt(i) & 255).toString(16)).slice(-2);
    return h;
  }
  function submit(text) {
    var path = targetFor(ui.step);
    if (!path) { note("nothing to scan right now: " + (ui.step === "action" ? "waiting for a transaction" : ui.step), "wait"); return Promise.resolve(0); }
    ui.busy = true; renderScanner();
    return fetch(path, { method: "POST", headers: H, body: text }).then(function (r) {
      return r.text().then(function (t) {
        ui.busy = false;
        if (r.status === 202) { scanStatus.textContent = t; return 202; }
        note(t, r.status === 200 ? "ok" : "err");
        if (r.status === 200) { stopScan(); scan.lastSent = ""; }
        refresh(); // advance now; do not wait for the next poll
        return r.status;
      });
    }).catch(function () { ui.busy = false; note("err the page lost the session process", "err"); });
  }
  function onText(text) {
    if (text === scan.lastSent || ui.busy) return;
    scan.lastSent = text;
    submit(enc(text));
  }
  $("scan").onclick = function () { if (scan.reader) { scan.wanted = false; stopScan(); } else startScan(); };
  $("check").onclick = function () { var v = $("paste").value.trim(); if (v) submit(v); };
  $("refuse").onclick = function () {
    fetch("/refuse", { method: "POST", headers: H }).then(function (r) { return r.text(); }).then(function (t) { note(t, "err"); refresh(); });
  };
  var endButton = $("end");
  if (endButton) endButton.onclick = function () {
    fetch("/end", { method: "POST", headers: H }).then(function (r) { return r.text(); }).then(function (t) { note(t, "wait"); refresh(); });
  };

  // ---- step changes re-target and re-arm the scanner ----
  function setStep(step) {
    if (step === ui.step) return;
    var before = targetFor(ui.step), after = targetFor(step);
    ui.step = step;
    if (before !== after) {
      stopScan();
      result.hidden = true;
      // the camera was on for the previous scan: keep it on for the next one
      if (after && scan.wanted) startScan();
    }
    if (step === "ended") { scan.wanted = false; stopScan(); }
  }

  // ---- render ----
  var ORDER = ["auth", "action", "sign", "broadcast"];
  function stepIndex(step) { return step === "starting" ? 0 : step === "ended" ? 4 : ORDER.indexOf(step); }
  function renderStepper() {
    var at = stepIndex(ui.step);
    Array.prototype.forEach.call(document.querySelectorAll("#stepper li"), function (li) {
      var i = ORDER.indexOf(li.dataset.step);
      li.hidden = !session && li.dataset.step === "auth";
      li.className = i < at || ui.step === "broadcast" && i === at ? "is-done" : i === at ? "is-on" : "";
    });
  }
  function renderPanels() {
    ["auth", "starting", "action", "approval", "broadcast", "ended"].forEach(function (p) { $("panel-" + p).hidden = true; });
    var panel = ui.step === "sign" ? "approval" : ui.step;
    var el = $("panel-" + panel);
    if (el) el.hidden = false;
  }
  function renderScanner() {
    var t = targetFor(ui.step);
    $("scanner").classList.toggle("idle", !t);
    $("scan-title").textContent = ui.step === "auth" ? "Scan the viewing key export" : ui.step === "sign" ? "Scan Zigner's signature" : "Scanner idle";
    $("scan-hint").textContent = ui.busy ? "checking…" : ui.step === "auth" ? "Point the camera at Zigner's Export viewing key QR."
      : ui.step === "sign" ? "After approving on Zigner, point the camera at the signature QR it shows."
      : ui.step === "ended" ? "The session has ended." : "Nothing to scan until a transaction is waiting. The camera re-arms by itself when one arrives.";
    $("scan").disabled = !t; $("check").disabled = !t || ui.busy;
  }
  function renderStatus() {
    var dot = $("conn-dot"), txt = $("conn-text"), badge = $("state-badge");
    dot.className = "dot " + (ui.online === false ? "err" : ui.online ? "ok" : "wait");
    txt.textContent = ui.online === false ? "process unreachable" : ui.online ? "connected" : "connecting";
    var labels = { auth: "waiting for viewing key", starting: "starting session", action: "ready", sign: "awaiting signature", broadcast: "signed", ended: "ended" };
    badge.textContent = labels[ui.step] || ui.step;
    badge.className = "badge " + (ui.step === "ended" ? "err" : ui.step === "action" || ui.step === "broadcast" ? "ok" : "wait");
    var s = ui.status;
    var chip = $("wallet-chip");
    chip.hidden = !(s && s.wallet_id); if (s && s.wallet_id) chip.textContent = s.wallet_id;
    $("ttl").textContent = s && s.expires_in_secs != null ? "expires in " + Math.floor(s.expires_in_secs / 60) + "m " + (s.expires_in_secs % 60) + "s" : "";
    if (session && s) {
      $("session-state").textContent = s.last_scan ? "last scan: " + s.last_scan : "";
      $("session-run").textContent = s.home ? "pcli --home " + s.home + " view balance" : "";
      if (s.view_db && $("view-db")) $("view-db").textContent = s.view_db;
    }
  }
  function renderApproval(view) {
    if (!view) { if (shownApproval) { animateQr($("zigner-qr"), [], ""); shownApproval = 0; } return; }
    if (view.id === shownApproval) return;
    shownApproval = view.id;
    $("approval-title").textContent = "Review and sign · request " + view.id;
    var meta = $("plan-meta"); meta.textContent = "";
    [["chain", view.chain], ["expiry height", String(view.expiry)], ["fee", view.fee], ["wallet", view.wallet], ["effect hash", view.effect_hash]].forEach(function (r) {
      var dt = document.createElement("dt"); dt.textContent = r[0]; var dd = document.createElement("dd"); dd.textContent = r[1]; meta.appendChild(dt); meta.appendChild(dd);
    });
    var cards = $("action-cards"); cards.textContent = "";
    view.actions.forEach(function (a, i) {
      var c = document.createElement("div"); c.className = "action-card";
      var n = document.createElement("span"); n.className = "num"; n.textContent = String(i + 1);
      var t = document.createElement("span"); t.textContent = a;
      c.appendChild(n); c.appendChild(t); cards.appendChild(c);
    });
    var warn = $("plan-warnings"); warn.textContent = "";
    view.warnings.forEach(function (w) { var d = document.createElement("div"); d.className = "alert err"; d.textContent = w; warn.appendChild(d); });
    animateQr($("zigner-qr"), view.frames, view.frames[0]);
    cwOrchLog("wait", "approval " + view.id + " waiting for the phone");
  }
  function renderOutcome(o) {
    if (!o) return;
    var good = o.result === "verified";
    $("outcome-title").textContent = good ? "Signed · request " + o.id : "Not signed · request " + o.id;
    alertBox($("outcome"), good ? "ok" : "err", good ? "Zigner's signature verified against the pinned account. pcli is building and broadcasting the transaction: watch its terminal for the tx hash." : o.message);
  }
  function render() { renderStatus(); renderStepper(); renderPanels(); renderScanner(); }

  // ---- state: polled, and re-read right after every POST ----
  function deriveStep() {
    var s = ui.status;
    if (session && s && s.step && s.step !== "action" && s.step !== "sign") return s.step;
    if (ui.view) return "sign";
    if (ui.outcome && ui.outcome.id > seenOutcome) return "broadcast";
    return session && s && s.step === "auth" ? "auth" : "action";
  }
  var inflight = false;
  function refresh() {
    if (inflight) return; inflight = true;
    var reads = [
      fetch("/approval", { headers: H }).then(function (r) { if (!r.ok) throw r; return r.json(); }),
      fetch("/outcome", { headers: H }).then(function (r) { return r.ok ? r.json() : null; }),
      session ? fetch("/status", { headers: H }).then(function (r) { if (!r.ok) throw r; return r.json(); }) : Promise.resolve(null)
    ];
    Promise.all(reads).then(function (got) {
      ui.online = true;
      var hadView = ui.view;
      ui.view = got[0]; ui.outcome = got[1]; ui.status = got[2];
      if (ui.view && ui.outcome) seenOutcome = Math.max(seenOutcome, ui.outcome.id); // a new request supersedes the last outcome
      if (!ui.view && hadView && ui.outcome && ui.outcome.id >= hadView.id) seenOutcome = hadView.id - 1;
      renderApproval(ui.view); renderOutcome(ui.outcome);
      setStep(deriveStep());
    }).catch(function () {
      ui.online = false;
      if (scan.reader) stopScan();
    }).then(function () { inflight = false; render(); });
  }
  render();
  refresh();
  setInterval(refresh, 1000);
})();
</script>"##;
