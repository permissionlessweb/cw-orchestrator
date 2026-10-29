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
    gate: tokio::sync::Mutex<()>,
}

impl Approvals {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            token: ui_shared::approval_token(),
            next: Mutex::new(0),
            pending: Mutex::new(None),
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
                bail!("approval timed out")
            }
            Ok(Err(_)) => bail!("approval page closed"),
            Ok(Ok(Err(e))) => {
                eprintln!("penumbra approval {id} refused: {e}");
                bail!(e)
            }
            Ok(Ok(Ok(d))) => {
                println!("penumbra approval {id} verified");
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

/// The page router: `/`, `/zxing/index.min.js`, `/approval`, `/response`,
/// `/refuse`, plus `extra` (the session's `/fvk`, `/status`, `/end`).
pub fn router(approvals: Arc<Approvals>, session_card: Option<&str>, extra: Router) -> Router {
    let html = html(approvals.token(), session_card);
    let state = Arc::new(PageState { html, zxing: ui_shared::zxing_js_bytes(), approvals });
    Router::new()
        .route("/", get(index))
        .route("/zxing/index.min.js", get(zxing_js))
        .route("/approval", get(approval))
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

const APPROVAL_CARD: &str = "<section class=\"card\" id=\"approval-card\">\
<p class=\"kicker\">Approval</p>\
<p class=\"lede\" id=\"approval-state\">no transaction is waiting for the phone</p>\
<div id=\"approval-view\"></div>\
<div id=\"zigner-qr\"></div>\
<div class=\"row\"><button id=\"refuse\" type=\"button\" hidden>Refuse</button></div>\
</section>";

const SCAN_CARD: &str = "<section class=\"card\">\
<p class=\"kicker\">Phone</p>\
<video id=\"camera\" hidden playsinline></video>\
<p id=\"scan-status\"></p>\
<button id=\"scan\" type=\"button\">Scan the phone</button>\
<label>Or paste what Zigner shows<input id=\"paste\" autocomplete=\"off\" spellcheck=\"false\"></label>\
<button id=\"check\" type=\"button\">Check</button>\
<p id=\"check-result\"></p>\
</section>";

/// Session card (FVK import, status, end). Public data only.
pub fn session_card(pinned_address: &str) -> String {
    format!(
        "<section class=\"card\" id=\"session-card\">\
<p class=\"kicker\">View session</p>\
<div class=\"row\"><span class=\"chip\" id=\"pinned\">{}</span></div>\
<p class=\"lede\">On Zigner: Penumbra key, Export viewing key, then scan it here. The key stays in this process and an ephemeral pcli home that is wiped when the session ends.</p>\
<p class=\"meta\" id=\"session-state\">waiting for the viewing key</p>\
<pre class=\"meta\" id=\"session-run\"></pre>\
<button id=\"end\" type=\"button\">End session (wipe)</button>\
</section>",
        ui_shared::escape(pinned_address)
    )
}

fn html(token: &str, session: Option<&str>) -> String {
    let body = format!(
        "<script type=\"application/json\" id=\"page-token\">{}</script>{}{APPROVAL_CARD}{SCAN_CARD}",
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

const PAGE_SCRIPT: &str = r#"<script>
(function () {
  var T = JSON.parse(document.getElementById("page-token").textContent);
  var H = { "x-approval-token": T };
  var video = document.getElementById("camera");
  var scanStatus = document.getElementById("scan-status");
  var result = document.getElementById("check-result");
  var session = document.getElementById("session-card");
  var reader = null;
  var shown = 0;
  var state = session ? "waiting_for_fvk" : "active";
  var lastSent = "";
  function kind(text) { return text.indexOf("ok ") === 0 ? "ok" : text.indexOf("err ") === 0 ? "err" : "wait"; }
  function note(text) { result.textContent = text; cwOrchLog(kind(text), text); }
  function post(path, body) {
    return fetch(path, { method: "POST", headers: H, body: body }).then(function (r) {
      return r.text().then(function (t) { note(t); return r.status; });
    });
  }
  // zxing returns byte-mode codes as latin-1 text; send them as hex.
  function enc(s) {
    if (/^(penumbrafullviewingkey1|ur:)/i.test(s) || /^[0-9a-f]+$/i.test(s)) return s;
    var h = "";
    for (var i = 0; i < s.length; i++) h += ("0" + (s.charCodeAt(i) & 255).toString(16)).slice(-2);
    return h;
  }
  function target() { return state === "waiting_for_fvk" ? "/fvk" : "/response"; }
  function stopScan() { cwOrchScan.stop(reader, video); reader = null; scanStatus.textContent = ""; }
  function onText(text) {
    if (text === lastSent) return;
    lastSent = text;
    post(target(), enc(text)).then(function (code) {
      if (code === 202) return;
      if (code === 200) stopScan();
    });
  }
  document.getElementById("scan").onclick = function () {
    stopScan();
    lastSent = "";
    reader = cwOrchScan.start(video, scanStatus, onText);
  };
  document.getElementById("check").onclick = function () {
    post(target(), document.getElementById("paste").value.trim());
  };
  document.getElementById("refuse").onclick = function () { post("/refuse", ""); };
  var endButton = document.getElementById("end");
  if (endButton) endButton.onclick = function () { post("/end", ""); };
  function renderApproval(view) {
    var box = document.getElementById("approval-view");
    var qr = document.getElementById("zigner-qr");
    var refuse = document.getElementById("refuse");
    var label = document.getElementById("approval-state");
    if (!view) {
      if (shown) { box.innerHTML = ""; animateQr(qr, [], ""); refuse.hidden = true; label.textContent = "no transaction is waiting for the phone"; shown = 0; }
      return;
    }
    if (view.id === shown) return;
    shown = view.id;
    label.textContent = "scan this with Zigner, then scan the phone's answer";
    var rows = [["chain", view.chain], ["expiry height", String(view.expiry)], ["fee", view.fee], ["wallet", view.wallet], ["effect hash", view.effect_hash]];
    var html = "";
    rows.forEach(function (r) { html += "<p class=\"meta\"></p>"; });
    box.innerHTML = html + "<div class=\"term\" id=\"plan-lines\"></div>";
    var metas = box.querySelectorAll("p.meta");
    rows.forEach(function (r, i) { metas[i].textContent = r[0] + ": " + r[1]; });
    var lines = document.getElementById("plan-lines");
    view.actions.forEach(function (a) { var d = document.createElement("div"); d.className = "dim"; d.textContent = a; lines.appendChild(d); });
    view.warnings.forEach(function (a) { var d = document.createElement("div"); d.className = "err"; d.textContent = "warn " + a; lines.appendChild(d); });
    animateQr(qr, view.frames, view.frames[0]);
    refuse.hidden = false;
    cwOrchLog("wait", "approval " + view.id + " waiting for the phone");
  }
  function renderSession(j) {
    state = j.state;
    var s = "state: " + j.state;
    if (j.wallet_id) s += "  wallet: " + j.wallet_id;
    if (j.expires_in_secs != null) s += "  expires in: " + j.expires_in_secs + "s";
    document.getElementById("session-state").textContent = s;
    document.getElementById("session-run").textContent = j.home ? "pcli --home " + j.home + " view balance" : "";
  }
  function tick() {
    fetch("/approval", { headers: H }).then(function (r) { return r.json(); }).then(renderApproval).catch(function () {});
    if (session) fetch("/status", { headers: H }).then(function (r) { return r.json(); }).then(renderSession).catch(function () {});
  }
  tick();
  setInterval(tick, 1500);
})();
</script>"#;
