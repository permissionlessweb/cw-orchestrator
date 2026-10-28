//! Loopback approval page. The browser sees the digest and the messages.
//! It does not receive a share or a broadcasting key.

use std::net::SocketAddr;
use std::sync::Arc;

use sha2::Digest;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::middleware;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio::sync::{broadcast, oneshot, watch, Mutex};
use tokio::task::JoinHandle;

use crate::allowlist::{Principal, SignDocDigest, SigningRequest};
use crate::session::ApprovalFactor;
use crate::ui_shared::*;

/// Decides whether a named factor may approve this digest.
/// The test factor is the only one this phase accepts.
pub trait Approver: Send + Sync {
    fn approve(&self, factor: ApprovalFactor, digest: &str) -> bool;
}

/// Accepts `ApprovalFactor::Test` and nothing else.
#[derive(Clone, Copy, Debug, Default)]
pub struct TestApprover;

impl Approver for TestApprover {
    fn approve(&self, factor: ApprovalFactor, _digest: &str) -> bool {
        matches!(factor, ApprovalFactor::Test)
    }
}

/// What the page is asking the operator to approve.
#[derive(Clone, Debug)]
pub struct ApprovalView {
    pub digest: SignDocDigest,
    pub principal: Principal,
    pub messages: Vec<SigningRequest>,
}

/// Result of one page decision. A refusal carries no signature.
/// `signer` is the bech32 address when Zafu signed the approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalOutcome {
    Approved {
        digest: String,
        signer: Option<String>,
    },
    /// Cold key signed the exact bytes on the page. Used for the session grant.
    Signed {
        signer: String,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    },
    Refused,
}

/// One cold-key signature collected from a multi-bundle page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColdSignature {
    pub signer: String,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

/// One tab group on the session page. `sign_doc` is empty when the session
/// key broadcasts the actions and the cold key does not sign them.
#[derive(Clone, Debug)]
pub struct PageBundle {
    pub title: String,
    pub sign_doc: Vec<u8>,
    pub messages: Vec<SigningRequest>,
}

/// Listener bound to `127.0.0.1`. Dropping it stops the listener.
pub struct Terminal {
    addr: SocketAddr,
    outcome: Option<oneshot::Receiver<TerminalOutcome>>,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    notes: broadcast::Sender<String>,
}

impl std::fmt::Debug for Terminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Terminal")
            .field("addr", &self.addr)
            .finish()
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Terminal {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn outcome(&mut self) -> Result<TerminalOutcome, String> {
        let receiver = self
            .outcome
            .take()
            .ok_or_else(|| "terminal outcome already taken".to_string())?;
        receiver
            .await
            .map_err(|_| "terminal closed before a decision".to_string())
    }

    /// One line for the page log. `ok ` and `err ` are the success and failure forms.
    pub fn note(&self, line: &str) {
        let _ = self.notes.send(line.to_string());
    }
}

struct AppState {
    html: String,
    prompt: String,
    digest: String,
    principal: String,
    approval: String,
    messages: Vec<SigningRequest>,
    approver: Arc<dyn Approver>,
    outcome: Arc<Mutex<Option<oneshot::Sender<TerminalOutcome>>>>,
    /// When set, the page QR and the signature check use these bytes.
    /// The signer address must equal `principal`.
    sign_doc: Option<Vec<u8>>,
    /// Sign documents for one tabbed session page, in cold-key order.
    bundle_docs: Vec<Vec<u8>>,
    /// How many leading `bundle_docs` are the authorization. The rest are the revoke.
    authorize_count: usize,
    bundle_sigs: Mutex<Vec<Option<ColdSignature>>>,
    authorize_done: Mutex<Option<oneshot::Sender<Vec<ColdSignature>>>>,
    revoke_done: Mutex<Option<oneshot::Sender<Vec<ColdSignature>>>>,
    wasm_js: Vec<u8>,
    wasm_bg: Vec<u8>,
    zxing_js: Vec<u8>,
    notes: broadcast::Sender<String>,
}

/// Bind `addr` only when it is loopback. `127.0.0.1:0` asks the OS for a port.
pub async fn listen(
    addr: SocketAddr,
    view: ApprovalView,
    approver: Arc<dyn Approver>,
) -> Result<Terminal, String> {
    if !addr.ip().is_loopback() {
        return Err(format!("terminal refused: bind {addr} is not loopback"));
    }
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|err| format!("terminal bind refused: {err}"))?;
    let bound = listener
        .local_addr()
        .map_err(|err| format!("terminal addr refused: {err}"))?;
    let chain_id = approval_chain_id()?;
    let approval = approval_token();
    let sign_doc = approval_sign_bytes(
        &chain_id,
        view.digest.as_str(),
        view.principal.as_str(),
        &approval,
        &view.messages,
    );
    serve(
        listener,
        bound,
        &view,
        approver,
        approval,
        sign_doc,
        None,
        0,
        &format!("Each block is one action. Scan the code below with Zigner on the {} key, account 0. Then scan the phone here. The Zafu extension is not required.", crate::chain::approval_chain().display_name),
    )
}

/// Serve `sign_doc` itself. The cold key signs those bytes. `granter` is the
/// only address the page accepts.
pub async fn listen_sign_doc(
    addr: SocketAddr,
    granter: &str,
    sign_doc: Vec<u8>,
    messages: Vec<SigningRequest>,
    account_index: u32,
) -> Result<Terminal, String> {
    if !addr.ip().is_loopback() {
        return Err(format!("terminal refused: bind {addr} is not loopback"));
    }
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|err| format!("terminal bind refused: {err}"))?;
    let bound = listener
        .local_addr()
        .map_err(|err| format!("terminal addr refused: {err}"))?;
    let digest = hex_encode(sha2::Sha256::digest(&sign_doc).as_slice());
    let view = ApprovalView {
        digest: SignDocDigest::new(&digest)?,
        principal: Principal::new(granter)?,
        messages,
    };
    serve(
        listener,
        bound,
        &view,
        Arc::new(TestApprover),
        String::new(),
        sign_doc.clone(),
        Some(sign_doc),
        account_index,
        &if granter == "key" {
            format!("Sign this line with the airgapped {} key. That key is the granter. The address is not chosen before the signature.", crate::chain::approval_chain().display_name)
        } else {
            format!("Each block is one message in the session grant. Scan the code with Zigner on the {} key. The script broadcasts the signed grant, then the session key uploads.", crate::chain::approval_chain().display_name)
        },
    )
}

/// Blocking form of [`capture_granter`] for a script that has no runtime yet.
pub fn capture_granter_sync(
    addr: SocketAddr,
    account_index: u32,
    binding: &str,
) -> Result<String, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("granter refused: {err}"))?;
    runtime.block_on(capture_granter(addr, account_index, binding))
}

/// One off-chain signature. The Terp address of the signing key is the granter.
pub async fn capture_granter(
    addr: SocketAddr,
    account_index: u32,
    binding: &str,
) -> Result<String, String> {
    if binding.trim().is_empty() {
        return Err("granter refused: empty binding".into());
    }
    let doc = format!("cw-orch-granter:v1\n{binding}").into_bytes();
    let messages = vec![SigningRequest::new("cw-orch-granter:v1").body(format!(
        "the key that signs {binding} is the granter"
    ))];
    let mut terminal = listen_sign_doc(addr, "key", doc, messages, account_index).await?;
    let outcome = terminal.outcome().await?;
    drop(terminal);
    match outcome {
        TerminalOutcome::Signed { signer, .. } => {
            crate::policy::validate_chain_address(&signer).map_err(|e| format!("granter refused: {e}"))?;
            Ok(signer)
        }
        TerminalOutcome::Approved { .. } => {
            Err("granter refused: the page returned an off-chain approval".into())
        }
        TerminalOutcome::Refused => Err("granter refused: the cold key declined".into()),
    }
}

/// One page for every cold-key bundle and the actions the session key broadcasts.
///
/// `authorize_count` is how many leading cold-key documents authorize the
/// session. The oneshot for those signatures fires without waiting for the
/// revoke documents that follow. The page stays up for the revoke.
pub async fn listen_bundles(
    addr: SocketAddr,
    granter: &str,
    bundles: Vec<PageBundle>,
    account_index: u32,
    authorize_count: usize,
) -> Result<
    (
        Terminal,
        oneshot::Receiver<Vec<ColdSignature>>,
        oneshot::Receiver<Vec<ColdSignature>>,
    ),
    String,
> {
    if !addr.ip().is_loopback() {
        return Err(format!("terminal refused: bind {addr} is not loopback"));
    }
    if bundles.is_empty() {
        return Err("terminal refused: no session bundles".into());
    }
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|err| format!("terminal bind refused: {err}"))?;
    let bound = listener
        .local_addr()
        .map_err(|err| format!("terminal addr refused: {err}"))?;
    let cold: Vec<Vec<u8>> = bundles
        .iter()
        .filter(|bundle| !bundle.sign_doc.is_empty())
        .map(|bundle| bundle.sign_doc.clone())
        .collect();
    if authorize_count > cold.len() {
        return Err("terminal refused: authorize count exceeds cold bundles".into());
    }
    let (authorize_tx, authorize_rx) = oneshot::channel();
    let (revoke_tx, revoke_rx) = oneshot::channel();
    let authorize_done = if authorize_count == 0 {
        let _ = authorize_tx.send(Vec::new());
        None
    } else {
        Some(authorize_tx)
    };
    let revoke_done = if cold.len() == authorize_count {
        let _ = revoke_tx.send(Vec::new());
        None
    } else {
        Some(revoke_tx)
    };
    let view = ApprovalView {
        digest: SignDocDigest::new(&hex_encode(
            sha2::Sha256::digest(bundles[0].sign_doc.as_slice()).as_slice(),
        ))?,
        principal: Principal::new(granter)?,
        messages: bundles[0].messages.clone(),
    };
    let html = session_page(&bundles, granter, account_index)?;
    let terminal = serve_with(
        listener,
        bound,
        &view,
        Arc::new(TestApprover),
        String::new(),
        bundles
            .iter()
            .find(|bundle| !bundle.sign_doc.is_empty())
            .map(|bundle| bundle.sign_doc.clone())
            .unwrap_or_default(),
        account_index,
        "Sign the open step. The next tab stays closed until that signature checks. The session key broadcasts after the cold key is done.",
        html,
        None,
        cold,
        authorize_count,
        authorize_done,
        revoke_done,
    )?;
    Ok((terminal, authorize_rx, revoke_rx))
}

fn serve(
    listener: tokio::net::TcpListener,
    bound: SocketAddr,
    view: &ApprovalView,
    approver: Arc<dyn Approver>,
    approval: String,
    qr_doc: Vec<u8>,
    sign_doc: Option<Vec<u8>>,
    account_index: u32,
    intro: &str,
) -> Result<Terminal, String> {
    let html = page(view, &approval, &qr_doc, account_index, intro);
    serve_with(
        listener,
        bound,
        view,
        approver,
        approval,
        qr_doc,
        account_index,
        intro,
        html,
        sign_doc,
        Vec::new(),
        0,
        None,
        None,
    )
}

fn serve_with(
    listener: tokio::net::TcpListener,
    bound: SocketAddr,
    view: &ApprovalView,
    approver: Arc<dyn Approver>,
    approval: String,
    qr_doc: Vec<u8>,
    account_index: u32,
    intro: &str,
    html: String,
    sign_doc: Option<Vec<u8>>,
    bundle_docs: Vec<Vec<u8>>,
    authorize_count: usize,
    authorize_done: Option<oneshot::Sender<Vec<ColdSignature>>>,
    revoke_done: Option<oneshot::Sender<Vec<ColdSignature>>>,
) -> Result<Terminal, String> {
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let (notes, _) = broadcast::channel(64);
    let _ = (qr_doc, account_index, intro);
    let state = AppState {
        html,
        prompt: prompt(view, &approval),
        digest: view.digest.as_str().to_string(),
        principal: view.principal.as_str().to_string(),
        approval,
        messages: view.messages.clone(),
        approver,
        outcome: Arc::new(Mutex::new(Some(outcome_tx))),
        sign_doc,
        bundle_docs: bundle_docs.clone(),
        authorize_count,
        bundle_sigs: Mutex::new(vec![None; bundle_docs.len()]),
        authorize_done: Mutex::new(authorize_done),
        revoke_done: Mutex::new(revoke_done),
        wasm_js: read_vendor("../../../zafu/apps/extension/public/zafu-wasm/zafu_wasm.js"),
        wasm_bg: read_vendor("../../../zafu/apps/extension/public/zafu-wasm/zafu_wasm_bg.wasm"),
        zxing_js: zxing_js_bytes(),
        notes: notes.clone(),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/ws", get(ws))
        .route("/zafu-wasm/zafu_wasm.js", get(wasm_js))
        .route("/zafu-wasm/zafu_wasm_bg.wasm", get(wasm_bg))
        .route("/zafu-wasm/snippets/{*rest}", get(wasm_snippet))
        .route("/zxing/index.min.js", get(zxing_js))
        .fallback(missing)
        .layer(middleware::from_fn(isolate))
        .with_state(Arc::new(state));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await;
    });
    Ok(Terminal {
        addr: bound,
        outcome: Some(outcome_rx),
        shutdown: shutdown_tx,
        task: Some(task),
        notes,
    })
}

fn session_page(
    bundles: &[PageBundle],
    granter: &str,
    account_index: u32,
) -> Result<String, String> {
    let mut json = String::from("[");
    for (index, bundle) in bundles.iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        let sign = !bundle.sign_doc.is_empty();
        let digest = hex_encode(sha2::Sha256::digest(bundle.sign_doc.as_slice()).as_slice());
        let doc = hex_encode(bundle.sign_doc.as_slice());
        let frames = if sign {
            zigner_frames(&zigner_request(account_index, &crate::chain::approval_chain().zigner_chain_name, &bundle.sign_doc))?
        } else {
            Vec::new()
        };
        let qr = match frames.as_slice() {
            [] => String::new(),
            [one] => qr_svg(one),
            many => frame_svg(&many[0]),
        };
        let (frames_svg, frames_hex): (Vec<String>, Vec<String>) = if frames.len() > 1 {
            frames.iter().map(|f| (frame_svg(f), hex_encode(f))).unzip()
        } else {
            (Vec::new(), Vec::new())
        };
        json.push_str(&format!(
            "{{\"sign\":{sign},\"title\":{title},\"digest\":{digest},\"doc\":{doc},\"qr\":{qr},\"frames\":{frames},\"frames_hex\":{frames_hex},\"actions\":{actions}}}",
            sign = if sign { "true" } else { "false" },
            title = json_string(&bundle.title),
            digest = json_string(&digest),
            doc = json_string(&doc),
            qr = json_string(&qr),
            frames = json_list(&frames_svg),
            frames_hex = json_list(&frames_hex),
            actions = actions_json(&bundle.messages),
        ));
    }
    json.push(']');
    json = json.replace('<', "\\u003c");
    let view = ApprovalView {
        digest: SignDocDigest::new(&hex_encode(
            sha2::Sha256::digest(
                bundles
                    .iter()
                    .find(|bundle| !bundle.sign_doc.is_empty())
                    .map(|bundle| bundle.sign_doc.as_slice())
                    .unwrap_or(b""),
            )
            .as_slice(),
        ))?,
        principal: Principal::new(granter).unwrap_or_else(|_| Principal::new(crate::chain::approval_chain().bech32_prefix).expect("principal")),
        messages: Vec::new(),
    };
    let mut html = page(
        &view,
        "",
        b"",
        account_index,
        "One page for this session. Tabs are the actions. The cold key signs an authorization bundle, the session key broadcasts the middle actions, and the cold key signs the revoke at the end.",
    );
    let embed = format!("<script type=\"application/json\" id=\"bundles\">{json}</script>");
    html = html.replacen("<div id=\"actions-view\">", &format!("{embed}<div id=\"actions-view\">"), 1);
    Ok(html)
}

fn page(
    view: &ApprovalView,
    approval: &str,
    sign_doc: &[u8],
    account_index: u32,
    intro: &str,
) -> String {
    let request = zigner_request(account_index, &crate::chain::approval_chain().zigner_chain_name, sign_doc);
    let qr = match zigner_frames(&request) {
        Ok(frames) if frames.len() > 1 => {
            let svgs: Vec<String> = frames.iter().map(|f| frame_svg(f)).collect();
            format!("{}<script type=\"application/json\" id=\"qr-frames\">{}</script>", svgs[0], json_list(&svgs))
        }
        _ => qr_svg(&request),
    };
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Zafu session</title>\
<style>\
{style}</style></head>\
<body><div class=\"shell\">\
<p class=\"mark\">ZAFU <span>·</span> SESSION</p>\
<h1>Approve this run</h1>\
<p class=\"lede\" id=\"approval\">{approval}</p>\
<div class=\"row\"><span class=\"chip\" id=\"principal\">{principal}</span></div>\
<p class=\"meta\" id=\"digest\">{digest}</p>\
<script type=\"application/json\" id=\"chain\">{chain_json}</script>\
<p class=\"lede\">{intro}</p>\
<div id=\"tabs\"></div>\
<p class=\"lede\" id=\"step-guide\"></p>\
<div id=\"actions-view\">{cards}</div>\
<script type=\"application/json\" id=\"actions\">{actions}</script>\
<div id=\"zigner-qr\">{qr}</div>\
<video id=\"camera\" hidden playsinline></video>\
<p id=\"scan-status\"></p>\
<button id=\"scan\" type=\"button\">Scan the phone</button>\
<label>Public key<input id=\"pubkey\" autocomplete=\"off\" spellcheck=\"false\"></label>\
<label>Signature<input id=\"signature\" autocomplete=\"off\" spellcheck=\"false\"></label>\
<button id=\"check\" type=\"button\">Check signature</button>\
<p id=\"check-result\"></p>\
<p class=\"foot\">The phone signs the open step. This page does not hold a key. The next tab stays closed until that signature checks.</p>\
<section class=\"run\"><p class=\"kicker\">cw-orch</p><div class=\"term\" id=\"term-log\" role=\"log\"></div></section>\
<details id=\"zafu-path\"><summary>Zafu</summary>\
<p class=\"foot\">Zafu signs only after you open this. It is not the next step.</p>\
<div id=\"wallets\"></div><p id=\"zafu-status\"></p>\
<button id=\"zafu-approve\" type=\"button\" hidden>Approve with Zafu</button>\
</details>\
</div>\
<script src=\"/zxing/index.min.js\"></script>\
{shared}{script}</body></html>",
        digest = escape(view.digest.as_str()),
        chain_json = json_string(&approval_chain_id().unwrap_or_default()).replace('<', "\\u003c"),
        principal = escape(view.principal.as_str()),
        approval = escape(approval),
        cards = action_cards(&view.messages),
        actions = actions_json(&view.messages).replace('<', "\\u003c"),
        intro = escape(intro),
        qr = qr,
        style = PAGE_STYLE,
        shared = SHARED_SCRIPT,
        script = PAGE_SCRIPT,
    )
}

fn action_cards(messages: &[SigningRequest]) -> String {
    let mut out = String::new();
    for message in messages {
        out.push_str("<section class=\"card\"><p class=\"kicker\">");
        out.push_str(&escape(&message.type_url));
        out.push_str("</p>");
        if let Some(code_id) = message.code_id {
            out.push_str("<p>code ");
            out.push_str(&code_id.to_string());
            out.push_str("</p>");
        }
        if let Some(contract) = &message.contract {
            out.push_str("<p>");
            out.push_str(&escape(contract));
            out.push_str("</p>");
        }
        if let Some(body) = &message.body {
            out.push_str("<pre>");
            out.push_str(&escape(body));
            out.push_str("</pre>");
        }
        out.push_str("</section>");
    }
    out
}

/// Zigner cosmos QR payload. The phone reads the raw bytes and hex-encodes them.
pub(crate) fn zigner_request(account_index: u32, chain_name: &str, sign_doc: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(12 + chain_name.len() + sign_doc.len());
    payload.extend_from_slice(&[0x53, 0x05, 0x10]);
    payload.extend_from_slice(&account_index.to_le_bytes());
    payload.push(u8::try_from(chain_name.len()).unwrap_or(u8::MAX));
    payload.extend_from_slice(chain_name.as_bytes());
    payload.extend_from_slice(
        &(u32::try_from(sign_doc.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes()),
    );
    payload.extend_from_slice(sign_doc);
    // Non-Terp chains carry Zigner's QR extension so the phone derives the
    // right prefix and coin type: address_idx u32 LE (0), then 0xC5, version
    // 0x01, flags (bit0 coin_type u32 LE, bit1 prefix len + prefix).
    // Terp payloads stay byte-identical to the legacy layout.
    let chain = crate::chain::approval_chain();
    if chain.bech32_prefix != "terp" && chain.bech32_prefix.len() <= 83 {
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&[0xC5, 0x01, 0b11]);
        payload.extend_from_slice(&chain.coin_type.to_le_bytes());
        payload.push(chain.bech32_prefix.len() as u8);
        payload.extend_from_slice(chain.bech32_prefix.as_bytes());
    }
    payload
}

/// Hex of the Zigner QR the page shows for `sign_doc` on the approval chain.
pub fn zigner_qr_hex(account_index: u32, sign_doc: &[u8]) -> String {
    let chain = crate::chain::approval_chain();
    zigner_request(account_index, &chain.zigner_chain_name, sign_doc)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(crate) fn zigner_request_fits(account_index: u32, chain_name: &str, sign_doc: &[u8]) -> bool {
    qrcode::QrCode::new(zigner_request(account_index, chain_name, sign_doc)).is_ok()
}

const PAGE_SCRIPT: &str = r#"<script>
(function () {
  var t = document.getElementById("qr-frames");
  if (!t || document.getElementById("bundles")) return;
  try { animateQr(document.getElementById("zigner-qr"), JSON.parse(t.textContent), ""); } catch (e) {}
})();
(function () {
  var chain = JSON.parse(document.getElementById("chain").textContent);
  var digest = document.getElementById("digest").textContent;
  var principal = document.getElementById("principal").textContent;
  var approval = document.getElementById("approval").textContent;
  var actions = JSON.parse(document.getElementById("actions").textContent);
  var bundleEl = document.getElementById("bundles");
  var bundles = bundleEl ? JSON.parse(bundleEl.textContent) : null;
  var cold = [];
  var shown = 0;
  var signedAt = {};
  if (bundles) {
    bundles.forEach(function (bundle, index) { if (bundle.sign) cold.push(index); });
  }
  var status = document.getElementById("zafu-status");
  var box = document.getElementById("wallets");
  var button = document.getElementById("zafu-approve");
  var result = document.getElementById("check-result");
  var scanStatus = document.getElementById("scan-status");
  var video = document.getElementById("camera");
  var guide = document.getElementById("step-guide");
  var ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");
  var open = false;
  var reader = null;
  var finished = false;
  var cameraOn = false;
  var mode = "";
  var urParts = [];
  var urSeen = {};
  var urType = "";
  var usedCodes = {};
  var framesThisScan = [];
  var pFrames = {};
  var pTotal = 0;
  var wasmReady = null;
  var zafuArmed = false;
  function logLine(kind, text) { cwOrchLog(kind, text); }
  function kindFor(text) {
    if (text.indexOf("ok ") === 0 || text.indexOf("valid ") === 0 || text.indexOf("authorized ") === 0 || text.indexOf("session-ready ") === 0 || text === "approved") return "ok";
    if (text.indexOf("err ") === 0 || text.indexOf("refused") === 0) return "err";
    return "wait";
  }
  function stepOpen(index) {
    if (!bundles) return true;
    for (var i = 0; i < index; i++) {
      if (bundles[i].sign && !signedAt[i]) return false;
    }
    return true;
  }
  ws.onopen = function () { open = true; };
  ws.onmessage = function (ev) {
    var text = String(ev.data || "");
    if (text.indexOf("digest=") === 0) return;
    if (text.indexOf("log ") === 0) {
      var body = text.slice(4);
      logLine(kindFor(body), body);
      return;
    }
    result.textContent = text;
    logLine(kindFor(text), text);
    if (!bundles) return;
    var accepted = text.indexOf("valid ") === 0 || text.indexOf("authorized ") === 0 || text.indexOf("session-ready ") === 0;
    if (!accepted) return;
    signedAt[shown] = true;
    stopScan();
    mode = "";
    urParts = [];
    urSeen = {};
    urType = "";
    pFrames = {};
    pTotal = 0;
    framesThisScan = [];
    if (text.indexOf("session-ready ") === 0) {
      scanStatus.textContent = "revoke signed. the script broadcasts it and this page can close";
      showBundle(shown);
      return;
    }
    var next = null;
    for (var i = 0; i < cold.length; i++) {
      if (!signedAt[cold[i]]) { next = cold[i]; break; }
    }
    if (text.indexOf("authorized ") === 0) {
      scanStatus.textContent = "authorization accepted. the session key broadcasts next. watch the cw-orch log";
    } else if (next !== null) {
      scanStatus.textContent = "signed. sign the open tab on the phone, then press Scan the phone. the camera stays off so it cannot read the previous signature";
    }
    if (next !== null) showBundle(next);
    else showBundle(shown);
  };
  if (bundles) showBundle(cold.length ? cold[0] : 0);
  else {
    guide.textContent = "Sign this code. Zafu stays closed unless you open it.";
    logLine("wait", "waiting for the cold key");
    actions.forEach(function (action) {
      logLine("dim", (action.type || "action") + (action.body ? " " + action.body : ""));
    });
  }
  document.getElementById("check").onclick = function () { submitFields(); };
  document.getElementById("scan").onclick = startScan;

  document.getElementById("zafu-path").addEventListener("toggle", function () {
    if (!this.open || zafuArmed) return;
    zafuArmed = true;
    armZafu();
  });
  function armZafu() {
    if (bundles) {
      status.textContent = "This page is a phone signature of the grant. Zafu is not this step.";
      button.hidden = true;
      return;
    }
    button.hidden = false;
    if (!window.zafu) {
      status.textContent = "Zafu is not installed";
      button.disabled = true;
      return;
    }
    var accounts = [];
    window.zafu.enable(chain).then(function () {
      return window.zafu.getOfflineSigner(chain).getAccounts();
    }).then(function (list) {
      accounts = list;
      if (list.length > 1) {
        var sel = document.createElement("select");
        sel.id = "zafu-account";
        list.forEach(function (account) {
          var option = document.createElement("option");
          option.value = account.address;
          option.textContent = account.address;
          sel.appendChild(option);
        });
        box.appendChild(sel);
      } else if (list.length === 1) {
        status.textContent = list[0].address;
      } else {
        status.textContent = "Zafu has no account";
        button.disabled = true;
      }
    }).catch(function (err) {
      status.textContent = err && err.message ? err.message : "zafu enable failed";
      button.disabled = true;
    });
    button.onclick = function () {
      var sel = document.getElementById("zafu-account");
      var address = sel ? sel.value : (accounts[0] && accounts[0].address);
      if (!open || !address) return;
      logLine("wait", "zafu signing the open step");
      var signDoc = {
        chain_id: chain,
        account_number: "0",
        sequence: "0",
        fee: { amount: [], gas: "0" },
        memo: "cw-orch-approval:v1",
        msgs: [{ type: "cw-orch/Approval", value: { actions: actions, digest: digest, nonce: approval, principal: principal } }]
      };
      window.zafu.signAmino(chain, address, signDoc).then(function (res) {
        ws.send("approve zafu " + address + " " + res.signature.pub_key.value + " " + res.signature.signature);
      }).catch(function (err) {
        var message = err && err.message ? err.message : "zafu sign failed";
        status.textContent = message;
        logLine("err", message);
      });
    };
  }

  function startScan() {
    if (reader && reader.reset) {
      try { reader.reset(); } catch (err) {}
    }
    var next = cwOrchScan.start(video, scanStatus, function (text) {
      if (finished) return;
      onFrame(text);
    });
    if (!next) return;
    finished = false;
    reader = next;
    cameraOn = true;
  }

  function stopScan() {
    cameraOn = false;
    finished = true;
    cwOrchScan.stop(reader, video);
  }

  function onFrame(text) {
    if (usedCodes[text]) {
      scanStatus.textContent = "that code belongs to the previous step. sign the open tab on the phone, then scan the new signature";
      return;
    }
    framesThisScan.push(text);
    var lower = String(text || "").toLowerCase();
    if (lower.indexOf("ur:") === 0) {
      if (mode === "p") return;
      mode = "ur";
      if (text.length > 2048 || urSeen[text]) return;
      if (urParts.length >= 4096) {
        scanStatus.textContent = "too many frames";
        return;
      }
      var slash = text.indexOf("/");
      var kind = slash > 3 ? text.slice(3, slash) : "";
      if (urType && urType !== kind) return;
      urType = kind;
      urSeen[text] = true;
      urParts.push(text);
      scanStatus.textContent = urParts.length + (urParts.length === 1 ? " frame, joining" : " frames, joining");
      var newest = text;
      var kind = urType;
      loadWasm().then(function (mod) {
        if (finished) return;
        var hex = null;
        var errText = "";
        try {
          hex = mod.ur_decode_frames(JSON.stringify([newest]), kind);
        } catch (err) {
          errText = err && err.message ? err.message : String(err);
        }
        if (!hex && urParts.length > 1) {
          try {
            hex = mod.ur_decode_frames(JSON.stringify(urParts), kind);
            errText = "";
          } catch (err) {
            errText = err && err.message ? err.message : String(err);
          }
        }
        if (!hex) {
          scanStatus.textContent = urParts.length + " frames. " + errText;
          return;
        }
        var bytes = hexToBytes(hex);
        if (bytes.length < 97) {
          scanStatus.textContent = urParts.length + " frames, signature is " + bytes.length + " bytes";
          return;
        }
        acceptBytes(bytes);
      }).catch(function (err) {
        scanStatus.textContent = err && err.message ? err.message : "wasm failed";
      });
      return;
    }
    var match = /^P(\d+)\/(\d+)\/([^/]+)\/(.+)$/.exec(text);
    if (!match) {
      if (/^[0-9a-fA-F]{128}$/.test(text.trim())) {
        scanStatus.textContent = "that code is only the signature. scan the cw-orch code on the phone";
      }
      return;
    }
    if (mode === "ur") return;
    mode = "p";
    var idx = Number(match[1]);
    var total = Number(match[2]);
    if (!pTotal) pTotal = total;
    pFrames[idx] = match[4];
    var got = Object.keys(pFrames).length;
    scanStatus.textContent = got + " of " + total;
    if (got < total) return;
    var b64 = "";
    for (var i = 1; i <= total; i++) b64 += pFrames[i] || "";
    try {
      var binary = atob(b64);
      var bytes = new Uint8Array(binary.length);
      for (var j = 0; j < binary.length; j++) bytes[j] = binary.charCodeAt(j);
      acceptBytes(bytes);
    } catch (err) {
      scanStatus.textContent = "could not join the frames";
    }
  }

  function loadWasm() {
    if (!wasmReady) {
      wasmReady = import("/zafu-wasm/zafu_wasm.js").then(function (mod) {
        return mod.default({ module_or_path: "/zafu-wasm/zafu_wasm_bg.wasm" }).then(function () { return mod; });
      });
    }
    return wasmReady;
  }

  function acceptBytes(bytes) {
    if (finished || !bytes || bytes.length < 97) return;
    framesThisScan.forEach(function (frame) { usedCodes[frame] = true; });
    framesThisScan = [];
    finished = true;
    if (reader && reader.reset) reader.reset();
    var pk = bytes.slice(0, 33);
    var sig = bytes.slice(33, 97);
    document.getElementById("pubkey").value = toHex(pk);
    document.getElementById("signature").value = toHex(sig);
    scanStatus.textContent = "signature received";
    submit(pk, sig);
  }

  function submitFields() {
    if (!open) {
      result.textContent = "waiting for the page socket";
      return;
    }
    var pub = document.getElementById("pubkey").value.trim();
    var sigText = document.getElementById("signature").value.trim();
    if (!pub || !sigText) {
      result.textContent = "scan the phone for the bundle on screen";
      return;
    }
    try {
      submit(decodeField(pub), decodeField(sigText));
    } catch (err) {
      result.textContent = "that is not hex or base64";
    }
  }

  function submit(pk, sig) {
    if (!open) {
      result.textContent = "waiting for the page socket";
      return;
    }
    if (!bundles) {
      ws.send("check " + toB64(pk) + " " + toB64(sig));
      return;
    }
    var at = cold.indexOf(shown);
    if (at < 0) {
      result.textContent = "the session key broadcasts this bundle";
      return;
    }
    if (signedAt[shown]) {
      result.textContent = "this bundle is already signed";
      return;
    }
    ws.send("check " + at + " " + toB64(pk) + " " + toB64(sig));
  }

  function renderBody(body) {
    var text = String(body || "");
    var shown = text;
    try {
      shown = JSON.stringify(JSON.parse(text), null, 2);
    } catch (e) { shown = text; }
    var pre = document.createElement("pre");
    pre.textContent = shown;
    return pre;
  }

  function showBundle(index) {
    if (!stepOpen(index)) return;
    shown = index;
    var pubkey = document.getElementById("pubkey");
    var signature = document.getElementById("signature");
    if (pubkey) pubkey.value = "";
    if (signature) signature.value = "";
    var bundle = bundles[index];
    var tabs = document.getElementById("tabs");
    if (tabs) {
      tabs.innerHTML = "";
      bundles.forEach(function (item, itemIndex) {
        var tab = document.createElement("button");
        tab.type = "button";
        var openStep = stepOpen(itemIndex);
        tab.disabled = !openStep;
        var classes = [];
        if (itemIndex === index) classes.push("is-on");
        if (signedAt[itemIndex]) classes.push("is-done");
        tab.className = classes.join(" ");
        tab.textContent = item.title || ("step " + (itemIndex + 1));
        tab.onclick = function () { showBundle(itemIndex); };
        tabs.appendChild(tab);
      });
    }
    var stepNo = index + 1;
    if (bundle.sign && !signedAt[index]) {
      guide.textContent = "Step " + stepNo + " of " + bundles.length + ". Sign this code on the phone. Press Scan the phone only when the new signature is on the screen.";
    } else if (bundle.sign) {
      guide.textContent = "Step " + stepNo + " of " + bundles.length + " is signed.";
    } else {
      guide.textContent = "Step " + stepNo + " of " + bundles.length + ". The session key broadcasts these actions. The cold key does not sign this tab.";
    }
    if (!bundle.logged) {
      bundle.logged = true;
      logLine("wait", bundle.title || ("step " + stepNo));
      (bundle.actions || []).forEach(function (action) {
        logLine("dim", (action.type || "action") + (action.body ? " " + action.body : ""));
      });
    }
    document.getElementById("digest").textContent = bundle.digest || "";
    var view = document.getElementById("actions-view");
    view.innerHTML = "";
    var heading = document.createElement("p");
    heading.className = "kicker";
    heading.textContent = bundle.title || "";
    view.appendChild(heading);
    (bundle.actions || []).forEach(function (action) {
      var section = document.createElement("section");
      section.className = "card";
      var label = document.createElement("p");
      label.className = "kicker";
      label.textContent = action.type || "";
      section.appendChild(label);
      if (action.body) section.appendChild(renderBody(action.body));
      view.appendChild(section);
    });
    var qr = document.getElementById("zigner-qr");
    var scan = document.getElementById("scan");
    var check = document.getElementById("check");
    var signing = bundle.sign && !signedAt[index];
    var pubkeyField = document.getElementById("pubkey");
    var signatureField = document.getElementById("signature");
    if (pubkeyField && pubkeyField.parentElement) pubkeyField.parentElement.hidden = !signing;
    if (signatureField && signatureField.parentElement) signatureField.parentElement.hidden = !signing;
    if (bundle.sign) {
      animateQr(qr, bundle.frames, bundle.qr || "");
      if (scan) scan.hidden = !signing;
      if (check) check.hidden = !signing;
    } else {
      animateQr(null);
      qr.innerHTML = "<p>the session key broadcasts this. the cold key does not sign it.</p>";
      if (scan) scan.hidden = true;
      if (check) check.hidden = true;
    }
  }

  function hexToBytes(hex) {
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
  }
  function toHex(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    return s;
  }
  function decodeField(text) {
    var t = String(text || "").trim().replace(/\s+/g, "");
    if (/^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0) return hexToBytes(t);
    var bin = atob(t);
    var bytes = new Uint8Array(bin.length);
    for (var j = 0; j < bin.length; j++) bytes[j] = bin.charCodeAt(j);
    return bytes;
  }
  function toB64(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
})();
</script>"#;

async fn wasm_js(State(state): State<Arc<AppState>>) -> Response {
    vendor_response(&state.wasm_js, "text/javascript")
}

async fn wasm_bg(State(state): State<Arc<AppState>>) -> Response {
    vendor_response(&state.wasm_bg, "application/wasm")
}

async fn zxing_js(State(state): State<Arc<AppState>>) -> Response {
    vendor_response(&state.zxing_js, "text/javascript")
}

/// Rayon glue that `zafu_wasm.js` imports. Without it the browser rejects the
/// dynamic import before the decoder runs.
async fn wasm_snippet(Path(rest): Path<String>) -> Response {
    if rest.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        || !rest.ends_with(".js")
    {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../zafu/apps/extension/public/zafu-wasm/snippets")
        .join(rest);
    match std::fs::read(path) {
        Ok(bytes) => vendor_response(&bytes, "text/javascript"),
        Err(_) => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}


fn prompt(view: &ApprovalView, approval: &str) -> String {
    let mut text = format!(
        "digest={}\nprincipal={}\napproval={}\n",
        view.digest.as_str(),
        view.principal.as_str(),
        approval
    );
    for message in &view.messages {
        text.push_str("msg=");
        text.push_str(&message.type_url);
        text.push('\n');
    }
    text
}


async fn index(State(state): State<Arc<AppState>>) -> Html<String> {
    Html(state.html.clone())
}

async fn missing() -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_FOUND
}

async fn ws(
    State(state): State<Arc<AppState>>,
    upgrade: WebSocketUpgrade,
) -> axum::response::Response {
    let state = Arc::clone(&state);
    upgrade.on_upgrade(move |socket| handle(socket, state))
}

async fn handle(mut socket: WebSocket, state: Arc<AppState>) {
    let mut notes = state.notes.subscribe();
    if socket
        .send(Message::Text(state.prompt.clone().into()))
        .await
        .is_err()
    {
        return;
    }
    loop {
        let incoming = tokio::select! {
            incoming = socket.recv() => incoming,
            line = notes.recv() => {
                match line {
                    Ok(line) => {
                        if socket
                            .send(Message::Text(format!("log {line}").into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
                continue;
            }
        };
        let text = match incoming {
            Some(Ok(Message::Text(text))) => text.to_string(),
            _ => return,
        };
        let trimmed = text.trim();
        if let Some(rest) = trimmed.strip_prefix("check ") {
            if !state.bundle_docs.is_empty() {
                let reply = check_bundle(&state, rest).await;
                println!("session check: {reply}");
                if socket
                    .send(Message::Text(reply.clone().into()))
                    .await
                    .is_err()
                {
                    return;
                }
                if reply.starts_with("session-ready") {
                    return;
                }
                continue;
            }
            let reply = check_signature(
                &state.digest,
                &state.principal,
                &state.approval,
                &state.messages,
                state.sign_doc.as_deref(),
                rest,
            );
            if socket
                .send(Message::Text(reply.clone().into()))
                .await
                .is_err()
            {
                return;
            }
            if let Some(addr) = reply.strip_prefix("valid ") {
                if let Some(sender) = state.outcome.lock().await.take() {
                    let outcome = if state.sign_doc.is_some() {
                        let mut parts = rest.split_whitespace();
                        let pubkey = decode_key_bytes(parts.next().unwrap_or("")).unwrap_or_default();
                        let signature =
                            decode_key_bytes(parts.next().unwrap_or("")).unwrap_or_default();
                        TerminalOutcome::Signed {
                            signer: addr.to_string(),
                            pubkey,
                            signature,
                        }
                    } else {
                        TerminalOutcome::Approved {
                            digest: state.digest.clone(),
                            signer: Some(addr.to_string()),
                        }
                    };
                    let _ = sender.send(outcome);
                }
                return;
            }
            continue;
        }
        let outcome = decide(
            trimmed,
            &state.digest,
            &state.principal,
            &state.approval,
            &state.messages,
            state.approver.as_ref(),
        );
        let reply = match &outcome {
            TerminalOutcome::Approved { .. } | TerminalOutcome::Signed { .. } => "approved",
            TerminalOutcome::Refused => "refused",
        };
        let _ = socket.send(Message::Text(reply.into())).await;
        if let Some(sender) = state.outcome.lock().await.take() {
            let _ = sender.send(outcome);
        }
        return;
    }
}

fn decide(
    text: &str,
    digest: &str,
    principal: &str,
    approval: &str,
    messages: &[SigningRequest],
    approver: &dyn Approver,
) -> TerminalOutcome {
    let Some(rest) = text.strip_prefix("approve ") else {
        return TerminalOutcome::Refused;
    };
    let mut parts = rest.split_whitespace();
    let name = parts.next().unwrap_or("");
    if name == "zafu" {
        let addr = parts.next();
        let pk = parts.next();
        let sig = parts.next();
        if parts.next().is_some() {
            return TerminalOutcome::Refused;
        }
        if let (Some(addr), Some(pk), Some(sig)) = (addr, pk, sig) {
            return zafu_approval(digest, principal, approval, messages, addr, pk, sig);
        }
        if addr.is_some() {
            return TerminalOutcome::Refused;
        }
    } else if parts.next().is_some() {
        return TerminalOutcome::Refused;
    }
    let factor = match name {
        "test" => ApprovalFactor::Test,
        "keplr" => ApprovalFactor::Keplr,
        "zafu" => ApprovalFactor::Zafu,
        "passkey" => ApprovalFactor::Passkey,
        _ => return TerminalOutcome::Refused,
    };
    if approver.approve(factor, digest) {
        TerminalOutcome::Approved {
            digest: digest.to_string(),
            signer: None,
        }
    } else {
        TerminalOutcome::Refused
    }
}

fn zafu_approval(
    digest: &str,
    principal: &str,
    approval: &str,
    messages: &[SigningRequest],
    addr: &str,
    pk_b64: &str,
    sig_b64: &str,
) -> TerminalOutcome {
    let Ok(pk) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pk_b64) else {
        return TerminalOutcome::Refused;
    };
    let Ok(sig) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
    else {
        return TerminalOutcome::Refused;
    };
    let Ok(chain_id) = approval_chain_id() else {
        return TerminalOutcome::Refused;
    };
    let message = approval_sign_bytes(&chain_id, digest, principal, approval, messages);
    if !address_matches(addr, &pk) || !verify_amino(&pk, &sig, &message) {
        return TerminalOutcome::Refused;
    }
    if !crate::policy::principal_accepts(Some(principal), addr) {
        return TerminalOutcome::Refused;
    }
    TerminalOutcome::Approved {
        digest: digest.to_string(),
        signer: Some(addr.to_string()),
    }
}

async fn check_bundle(state: &AppState, rest: &str) -> String {
    let mut parts = rest.split_whitespace();
    let Some(index_text) = parts.next() else {
        return "refused the check needs a bundle, a pubkey, and a signature".into();
    };
    let Ok(index) = index_text.parse::<usize>() else {
        return "refused the bundle number is not a number".into();
    };
    if index >= state.bundle_docs.len() {
        return "refused that bundle is not on this page".into();
    }
    let rest = parts.collect::<Vec<_>>().join(" ");
    let reply = check_signature(
        &state.digest,
        &state.principal,
        &state.approval,
        &state.messages,
        Some(&state.bundle_docs[index]),
        &rest,
    );
    let Some(addr) = reply.strip_prefix("valid ") else {
        return reply;
    };
    let mut fields = rest.split_whitespace();
    let pubkey = decode_key_bytes(fields.next().unwrap_or("")).unwrap_or_default();
    let signature = decode_key_bytes(fields.next().unwrap_or("")).unwrap_or_default();
    {
        let mut sigs = state.bundle_sigs.lock().await;
        sigs[index] = Some(ColdSignature {
            signer: addr.to_string(),
            pubkey,
            signature,
        });
        let authorize_ready = sigs
            .iter()
            .take(state.authorize_count)
            .all(|sig| sig.is_some());
        let all_ready = sigs.iter().all(|sig| sig.is_some());
        if authorize_ready {
            if let Some(sender) = state.authorize_done.lock().await.take() {
                let done = sigs
                    .iter()
                    .take(state.authorize_count)
                    .cloned()
                    .map(|sig| sig.expect("authorize signature"))
                    .collect();
                let _ = sender.send(done);
            }
        }
        if all_ready {
            if let Some(sender) = state.revoke_done.lock().await.take() {
                let done = sigs
                    .iter()
                    .skip(state.authorize_count)
                    .cloned()
                    .map(|sig| sig.expect("revoke signature"))
                    .collect();
                let _ = sender.send(done);
            }
            if state.bundle_docs.len() == state.authorize_count {
                return format!("authorized {addr}");
            }
            return format!("session-ready {addr}");
        }
        if authorize_ready && index < state.authorize_count {
            return format!("authorized {addr}");
        }
    }
    format!("valid {addr}")
}

fn check_signature(
    digest: &str,
    principal: &str,
    approval: &str,
    messages: &[SigningRequest],
    sign_doc: Option<&[u8]>,
    rest: &str,
) -> String {
    let mut parts = rest.split_whitespace();
    let Some(pk_text) = parts.next() else {
        return "refused the check needs a pubkey and a signature".to_string();
    };
    let Some(sig_text) = parts.next() else {
        return "refused the check needs a pubkey and a signature".to_string();
    };
    if parts.next().is_some() {
        return "refused the check needs a pubkey and a signature".to_string();
    }
    let Some(pk) = decode_key_bytes(pk_text) else {
        return "refused the pubkey is not hex or base64".to_string();
    };
    let Some(sig) = decode_key_bytes(sig_text) else {
        return "refused the signature is not hex or base64".to_string();
    };
    if pk.len() != 33 {
        return "refused the pubkey is not a 33-byte cosmos key".to_string();
    }
    if sig.len() != 64 {
        return "refused the signature is not 64 bytes".to_string();
    }
    let Some(addr) = chain_address(&pk) else {
        return "refused the pubkey is not a terp address".to_string();
    };
    // `key` means this signature chooses the granter. The address is the
    // Terp account of the key that signed, not an address typed in advance.
    if sign_doc.is_some() && principal != "key" && addr != principal {
        return "refused the signature is not from the granter".to_string();
    }
    let owned;
    let message = if let Some(doc) = sign_doc {
        doc
    } else {
        let Ok(chain_id) = approval_chain_id() else {
            return "refused the approval chain-id is not configured".to_string();
        };
        owned = approval_sign_bytes(&chain_id, digest, principal, approval, messages);
        owned.as_slice()
    };
    if !verify_amino(&pk, &sig, message) {
        return "refused the signature does not match these actions".to_string();
    }
    format!("valid {addr}")
}

fn decode_key_bytes(text: &str) -> Option<Vec<u8>> {
    if text.chars().all(|c| c.is_ascii_hexdigit()) && text.len() % 2 == 0 && text.len() >= 2 {
        let mut out = Vec::with_capacity(text.len() / 2);
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_val(bytes[i])?;
            let lo = hex_val(bytes[i + 1])?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        return Some(out);
    }
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text).ok()
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn chain_address(pk: &[u8]) -> Option<String> {
    let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(pk));
    crate::chain::approval_chain().address(hash.as_slice())
}


fn actions_json(messages: &[SigningRequest]) -> String {
    let mut out = String::from("[");
    for (index, message) in messages.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('{');
        {
            let mut field = 0;
            let mut write = |part: String| {
                if field > 0 {
                    out.push(',');
                }
                field += 1;
                out.push_str(&part);
            };
            if let Some(body) = &message.body {
                write(format!("\"body\":{}", json_string(body)));
            }
            if let Some(code_id) = message.code_id {
                write(format!("\"code_id\":{code_id}"));
            }
            if let Some(contract) = &message.contract {
                write(format!("\"contract\":{}", json_string(contract)));
            }
            write(format!("\"type\":{}", json_string(&message.type_url)));
        }
        out.push('}');
    }
    out.push(']');
    out
}

/// Chain-id bound into the approval sign doc. Set from the configured chain
/// (session open or the v2 granter challenge), else `CW_ORCH_APPROVAL_CHAIN_ID`.
/// There is no built-in default: an unset chain refuses the page.
static APPROVAL_CHAIN_ID: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

pub fn set_approval_chain_id(chain_id: &str) -> Result<(), String> {
    let trimmed = chain_id.trim();
    if trimmed.is_empty() || trimmed.len() > 64 || !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err(format!("approval refused: invalid chain-id {chain_id:?}"));
    }
    *APPROVAL_CHAIN_ID.write().map_err(|_| "approval refused: chain-id lock".to_string())? = Some(trimmed.to_string());
    Ok(())
}

pub fn approval_chain_id() -> Result<String, String> {
    if let Some(id) = APPROVAL_CHAIN_ID.read().ok().and_then(|g| g.clone()) {
        return Ok(id);
    }
    match std::env::var("CW_ORCH_APPROVAL_CHAIN_ID") {
        Ok(id) if !id.trim().is_empty() => Ok(id.trim().to_string()),
        _ => Err("approval refused: chain-id is not configured (open the session on a configured chain or set CW_ORCH_APPROVAL_CHAIN_ID)".into()),
    }
}

fn approval_sign_bytes(
    chain_id: &str,
    digest: &str,
    principal: &str,
    approval: &str,
    messages: &[SigningRequest],
) -> Vec<u8> {
    let json = format!(
        "{{\"account_number\":\"0\",\"chain_id\":{chain},\"fee\":{{\"amount\":[],\"gas\":\"0\"}},\"memo\":\"cw-orch-approval:v1\",\"msgs\":[{{\"type\":\"cw-orch/Approval\",\"value\":{{\"actions\":{actions},\"digest\":{digest},\"nonce\":{approval},\"principal\":{principal}}}}}],\"sequence\":\"0\"}}",
        chain = json_string(chain_id),
        actions = actions_json(messages),
        digest = json_string(digest),
        approval = json_string(approval),
        principal = json_string(principal),
    );
    json.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .into_bytes()
}


fn address_matches(addr: &str, pk: &[u8]) -> bool {
    let Ok((hrp, data)) = bech32::decode(addr) else {
        return false;
    };
    if hrp.as_str() != crate::chain::approval_chain().bech32_prefix {
        return false;
    }
    let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(pk));
    data.as_slice() == hash.as_slice()
}

fn verify_amino(pk: &[u8], sig_bytes: &[u8], message: &[u8]) -> bool {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let Ok(vk) = k256::ecdsa::VerifyingKey::from_sec1_bytes(pk) else {
        return false;
    };
    let Ok(sig) = k256::ecdsa::Signature::from_slice(sig_bytes) else {
        return false;
    };
    let sig = sig.normalize_s().unwrap_or(sig);
    let hash = sha2::Sha256::digest(message);
    vk.verify_prehash(&hash, &sig).is_ok()
}


#[cfg(test)]
mod frame_tests {
    use super::*;
    use raptorq::{Decoder, EncodingPacket, ObjectTransmissionInformation};

    /// Zigner's reader, as `qr_reader_phone::process_payload` decodes a fountain.
    fn zigner_decode<'a>(frames: impl Iterator<Item = &'a Vec<u8>>) -> Option<Vec<u8>> {
        let mut decoder: Option<(u32, Decoder)> = None;
        for frame in frames {
            assert!(frame[0] & 0x80 != 0, "fountain tag bit");
            let size = u32::from_be_bytes([frame[0] & 0x7f, frame[1], frame[2], frame[3]]);
            let packet = EncodingPacket::deserialize(&frame[4..]);
            let d = decoder.get_or_insert_with(|| {
                (size, Decoder::new(ObjectTransmissionInformation::with_defaults(size as u64, packet.data().len() as u16)))
            });
            assert_eq!(d.0, size);
            if let Some(out) = d.1.decode(packet) {
                return Some(out);
            }
        }
        None
    }

    fn big_doc(n: usize) -> Vec<u8> {
        let mut doc = String::from("{\"account_number\":\"1\",\"chain_id\":\"morocco-1\",\"memo\":\"");
        let mut i = 0u64;
        while doc.len() < n - 3 {
            doc.push_str(&format!("{:x}", i.wrapping_mul(0x9e3779b97f4a7c15)));
            i += 1;
        }
        doc.truncate(n - 2);
        doc.push_str("\"}");
        doc.into_bytes()
    }

    #[test]
    fn a_15k_sign_doc_round_trips_through_zigner_frames() {
        let doc = big_doc(15_000);
        assert_eq!(doc.len(), 15_000);
        let request = zigner_request(0, "terp", &doc);
        assert!(qrcode::QrCode::new(&request).is_err(), "15 KB does not fit one code");
        let frames = raptor_frames(&request, ZIGNER_FRAME_BYTES).unwrap();
        let source = request.len().div_ceil(ZIGNER_FRAME_BYTES as usize);
        let repair = request.len() / ZIGNER_FRAME_BYTES as usize;
        assert_eq!(source, 16);
        assert_eq!(frames.len(), source + repair);
        assert_eq!(frames.len(), 31);
        for f in &frames {
            assert_eq!(f.len(), 4 + 4 + ZIGNER_FRAME_BYTES as usize);
            assert!(qrcode::QrCode::with_error_correction_level(f, qrcode::EcLevel::L).is_ok());
        }
        assert_eq!(zigner_decode(frames.iter()).unwrap(), request);
        // A phone that missed frames still decodes from the repair frames.
        assert_eq!(zigner_decode(frames.iter().skip(5)).unwrap(), request);
        assert_eq!(zigner_decode(frames.iter().rev()).unwrap(), request);
        assert!(zigner_decode(frames.iter().take(source - 1)).is_none());
    }

    #[test]
    fn a_small_request_stays_one_plain_code() {
        let request = zigner_request(0, "terp", b"{\"a\":1}");
        let frames = zigner_frames(&request).unwrap();
        assert_eq!(frames, vec![request.clone()]);
        assert_eq!(frames[0][..3], [0x53, 0x05, 0x10]);
        let forced = raptor_frames(&request, 8).unwrap();
        assert!(forced.len() > 1);
        assert_eq!(zigner_decode(forced.iter()).unwrap(), request);
    }

    #[test]
    fn the_session_page_animates_a_large_bundle() {
        set_approval_chain_id("morocco-1").unwrap();
        let bundles = vec![PageBundle { title: "big".into(), sign_doc: big_doc(15_000), messages: Vec::new() }];
        let html = session_page(&bundles, "terp1denpf5rdle2rwgdl8n7n22n6d3cwzt844u2qtz", 0).unwrap();
        let start = html.find("id=\"bundles\">").unwrap() + 13;
        let end = start + html[start..].find("</script>").unwrap();
        let v: serde_json::Value = serde_json::from_str(&html[start..end]).unwrap();
        assert_eq!(v[0]["frames"].as_array().unwrap().len(), 31);
        let hex_frames: Vec<Vec<u8>> = v[0]["frames_hex"].as_array().unwrap().iter()
            .map(|h| (0..h.as_str().unwrap().len()).step_by(2).map(|i| u8::from_str_radix(&h.as_str().unwrap()[i..i + 2], 16).unwrap()).collect())
            .collect();
        let doc = big_doc(15_000);
        let want = zigner_request(0, &crate::chain::approval_chain().zigner_chain_name, &doc);
        assert_eq!(zigner_decode(hex_frames.iter()).unwrap(), want);
        assert!(html.contains("animateQr(qr, bundle.frames"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::{Principal, SignDocDigest, SigningRequest, MSG_STORE_CODE};
    use futures_util::{SinkExt, StreamExt};
    use std::time::Duration;
    use tokio::net::TcpStream;

    fn view() -> ApprovalView {
        set_approval_chain_id("morocco-1").unwrap();
        ApprovalView {
            digest: SignDocDigest::new("ab".repeat(32)).unwrap(),
            principal: Principal::new("treasury").unwrap(),
            messages: vec![SigningRequest::new(MSG_STORE_CODE)],
        }
    }

    async fn client(addr: SocketAddr) -> tokio_tungstenite::WebSocketStream<TcpStream> {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (socket, _) = tokio_tungstenite::client_async(format!("ws://{addr}/ws"), stream)
            .await
            .unwrap();
        socket
    }

    #[tokio::test]
    async fn non_loopback_bind_is_refused() {
        let err = listen("0.0.0.0:1".parse().unwrap(), view(), Arc::new(TestApprover))
            .await
            .unwrap_err();
        assert!(err.contains("not loopback"));
    }

    #[tokio::test]
    async fn page_shows_the_digest_and_the_message() {
        let terminal = listen(
            "127.0.0.1:0".parse().unwrap(),
            view(),
            Arc::new(TestApprover),
        )
        .await
        .unwrap();
        let body = http_body(terminal.addr()).await;
        assert!(body.contains(&"ab".repeat(32)));
        assert!(body.contains(MSG_STORE_CODE));
        assert!(body.contains("does not hold a key"));
        assert!(body.contains("id=\"zigner-qr\""));
        assert!(body.contains("id=\"scan\""));
        assert!(body.contains("id=\"term-log\""));
        assert!(body.contains("id=\"zafu-path\""));
        assert!(body.contains("Zafu signs only after you open this"));
        assert!(body.contains("that code belongs to the previous step"));
        assert!(body.contains("Check signature"));
        assert_eq!(http_status(terminal.addr(), "/zafu-wasm/zafu_wasm.js").await, 200);
        assert_eq!(
            http_status(
                terminal.addr(),
                "/zafu-wasm/snippets/wasm-bindgen-rayon-38edf6e439f6d70d/src/workerHelpers.js"
            )
            .await,
            200
        );
        assert_eq!(http_status(terminal.addr(), "/zxing/index.min.js").await, 200);
        let other = http_status(terminal.addr(), "/../secret").await;
        assert_eq!(other, 404);
    }

    #[tokio::test]
    async fn note_reaches_the_page_as_a_log_line() {
        let terminal = listen(
            "127.0.0.1:0".parse().unwrap(),
            view(),
            Arc::new(TestApprover),
        )
        .await
        .unwrap();
        let mut socket = client(terminal.addr()).await;
        let _prompt = next_text(&mut socket).await;
        terminal.note("ok stored demo code 7");
        let line = tokio::time::timeout(Duration::from_secs(2), next_text(&mut socket))
            .await
            .expect("log line");
        assert_eq!(line, "log ok stored demo code 7");
    }

    #[tokio::test]
    async fn refusal_has_no_nonce_or_signature() {
        let mut terminal = listen(
            "127.0.0.1:0".parse().unwrap(),
            view(),
            Arc::new(TestApprover),
        )
        .await
        .unwrap();
        let mut socket = client(terminal.addr()).await;
        let prompt = next_text(&mut socket).await;
        assert!(prompt.contains("digest="));
        assert!(prompt.contains("approval="));
        assert!(!prompt.contains("nonce"));
        assert!(!prompt.contains("signature"));
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "refuse".into(),
            ))
            .await
            .unwrap();
        let reply = next_text(&mut socket).await;
        assert_eq!(reply, "refused");
        assert!(!reply.contains("nonce"));
        assert!(!reply.contains("signature"));
        assert_eq!(terminal.outcome().await.unwrap(), TerminalOutcome::Refused);
    }

    #[tokio::test]
    async fn test_factor_approves_and_other_factors_do_not() {
        let mut terminal = listen(
            "127.0.0.1:0".parse().unwrap(),
            view(),
            Arc::new(TestApprover),
        )
        .await
        .unwrap();
        let mut socket = client(terminal.addr()).await;
        let _prompt = next_text(&mut socket).await;
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "approve test".into(),
            ))
            .await
            .unwrap();
        assert_eq!(next_text(&mut socket).await, "approved");
        match terminal.outcome().await.unwrap() {
            TerminalOutcome::Approved { digest, signer } => {
                assert_eq!(digest, "ab".repeat(32));
                assert_eq!(signer, None);
            }
            TerminalOutcome::Refused => panic!("test factor was refused"),
            TerminalOutcome::Signed { .. } => panic!("session signature was not requested"),
        }

        let mut terminal = listen(
            "127.0.0.1:0".parse().unwrap(),
            view(),
            Arc::new(TestApprover),
        )
        .await
        .unwrap();
        let mut socket = client(terminal.addr()).await;
        let _prompt = next_text(&mut socket).await;
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "approve keplr".into(),
            ))
            .await
            .unwrap();
        assert_eq!(next_text(&mut socket).await, "refused");
        assert_eq!(terminal.outcome().await.unwrap(), TerminalOutcome::Refused);
    }

    #[test]
    fn approval_chain_id_is_configured_not_hardcoded() {
        assert!(set_approval_chain_id("").is_err());
        assert!(set_approval_chain_id("bad chain").is_err());
        let a = approval_sign_bytes("morocco-1", "d", "p", "n", &[]);
        let b = approval_sign_bytes("terp-1", "d", "p", "n", &[]);
        assert_ne!(a, b);
        assert!(!PAGE_SCRIPT.contains("terp-1"));
    }

    #[test]
    fn amino_preimage_sorts_keys_and_escapes() {
        let action = SigningRequest::new(MSG_STORE_CODE)
            .contract("a<b")
            .body("{\"wasm\":\"QQ==\"}");
        let bytes = approval_sign_bytes(
            "morocco-1",
            &"ab".repeat(32),
            "a<b&c",
            &"cd".repeat(32),
            std::slice::from_ref(&action),
        );
        let text = String::from_utf8(bytes).unwrap();
        let expected = format!(
            "{{\"account_number\":\"0\",\"chain_id\":\"morocco-1\",\"fee\":{{\"amount\":[],\"gas\":\"0\"}},\"memo\":\"cw-orch-approval:v1\",\"msgs\":[{{\"type\":\"cw-orch/Approval\",\"value\":{{\"actions\":[{{\"body\":\"{{\\\"wasm\\\":\\\"QQ==\\\"}}\",\"contract\":\"a\\u003cb\",\"type\":\"{url}\"}}],\"digest\":\"{}\",\"nonce\":\"{}\",\"principal\":\"a\\u003cb\\u0026c\"}}}}],\"sequence\":\"0\"}}",
            "ab".repeat(32),
            "cd".repeat(32),
            url = MSG_STORE_CODE,
        );
        assert_eq!(text, expected);
    }

    #[tokio::test]
    async fn zafu_signature_approves_and_a_bad_signature_does_not() {
        let mut terminal = listen(
            "127.0.0.1:0".parse().unwrap(),
            view(),
            Arc::new(TestApprover),
        )
        .await
        .unwrap();
        let mut socket = client(terminal.addr()).await;
        let _prompt = next_text(&mut socket).await;
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "approve zafu".into(),
            ))
            .await
            .unwrap();
        assert_eq!(next_text(&mut socket).await, "refused");
        assert_eq!(terminal.outcome().await.unwrap(), TerminalOutcome::Refused);

        let mut terminal = listen(
            "127.0.0.1:0".parse().unwrap(),
            view(),
            Arc::new(TestApprover),
        )
        .await
        .unwrap();
        let mut socket = client(terminal.addr()).await;
        let prompt = next_text(&mut socket).await;
        let approval = prompt
            .lines()
            .find_map(|line| line.strip_prefix("approval="))
            .unwrap();
        let line = zafu_line(&"ab".repeat(32), "treasury", approval, false);
        let signer = line.split_whitespace().nth(2).unwrap().to_string();
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(line.into()))
            .await
            .unwrap();
        assert_eq!(next_text(&mut socket).await, "approved");
        match terminal.outcome().await.unwrap() {
            TerminalOutcome::Approved {
                digest,
                signer: got,
            } => {
                assert_eq!(digest, "ab".repeat(32));
                assert_eq!(got.as_deref(), Some(signer.as_str()));
            }
            TerminalOutcome::Refused => panic!("zafu signature was refused"),
            TerminalOutcome::Signed { .. } => panic!("session signature was not requested"),
        }

        let mut terminal = listen(
            "127.0.0.1:0".parse().unwrap(),
            view(),
            Arc::new(TestApprover),
        )
        .await
        .unwrap();
        let mut socket = client(terminal.addr()).await;
        let prompt = next_text(&mut socket).await;
        let approval = prompt
            .lines()
            .find_map(|line| line.strip_prefix("approval="))
            .unwrap();
        let line = zafu_line(&"ab".repeat(32), "treasury", approval, true);
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(line.into()))
            .await
            .unwrap();
        assert_eq!(next_text(&mut socket).await, "refused");
        assert_eq!(terminal.outcome().await.unwrap(), TerminalOutcome::Refused);
    }

    #[tokio::test]
    async fn pasted_zigner_signature_checks_and_a_bad_one_can_be_retried() {
        let mut terminal = listen(
            "127.0.0.1:0".parse().unwrap(),
            view(),
            Arc::new(TestApprover),
        )
        .await
        .unwrap();
        let mut socket = client(terminal.addr()).await;
        let prompt = next_text(&mut socket).await;
        let approval = prompt
            .lines()
            .find_map(|line| line.strip_prefix("approval="))
            .unwrap();
        let line = zafu_line(&"ab".repeat(32), "treasury", approval, false);
        let mut parts = line.split_whitespace();
        assert_eq!(parts.next(), Some("approve"));
        assert_eq!(parts.next(), Some("zafu"));
        let signer = parts.next().unwrap();
        let pk = parts.next().unwrap();
        let sig = parts.next().unwrap();
        let bad = zafu_line(&"ab".repeat(32), "treasury", approval, true);
        let bad_sig = bad.split_whitespace().nth(4).unwrap();
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                format!("check {pk} {bad_sig}").into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            next_text(&mut socket).await,
            "refused the signature does not match these actions"
        );
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                format!("check {pk} {sig}").into(),
            ))
            .await
            .unwrap();
        assert_eq!(next_text(&mut socket).await, format!("valid {signer}"));
        match terminal.outcome().await.unwrap() {
            TerminalOutcome::Approved {
                digest,
                signer: got,
            } => {
                assert_eq!(digest, "ab".repeat(32));
                assert_eq!(got.as_deref(), Some(signer));
            }
            TerminalOutcome::Refused => panic!("checked signature was refused"),
            TerminalOutcome::Signed { .. } => panic!("session signature was not requested"),
        }
    }

    fn zafu_line(digest: &str, principal: &str, approval: &str, flip: bool) -> String {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let sk = k256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let pk = sk.verifying_key().to_encoded_point(true);
        set_approval_chain_id("morocco-1").unwrap();
        let message = approval_sign_bytes(
            "morocco-1",
            digest,
            principal,
            approval,
            &[SigningRequest::new(MSG_STORE_CODE)],
        );
        let hash = sha2::Sha256::digest(&message);
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&hash).unwrap();
        let mut sig_bytes = sig.to_bytes().to_vec();
        if flip {
            sig_bytes[0] ^= 0xff;
        }
        let addr = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("terp").unwrap(),
            ripemd::Ripemd160::digest(sha2::Sha256::digest(pk.as_bytes())).as_slice(),
        )
        .unwrap();
        format!(
            "approve zafu {addr} {} {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.as_bytes()),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig_bytes),
        )
    }

    #[tokio::test]
    async fn authorize_signature_releases_before_revoke_and_a_crossed_signature_is_refused() {
        let authorize_doc =
            br#"{"memo":"cw-orch-session:v1","msgs":[{"type":"cosmos-sdk/MsgGrant"}]}"#.to_vec();
        let revoke_doc =
            br#"{"memo":"cw-orch-session:v1","msgs":[{"type":"cosmos-sdk/MsgRevoke"}]}"#.to_vec();
        let (addr, pk, sig_authorize) = sign_doc(&authorize_doc);
        let (_, _, sig_revoke) = sign_doc(&revoke_doc);
        let bundles = vec![
            PageBundle {
                title: "authorize 1/1".into(),
                sign_doc: authorize_doc.clone(),
                messages: vec![SigningRequest::new("cosmos-sdk/MsgGrant")],
            },
            PageBundle {
                title: "session key".into(),
                sign_doc: Vec::new(),
                messages: vec![SigningRequest::new("session-key").body("store wasm")],
            },
            PageBundle {
                title: "revoke 1/1".into(),
                sign_doc: revoke_doc,
                messages: vec![SigningRequest::new("cosmos-sdk/MsgRevoke")],
            },
        ];
        let (terminal, authorized, mut revoked) = listen_bundles(
            "127.0.0.1:0".parse().unwrap(),
            &addr,
            bundles,
            0,
            1,
        )
        .await
        .unwrap();
        let body = http_body(terminal.addr()).await;
        let mut doc_hex = String::new();
        for byte in &authorize_doc {
            doc_hex.push_str(&format!("{byte:02x}"));
        }
        assert!(
            body.contains(&doc_hex),
            "the page must publish the amino doc the cold key signs"
        );
        assert!(
            body.contains("cold.indexOf(shown)"),
            "the page must check the bundle on screen"
        );
        assert!(
            body.contains("cameraOn"),
            "the camera must start again for the next bundle"
        );
        let mut socket = client(terminal.addr()).await;
        let _prompt = next_text(&mut socket).await;
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                format!("check 1 {pk} {sig_authorize}").into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            next_text(&mut socket).await,
            "refused the signature does not match these actions"
        );
        assert!(revoked.try_recv().is_err());
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                format!("check 0 {pk} {sig_authorize}").into(),
            ))
            .await
            .unwrap();
        assert_eq!(next_text(&mut socket).await, format!("authorized {addr}"));
        let got = authorized.await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].signer, addr);
        assert!(revoked.try_recv().is_err());
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                format!("check 1 {pk} {sig_revoke}").into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            next_text(&mut socket).await,
            format!("session-ready {addr}")
        );
        let revokes = revoked.await.unwrap();
        assert_eq!(revokes.len(), 1);
        assert_eq!(revokes[0].signer, addr);
        drop(terminal);
    }

    fn sign_doc(message: &[u8]) -> (String, String, String) {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let sk = k256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let pk = sk.verifying_key().to_encoded_point(true);
        let hash = sha2::Sha256::digest(message);
        let sig: k256::ecdsa::Signature = sk.sign_prehash(&hash).unwrap();
        let addr = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("terp").unwrap(),
            ripemd::Ripemd160::digest(sha2::Sha256::digest(pk.as_bytes())).as_slice(),
        )
        .unwrap();
        (
            addr,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk.as_bytes()),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes()),
        )
    }

    #[tokio::test]
    async fn dropping_the_terminal_stops_the_listener() {
        let terminal = listen(
            "127.0.0.1:0".parse().unwrap(),
            view(),
            Arc::new(TestApprover),
        )
        .await
        .unwrap();
        let addr = terminal.addr();
        drop(terminal);
        let started = std::time::Instant::now();
        loop {
            if TcpStream::connect(addr).await.is_err() {
                break;
            }
            if started.elapsed() > Duration::from_secs(2) {
                panic!("listener stayed up after drop");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn next_text(socket: &mut tokio_tungstenite::WebSocketStream<TcpStream>) -> String {
        match socket.next().await.unwrap().unwrap() {
            tokio_tungstenite::tungstenite::Message::Text(text) => text.to_string(),
            other => panic!("expected text, got {other:?}"),
        }
    }

    async fn http_body(addr: SocketAddr) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!("GET / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut body = String::new();
        stream.read_to_string(&mut body).await.unwrap();
        body.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
    }

    async fn http_status(addr: SocketAddr, path: &str) -> u16 {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        text.split_whitespace().nth(1).unwrap().parse().unwrap()
    }
}

/// Granter capture bound to purpose, chain-id, a fresh nonce and an expiry (v2 challenge).
pub fn capture_granter_for_chain_sync(
    addr: SocketAddr,
    account_index: u32,
    purpose: &str,
    chain_id: &str,
) -> Result<String, String> {
    set_approval_chain_id(chain_id)?;
    let challenge = crate::policy::GranterChallenge::new(
        purpose,
        chain_id,
        crate::policy::MAX_CHALLENGE_TTL_SECS,
        crate::policy::now_unix(),
    )?;
    let signer = capture_granter_sync(addr, account_index, &challenge.binding())?;
    if crate::policy::now_unix() >= challenge.expires_unix {
        return Err("granter refused: challenge expired before signing".into());
    }
    Ok(signer)
}
