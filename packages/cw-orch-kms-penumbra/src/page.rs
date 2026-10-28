//! Loopback-only approval page: animated Zigner request QR + plan summary,
//! and a way back for the phone's answer (camera via zxing, or paste hex).
//! Each call to [`approve`] serves one plan and shuts down when it is
//! answered, refused or times out.

use crate::{auth, qr, summary::Summary};
use anyhow::{bail, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use penumbra_sdk_keys::FullViewingKey;
use penumbra_sdk_transaction::{AuthorizationData, TransactionPlan};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{oneshot, Mutex};

/// cw-orch-kms's Cosmos approval page; never bind it from here.
pub const RESERVED_PORT: u16 = 8741;

struct Session {
    plan: TransactionPlan,
    fvk: FullViewingKey,
    html: String,
    token: String,
    done: Mutex<Option<oneshot::Sender<Result<AuthorizationData, String>>>>,
    zxing: Option<Vec<u8>>,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn render(summary: &Summary, frames: &[Vec<u8>], token: &str, wallet: &str, camera: bool) -> String {
    let svgs: Vec<String> = frames.iter().map(|f| qr::frame_svg(f)).collect();
    let frames_html: String = svgs
        .iter()
        .enumerate()
        .map(|(i, s)| format!("<div class=f style=\"display:{}\">{}</div>", if i == 0 { "block" } else { "none" }, s))
        .collect();
    let rows: String = summary.actions.iter().map(|a| format!("<li>{}</li>", esc(a))).collect();
    let warns: String = summary.warnings.iter().map(|a| format!("<li>{}</li>", esc(a))).collect();
    let cam = if camera {
        r#"<button id=cam>scan Zigner's answer with camera</button><video id=v width=320 height=240 style="display:none"></video><script src="/zxing.js"></script>"#
    } else {
        "<p><small>camera scan disabled (set CW_ORCH_KMS_ZXING to zxing's umd/index.min.js)</small></p>"
    };
    format!(
        r#"<!doctype html><html><head><meta charset=utf-8><title>penumbra approval</title>
<style>body{{font-family:monospace;max-width:900px;margin:2em auto}}.w{{color:#b00}}textarea{{width:100%;height:6em}}</style></head><body>
<h2>Penumbra transaction — approve on Zigner</h2>
<p>chain <b>{chain}</b> · expiry height {exp} · fee <b>{fee}</b><br>pinned wallet {wallet}</p>
<ul>{rows}</ul>
<ul class=w>{warns}</ul>
<p>effect hash <small>{eh}</small></p>
<div id=qr>{frames_html}</div><p>{n} frame(s)</p>
<h3>Zigner's answer</h3>
{cam}
<textarea id=hex placeholder="or paste the hex Zigner shows"></textarea>
<button id=ok>submit</button> <button id=no>refuse</button>
<pre id=out></pre>
<script>
const T={token:?};
const fs=[...document.querySelectorAll('.f')];let k=0;
if(fs.length>1)setInterval(()=>{{fs[k].style.display='none';k=(k+1)%fs.length;fs[k].style.display='block'}},300);
async function send(path,body){{const r=await fetch(path,{{method:'POST',headers:{{'x-approval-token':T}},body}});document.getElementById('out').textContent=await r.text();}}
document.getElementById('ok').onclick=()=>send('/response',document.getElementById('hex').value);
document.getElementById('no').onclick=()=>send('/refuse','');
const c=document.getElementById('cam');
if(c)c.onclick=async()=>{{const v=document.getElementById('v');v.style.display='block';
 const r=new ZXing.BrowserQRCodeReader();const found=await r.decodeOnceFromVideoDevice(undefined,v);r.reset();v.style.display='none';
 document.getElementById('hex').value=found.getText();send('/response',found.getText());}};
</script></body></html>"#,
        chain = esc(&summary.chain_id),
        exp = summary.expiry_height,
        fee = esc(&summary.fee),
        wallet = esc(wallet),
        eh = esc(&summary.effect_hash),
        n = frames.len(),
        token = token,
    )
}

fn loopback_host(h: &HeaderMap) -> bool {
    let host = h.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    let name = host.rsplit_once(':').map(|(a, _)| a).unwrap_or(host);
    matches!(name, "127.0.0.1" | "localhost" | "[::1]")
}

async fn index(State(s): State<Arc<Session>>, h: HeaderMap) -> Response {
    if !loopback_host(&h) {
        return (StatusCode::FORBIDDEN, "loopback only").into_response();
    }
    Html(s.html.clone()).into_response()
}

async fn zxing_js(State(s): State<Arc<Session>>) -> Response {
    match &s.zxing {
        Some(js) => ([("content-type", "application/javascript")], js.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn authorized(s: &Session, h: &HeaderMap) -> bool {
    loopback_host(h) && h.get("x-approval-token").and_then(|v| v.to_str().ok()) == Some(s.token.as_str())
}

async fn response(State(s): State<Arc<Session>>, h: HeaderMap, body: axum::body::Bytes) -> Response {
    if !authorized(&s, &h) {
        return (StatusCode::FORBIDDEN, "bad token").into_response();
    }
    let res = auth::ZignerResponse::decode_text_or_bytes(&body).and_then(|r| auth::verify_response(&s.plan, &s.fvk, &r));
    match res {
        Ok(data) => {
            if let Some(tx) = s.done.lock().await.take() {
                let _ = tx.send(Ok(data));
            }
            (StatusCode::OK, "verified: signatures match the plan and the pinned account. you can close this page.").into_response()
        }
        // Keep the session open: a bad scan can be retried.
        Err(e) => (StatusCode::BAD_REQUEST, format!("rejected: {e:#}")).into_response(),
    }
}

async fn refuse(State(s): State<Arc<Session>>, h: HeaderMap) -> Response {
    if !authorized(&s, &h) {
        return (StatusCode::FORBIDDEN, "bad token").into_response();
    }
    if let Some(tx) = s.done.lock().await.take() {
        let _ = tx.send(Err("refused on the approval page".into()));
    }
    (StatusCode::OK, "refused").into_response()
}

fn random_token() -> String {
    let mut b = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    hex::encode(b)
}

pub fn check_bind(addr: SocketAddr) -> Result<()> {
    if !addr.ip().is_loopback() {
        bail!("approval page binds loopback only, refusing {addr}");
    }
    if addr.port() == RESERVED_PORT {
        bail!("port {RESERVED_PORT} belongs to the cw-orch-kms Cosmos approval page");
    }
    Ok(())
}

/// Serve the approval page for `plan` on `addr` (loopback) until Zigner's
/// verified answer arrives. `on_ready` gets the URL (print it, open a browser).
pub async fn approve(
    plan: &TransactionPlan,
    fvk: &FullViewingKey,
    asset_names: Vec<String>,
    addr: SocketAddr,
    timeout: Duration,
    on_ready: impl FnOnce(&str, &Summary),
) -> Result<AuthorizationData> {
    check_bind(addr)?;
    let summary = crate::summary::summarize(plan, fvk);
    let req = qr::ZignerRequest::from_plan(plan, fvk, asset_names)?.encode()?;
    let frames = qr::zigner_frames(&req)?;
    let zxing = std::env::var("CW_ORCH_KMS_ZXING").ok().and_then(|p| std::fs::read(p).ok());
    let token = random_token();
    let (tx, rx) = oneshot::channel();
    let html = render(&summary, &frames, &token, &fvk.wallet_id().to_string(), zxing.is_some());
    let session = Arc::new(Session { plan: plan.clone(), fvk: fvk.clone(), html, token, done: Mutex::new(Some(tx)), zxing });
    let app = Router::new()
        .route("/", get(index))
        .route("/zxing.js", get(zxing_js))
        .route("/response", post(response))
        .route("/refuse", post(refuse))
        .with_state(session);
    let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
    let url = format!("http://{}/", listener.local_addr()?);
    on_ready(&url, &summary);
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).with_graceful_shutdown(async { let _ = stop_rx.await; }).await
    });
    let out = tokio::time::timeout(timeout, rx).await;
    let _ = stop_tx.send(());
    let _ = server.await;
    match out {
        Err(_) => bail!("approval timed out"),
        Ok(Err(_)) => bail!("approval page closed"),
        Ok(Ok(Err(e))) => bail!(e),
        Ok(Ok(Ok(d))) => Ok(d),
    }
}
