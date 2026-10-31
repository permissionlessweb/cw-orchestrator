//! Page pieces shared by every cw-orch-kms page: the Cosmos terminal pages
//! (`terminal.rs`) and the Penumbra custody page (`penumbra/page.rs`, built by
//! `packages/cw-orch-kms/penumbra`, which includes this file via `#[path]`).
//! One layout, one script, one zxing scanner, one QR/frame encoder, one token
//! scheme, so the pages cannot drift. Keep this file free of workspace-only
//! dependencies (it must build in both Cargo roots).

use axum::extract::Request;
use axum::http::{header, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Directory vendored paths are relative to: this crate (`packages/cw-orch-kms`).
/// The Penumbra build root sets `CW_ORCH_KMS_DIR` at compile time (build.rs) so
/// both builds read the same files; it is not a runtime variable.
fn kms_dir() -> &'static str {
    match option_env!("CW_ORCH_KMS_DIR") {
        Some(dir) => dir,
        None => env!("CARGO_MANIFEST_DIR"),
    }
}

/// Raptorq symbol size per animated frame. A 1000-byte symbol plus the 8-byte
/// header fits a version-24 code at ECC L.
pub const ZIGNER_FRAME_BYTES: u16 = 1000;
/// Byte-mode capacity of a version-40 code at ECC L (Zigner's own limit).
const QR_MAX_BYTES: usize = 2953;

/// `CW_ORCH_KMS_QR_FRAME_BYTES=<n>` forces animated frames of `n` bytes even
/// when the request fits one code (rehearsal / phone testing).
fn forced_frame_bytes() -> Option<u16> {
    std::env::var("CW_ORCH_KMS_QR_FRAME_BYTES").ok().and_then(|v| v.trim().parse::<u16>().ok()).filter(|n| *n >= 64)
}

/// The codes the phone scans for one Zigner request. One plain code when it
/// fits; otherwise Zigner's fountain frames (see [`raptor_frames`]).
pub fn zigner_frames(request: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    match forced_frame_bytes() {
        Some(n) => raptor_frames(request, n),
        None if qrcode::QrCode::new(request).is_ok() => Ok(vec![request.to_vec()]),
        None => raptor_frames(request, ZIGNER_FRAME_BYTES),
    }
}

/// Zigner's multi-frame format, byte for byte as `qrcode_rtx::make_data_packs`
/// writes it and `qr_reader_phone` reads it: each frame is a 4-byte big-endian
/// header (top bit 1, low 31 bits = total payload length) followed by one
/// serialized raptorq `EncodingPacket` (`Encoder::with_defaults(input, chunk)`,
/// `len / chunk` repair packets). Any `ceil(len / chunk)` distinct frames decode.
pub fn raptor_frames(input: &[u8], chunk: u16) -> Result<Vec<Vec<u8>>, String> {
    if input.is_empty() {
        return Err("qr refused: empty request".into());
    }
    if input.len() >= 0x8000_0000 || chunk == 0 {
        return Err("qr refused: request too long".into());
    }
    let head = (input.len() as u32 + 0x8000_0000).to_be_bytes();
    let repair = if input.len() as u32 <= chunk as u32 { 0 } else { input.len() as u32 / chunk as u32 };
    let encoder = raptorq::Encoder::with_defaults(input, chunk);
    let frames: Vec<Vec<u8>> = encoder
        .get_encoded_packets(repair)
        .iter()
        .map(|packet| [head.to_vec(), packet.serialize()].concat())
        .collect();
    let len = frames.first().map(|f| f.len()).unwrap_or(0);
    if frames.iter().any(|f| f.len() != len) {
        return Err("qr refused: frames have different lengths".into());
    }
    if len > QR_MAX_BYTES {
        return Err("qr refused: frame too large for one code".into());
    }
    Ok(frames)
}

pub(crate) fn frame_svg(data: &[u8]) -> String {
    match qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::L) {
        Ok(code) => code.render::<qrcode::render::svg::Color<'_>>().min_dimensions(240, 240).build(),
        Err(_) => "<p>this frame does not fit in one code.</p>".to_string(),
    }
}

pub(crate) fn json_list(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|item| json_string(item)).collect();
    format!("[{}]", parts.join(",")).replace('<', "\\u003c")
}

pub(crate) fn qr_svg(data: &[u8]) -> String {
    let Ok(code) = qrcode::QrCode::new(data) else {
        return "<p>this request does not fit in one code. use approve with zafu.</p>".to_string();
    };
    code.render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(240, 240)
        .build()
}

/// Zafu page layout shared by every cw-orch-kms page (Cosmos runs and the
/// Penumbra session). One stylesheet, so the pages cannot drift apart.
pub(crate) const PAGE_STYLE: &str = ":root{--bg:#0D0D12;--surface:#16161D;--card:#1E1E26;--line:#2A2A35;--gold:#F4A31E;--text:#E0E0E4;--dim:#707078;--ok:#50C878;--err:#C05050}\
*{box-sizing:border-box}\
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:16px/1.45 Inter,ui-sans-serif,system-ui,sans-serif}\
.shell{max-width:720px;margin:0 auto;padding:28px 20px 72px}\
.mark{margin:0;letter-spacing:.18em;font-size:12px;font-weight:650;color:var(--gold)}\
.mark span{color:var(--dim)}\
h1{font-size:28px;font-weight:650;letter-spacing:-.02em;margin:10px 0 6px}\
.lede{color:var(--dim);margin:0 0 18px}\
.row{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 10px}\
.chip{background:#1B8A5A1f;color:#8fd4ae;border:1px solid #1B8A5A66;border-radius:999px;padding:4px 10px;font-size:13px}\
.meta{color:var(--dim);font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all;margin:0 0 18px}\
#tabs{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 8px}\
#tabs:empty{display:none}\
#tabs button{background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:999px;padding:8px 14px;font:inherit;cursor:pointer}\
#tabs button.is-on{border-color:var(--gold);color:var(--gold)}\
#tabs button.is-done{border-color:var(--ok);color:var(--ok)}\
#tabs button:disabled{background:var(--card);color:var(--dim);border-color:var(--line);opacity:.55;cursor:default}\
section,.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px 16px;margin:10px 0}\
.kicker{color:var(--dim);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 8px}\
pre{white-space:pre-wrap;word-break:break-word;font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;margin:0}\
#zigner-qr{background:#fff;border-radius:16px;padding:16px;display:inline-block;margin:8px 0 16px}\
#zigner-qr p{color:#16161D;margin:0}\
#scan,#check{background:var(--gold);color:#16161D;border:0;border-radius:12px;padding:12px 16px;font:600 15px/1 Inter,ui-sans-serif,sans-serif;cursor:pointer}\
#scan:disabled,#check:disabled{background:#3D3020;color:#5A4A30}\
#zafu-approve{background:transparent;color:var(--text);border:1px solid var(--line);border-radius:12px;padding:12px 16px;font:600 15px/1 Inter,ui-sans-serif,sans-serif;cursor:pointer}\
label{display:block;color:var(--dim);font-size:13px;margin:14px 0}\
input{width:100%;margin-top:6px;background:var(--surface);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font:13px ui-monospace,SFMono-Regular,Menlo,monospace}\
video{width:min(100%,320px);border-radius:16px;background:#000;margin:8px 0}\
#scan-status,#check-result,#zafu-status{color:var(--ok);min-height:1.2em}\
.foot{color:var(--dim);font-size:13px}\
.run{background:#07070b;border:1px solid var(--line);border-radius:16px;padding:12px 14px;margin:18px 0}\
.term{min-height:9em;max-height:280px;overflow:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}\
.term div{white-space:pre-wrap;word-break:break-word}\
.term .ok{color:var(--ok)}\
.term .err{color:var(--err)}\
.term .wait{color:var(--gold)}\
.term .dim{color:var(--dim)}\
details{margin-top:8px}\
summary{cursor:pointer;color:var(--dim);font-size:13px}\
h2{font-size:19px;font-weight:650;letter-spacing:-.01em;margin:0 0 6px}\
[hidden]{display:none!important}\
.btn{background:var(--gold);color:#16161D;border:0;border-radius:12px;padding:12px 16px;font:600 15px/1 Inter,ui-sans-serif,sans-serif;cursor:pointer}\
.btn:disabled{background:#3D3020;color:#5A4A30;cursor:default}\
.btn.ghost{background:transparent;color:var(--text);border:1px solid var(--line)}\
.btn.ghost:disabled{color:var(--dim);opacity:.6}\
.btn.danger{color:var(--err);border-color:#C0505066}\
.statusbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:var(--surface);padding:10px 14px;font-size:13px}\
.conn{display:inline-flex;align-items:center;gap:6px;color:var(--dim)}\
.dot{width:9px;height:9px;border-radius:50%;background:var(--dim);display:inline-block}\
.dot.ok{background:var(--ok)}.dot.err{background:var(--err)}.dot.wait{background:var(--gold)}\
.badge{border-radius:999px;padding:3px 10px;font-size:12px;border:1px solid var(--line);color:var(--dim)}\
.badge.ok{color:var(--ok);border-color:#50C87866}.badge.err{color:var(--err);border-color:#C0505066}.badge.wait{color:var(--gold);border-color:#F4A31E66}\
.ttl{margin-left:auto;color:var(--dim);font:12px ui-monospace,SFMono-Regular,Menlo,monospace}\
.stepper{list-style:none;display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;padding:0;margin:10px 0}\
.stepper li{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:10px 12px;display:grid;grid-template-columns:auto 1fr;column-gap:8px;color:var(--dim)}\
.stepper .num{grid-row:span 2;width:24px;height:24px;border-radius:50%;border:1px solid var(--line);display:grid;place-items:center;font-size:12px;font-weight:650}\
.stepper .name{font-weight:650;font-size:14px}\
.stepper .sub{font-size:12px}\
.stepper li.is-on{border-color:var(--gold);color:var(--text)}\
.stepper li.is-on .num{background:var(--gold);color:#16161D;border-color:var(--gold)}\
.stepper li.is-done{border-color:#50C87866;color:var(--ok)}\
.stepper li.is-done .num{background:#50C87822;border-color:var(--ok)}\
.facts{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:0 0 12px;font-size:13px}\
.facts dt{color:var(--dim)}\
.facts dd{margin:0;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}\
.actions{display:grid;gap:8px;margin:0 0 12px}\
.action-card{display:flex;gap:10px;align-items:flex-start;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:10px 12px;font-size:14px;word-break:break-word}\
.action-card .num{flex:none;width:22px;height:22px;border-radius:50%;background:#F4A31E22;color:var(--gold);display:grid;place-items:center;font-size:12px;font-weight:650}\
.alert{border-radius:12px;padding:10px 12px;margin:10px 0;font-size:14px;border:1px solid var(--line);background:var(--surface);word-break:break-word}\
.alert.ok{color:var(--ok);border-color:#50C87866;background:#50C8780f}\
.alert.err{color:#e08080;border-color:#C0505066;background:#C050500f}\
.alert.wait{color:var(--gold);border-color:#F4A31E66;background:#F4A31E0f}\
.cmd{background:#07070b;border:1px solid var(--line);border-radius:10px;padding:10px 12px}\
.cmd:empty{display:none}\
.scanner.idle{opacity:.7}\
#check-result.err{color:#e08080}#check-result.wait{color:var(--gold)}
";

/// A page in the shared Zafu layout: mark, heading, lede, `body`, the cw-orch
/// run log, zxing and [`SHARED_SCRIPT`], then the page's own `script`.
/// `mark`, `heading` and `lede` are escaped; `body` and `script` are trusted.
pub(crate) fn page_shell(mark: &str, heading: &str, lede: &str, body: &str, script: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Zafu session</title>\
<style>{style}</style></head>\
<body><div class=\"shell\">\
<p class=\"mark\">ZAFU <span>·</span> {mark}</p>\
<h1>{heading}</h1>\
<p class=\"lede\">{lede}</p>\
{body}\
<section class=\"run\"><p class=\"kicker\">cw-orch</p><div class=\"term\" id=\"term-log\" role=\"log\"></div></section>\
</div>\
<script src=\"/zxing/index.min.js\"></script>\
{shared}{script}</body></html>",
        style = PAGE_STYLE,
        mark = escape(mark),
        heading = escape(heading),
        lede = escape(lede),
        body = body,
        shared = SHARED_SCRIPT,
        script = script,
    )
}

/// Page script shared by every cw-orch-kms page: QR animation, the run log
/// and the zxing camera scanner (`/zxing/index.min.js`, see [`zxing_js_bytes`]).
pub(crate) const SHARED_SCRIPT: &str = r#"<script>
var qrTimer = null;
function animateQr(el, frames, single) {
  if (qrTimer) { clearInterval(qrTimer); qrTimer = null; }
  if (!el) return;
  if (!frames || frames.length < 2) { el.innerHTML = single || ""; return; }
  var at = 0;
  var note = "<p class=\"foot\">animated code: " + frames.length + " frames. keep the phone on it until Zigner shows the request.</p>";
  el.innerHTML = frames[0] + note;
  qrTimer = setInterval(function () { at = (at + 1) % frames.length; el.innerHTML = frames[at] + note; }, 250);
}
function cwOrchLog(kind, text) {
  var log = document.getElementById("term-log");
  if (!log) return;
  var row = document.createElement("div");
  row.className = kind;
  row.textContent = text;
  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
}
var cwOrchScan = {
  start: function (video, status, onText) {
    if (!window.ZXing || !window.ZXing.BrowserQRCodeReader) {
      status.textContent = "the QR reader did not load";
      return null;
    }
    video.hidden = false;
    status.textContent = "point the camera at the phone";
    var reader = new window.ZXing.BrowserQRCodeReader(30);
    reader.decodeFromVideoDevice(undefined, video, function (found) {
      if (found) onText(found.getText());
    }).catch(function (err) {
      status.textContent = err && err.message ? err.message : "the camera did not start";
    });
    return reader;
  },
  stop: function (reader, video) {
    // zxing's reset() stops the camera but not decodeContinuously's loop, so a
    // stopped reader would keep decoding the shared <video> (and calling its
    // callback) once the next scan reuses it. Stop the loop first.
    if (reader && reader.stopContinuousDecode) {
      try { reader.stopContinuousDecode(); } catch (err) {}
    }
    if (reader && reader.reset) {
      try { reader.reset(); } catch (err) {}
    }
    if (video) video.hidden = true;
  }
};
</script>"#;

/// zxing's UMD build from the zafu checkout next to this repo. Every page
/// serves it at `/zxing/index.min.js`; no CDN, no env var.
pub(crate) const ZXING_VENDOR: &str = "../../../zafu/node_modules/@zxing/library/umd/index.min.js";

pub(crate) fn zxing_js_bytes() -> Vec<u8> {
    read_vendor(ZXING_VENDOR)
}

pub(crate) fn read_vendor(rel: &str) -> Vec<u8> {
    let path = std::path::Path::new(kms_dir()).join(rel);
    std::fs::read(path).unwrap_or_default()
}

pub(crate) async fn isolate(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-embedder-policy"),
        HeaderValue::from_static("require-corp"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

pub(crate) fn vendor_response(bytes: &[u8], content_type: &'static str) -> Response {
    if bytes.is_empty() {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    }
    ([(header::CONTENT_TYPE, content_type)], bytes.to_vec()).into_response()
}

pub(crate) fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub(crate) fn approval_token() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    hex_encode(&bytes)
}

pub(crate) fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}
