//! Loopback approval page. The browser sees the digest and the messages.
//! It does not receive a share, a nonce, or a signature.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use tokio::sync::{oneshot, watch, Mutex};
use tokio::task::JoinHandle;

use crate::allowlist::{Principal, SignDocDigest, SigningRequest};
use crate::session::ApprovalFactor;

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

/// Result of one page decision. A refusal has no nonce and no signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalOutcome {
    Approved { digest: String },
    Refused,
}

/// Listener bound to `127.0.0.1`. Dropping it stops the listener.
pub struct Terminal {
    addr: SocketAddr,
    outcome: Option<oneshot::Receiver<TerminalOutcome>>,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
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
}

struct AppState {
    html: String,
    prompt: String,
    digest: String,
    approver: Arc<dyn Approver>,
    outcome: Arc<Mutex<Option<oneshot::Sender<TerminalOutcome>>>>,
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
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let state = AppState {
        html: page(&view),
        prompt: prompt(&view),
        digest: view.digest.as_str().to_string(),
        approver,
        outcome: Arc::new(Mutex::new(Some(outcome_tx))),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/ws", get(ws))
        .fallback(missing)
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
    })
}

fn page(view: &ApprovalView) -> String {
    let mut items = String::new();
    for message in &view.messages {
        items.push_str("<li>");
        items.push_str(&escape(&message.type_url));
        if let Some(code_id) = message.code_id {
            items.push_str(" code ");
            items.push_str(&code_id.to_string());
        }
        if let Some(contract) = &message.contract {
            items.push(' ');
            items.push_str(&escape(contract));
        }
        items.push_str("</li>");
    }
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>cw-orch approval</title></head>\
<body><p id=\"digest\">{digest}</p><p id=\"principal\">{principal}</p><ul id=\"msgs\">{items}</ul>\
<p>This page approves the digest. It does not hold a key.</p></body></html>",
        digest = escape(view.digest.as_str()),
        principal = escape(view.principal.as_str()),
    )
}

fn prompt(view: &ApprovalView) -> String {
    let mut text = format!(
        "digest={}\nprincipal={}\n",
        view.digest.as_str(),
        view.principal.as_str()
    );
    for message in &view.messages {
        text.push_str("msg=");
        text.push_str(&message.type_url);
        text.push('\n');
    }
    text
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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
    if socket
        .send(Message::Text(state.prompt.clone().into()))
        .await
        .is_err()
    {
        return;
    }
    let text = match socket.recv().await {
        Some(Ok(Message::Text(text))) => text.to_string(),
        _ => return,
    };
    let outcome = decide(text.trim(), &state.digest, state.approver.as_ref());
    let reply = match &outcome {
        TerminalOutcome::Approved { .. } => "approved",
        TerminalOutcome::Refused => "refused",
    };
    let _ = socket.send(Message::Text(reply.into())).await;
    if let Some(sender) = state.outcome.lock().await.take() {
        let _ = sender.send(outcome);
    }
}

fn decide(text: &str, digest: &str, approver: &dyn Approver) -> TerminalOutcome {
    let Some(name) = text.strip_prefix("approve ") else {
        return TerminalOutcome::Refused;
    };
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
        }
    } else {
        TerminalOutcome::Refused
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
        let other = http_status(terminal.addr(), "/../secret").await;
        assert_eq!(other, 404);
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
            TerminalOutcome::Approved { digest } => assert_eq!(digest, "ab".repeat(32)),
            TerminalOutcome::Refused => panic!("test factor was refused"),
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
