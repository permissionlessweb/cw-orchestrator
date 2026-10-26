//! Local e2e: cw-orch-kms pages <-> a mock Zigner phone built from Zigner's
//! own Rust code (tools/zigner-phone). Off by default; run with
//!   ZIGNER_PHONE_BIN=<path> cargo test -p cw-orch-kms --lib zigner_e2e -- --ignored --test-threads=1
//! The tests switch the global approval chain, so they must not share a
//! process run with the other unit tests in parallel.
//!
//! Covered per chain: v2 granter challenge -> amino authz+feegrant session
//! signed by the phone and accepted by the page -> MsgExec envelope for the
//! session key. Not covered: broadcast on a non-Terp localnet (no osmosisd /
//! junod / atomoned on the host) and the IBC/polytone leg (outline in
//! docs/zcinti-soundness-plan.md).
use crate::chain::{set_approval_chain, ChainProfile};
use crate::terminal::{capture_granter, listen_bundles, zigner_qr_hex, PageBundle};
use crate::{SigningRequest, SessionGrant, ApprovalFactor, GranteeState, SetupChain, RunAllowlist};
use futures_util::{SinkExt, StreamExt};
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use tokio_tungstenite::tungstenite::Message;

struct Phone {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Phone {
    fn spawn() -> Option<Self> {
        let bin = std::env::var("ZIGNER_PHONE_BIN").ok()?;
        let mut child = Command::new(bin).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().ok()?;
        let stdin = child.stdin.take()?;
        let stdout = BufReader::new(child.stdout.take()?);
        Some(Self { child, stdin, stdout })
    }
    fn ask(&mut self, line: &str) -> String {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
        let mut out = String::new();
        self.stdout.read_line(&mut out).unwrap();
        out.trim().to_string()
    }
    /// (pubkey_b64, sig_b64, signer) or the phone's error text.
    fn sign(&mut self, qr_hex: &str) -> Result<(String, String, String), String> {
        let reply = self.ask(&format!("sign {qr_hex}"));
        let mut it = reply.split_whitespace();
        match it.next() {
            Some("ok") => Ok((it.next().unwrap().into(), it.next().unwrap().into(), it.next().unwrap().into())),
            _ => Err(reply),
        }
    }
}

impl Drop for Phone {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

async fn ws(addr: SocketAddr) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
    for _ in 0..50 {
        if let Ok(stream) = tokio::net::TcpStream::connect(addr).await {
            if let Ok((s, _)) = tokio_tungstenite::client_async(format!("ws://{addr}/ws"), stream).await {
                return s;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("page at {addr} did not come up");
}

async fn next_text(s: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) -> String {
    loop {
        match s.next().await.unwrap().unwrap() {
            Message::Text(t) => return t.to_string(),
            _ => continue,
        }
    }
}

fn hash20(seed: u8) -> [u8; 20] {
    [seed; 20]
}

async fn run_chain(profile: ChainProfile) -> Result<(), String> {
    let Some(mut phone) = Phone::spawn() else {
        eprintln!("ZIGNER_PHONE_BIN not set; skipping");
        return Ok(());
    };
    let prefix = profile.bech32_prefix.clone();
    let chain_id = profile.chain_id.clone();
    set_approval_chain(profile.clone())?;
    println!("== {chain_id} ({prefix}, zigner chain_name {})", profile.zigner_chain_name);

    // 1. v2 granter challenge
    let challenge = crate::policy::GranterChallenge::new("e2e", &chain_id, 300, crate::policy::now_unix())?;
    let binding = challenge.binding();
    let doc = format!("cw-orch-granter:v1\n{binding}").into_bytes();
    let qr = zigner_qr_hex(0, &doc);
    let addr = free_addr();
    let capture = tokio::spawn({
        let binding = binding.clone();
        async move { capture_granter(addr, 0, &binding).await }
    });
    let mut socket = ws(addr).await;
    let _prompt = next_text(&mut socket).await;
    let (pk, sig, phone_addr) = phone.sign(&qr).map_err(|e| format!("granter: phone refused: {e}"))?;
    socket.send(Message::Text(format!("check {pk} {sig}").into())).await.unwrap();
    let reply = next_text(&mut socket).await;
    println!("granter page: {reply}");
    let granter = capture.await.unwrap()?;
    assert_eq!(granter, phone_addr);
    assert!(granter.starts_with(&format!("{prefix}1")), "{granter}");
    let doc_text = format!("cw-orch-granter:v1\n{binding}");
    challenge
        .validate(&doc_text, &chain_id, crate::policy::now_unix())?;
    println!("granter {granter} bound to {binding}");

    // 2. amino authz + feegrant session
    let grantee = profile.address(&hash20(9)).unwrap();
    let allow = RunAllowlist::default()
        .allow_type("/cosmos.bank.v1beta1.MsgSend".to_string());
    let grant = SessionGrant {
        grantee: grantee.clone(),
        expiration_unix: crate::policy::now_unix() + 600,
        session_id: format!("wallet-{grantee}"),
        allowlist: allow,
        factor: ApprovalFactor::Zafu,
        nonce: [0u8; 32],
    };
    let setup = SetupChain {
        chain_id: chain_id.clone(),
        account_number: 7,
        sequence: 0,
        gas: 400_000,
        fee_denom: profile.fee_denom.clone(),
        fee_amount: (profile.gas_price * 400_000f64).ceil() as u128,
    };
    let empty = GranteeState { grantee: grantee.clone(), authz: vec![], feegrant: None };
    let tx = match crate::plan_session_setup(&granter, &grant, &empty, &profile.fee_denom, 1_000_000, &setup)? {
        crate::SessionSetup::Sign(tx) => tx,
        crate::SessionSetup::Ready => return Err("nothing to sign".into()),
    };
    let batches = crate::grant::pack_qr_batches(&setup, &tx, 0, &profile.zigner_chain_name)?;
    let mut bundles: Vec<PageBundle> = batches
        .iter()
        .enumerate()
        .map(|(i, (_, b))| PageBundle {
            title: format!("authorize {}/{}", i + 1, batches.len()),
            sign_doc: b.amino.clone(),
            messages: vec![SigningRequest::new("cosmos-sdk/MsgGrant")],
        })
        .collect();
    bundles.push(PageBundle {
        title: "session key".into(),
        sign_doc: Vec::new(),
        messages: vec![SigningRequest::new("session-key").body("MsgExec")],
    });
    let addr = free_addr();
    let (terminal, authorized, _revoked) = listen_bundles(addr, &granter, bundles, 0, batches.len()).await?;
    let mut socket = ws(terminal.addr()).await;
    let _prompt = next_text(&mut socket).await;
    for (i, (_, b)) in batches.iter().enumerate() {
        let text = std::str::from_utf8(&b.amino).unwrap();
        assert!(text.contains(&format!("\"chain_id\":\"{chain_id}\"")));
        assert!(text.contains(&profile.fee_denom));
        let (pk, sig, signer) = phone
            .sign(&zigner_qr_hex(0, &b.amino))
            .map_err(|e| format!("session batch {i}: phone refused: {e}"))?;
        assert_eq!(signer, granter);
        socket.send(Message::Text(format!("check {i} {pk} {sig}").into())).await.unwrap();
        println!("session page batch {}/{}: {}", i + 1, batches.len(), next_text(&mut socket).await);
    }
    let got = authorized.await.map_err(|_| "page dropped authorize".to_string())?;
    assert!(got.iter().all(|c| c.signer == granter));
    println!("session authorized by {granter} for grantee {grantee} ({} signature(s))", got.len());
    drop(terminal);

    // 3. action through MsgExec, as the session key would broadcast it
    use cosmos_sdk_proto::cosmos::authz::v1beta1::MsgExec;
    use cosmos_sdk_proto::cosmos::bank::v1beta1::MsgSend;
    use cosmos_sdk_proto::prost::Message as _;
    let inner = MsgSend {
        from_address: granter.clone(),
        to_address: profile.address(&hash20(3)).unwrap(),
        amount: vec![cosmos_sdk_proto::cosmos::base::v1beta1::Coin { denom: profile.fee_denom.clone(), amount: "1".into() }],
    };
    let exec = MsgExec {
        grantee: grantee.clone(),
        msgs: vec![cosmos_sdk_proto::Any { type_url: "/cosmos.bank.v1beta1.MsgSend".into(), value: inner.encode_to_vec() }],
    };
    let bytes = exec.encode_to_vec();
    let back = MsgExec::decode(bytes.as_slice()).unwrap();
    assert_eq!(back.grantee, grantee);
    crate::chain::validate_address(&back.grantee, &prefix)?;
    println!("MsgExec built: grantee {grantee}, inner MsgSend from {granter} ({} bytes); broadcast leg stubbed (no {chain_id} localnet)", bytes.len());

    // Phone must refuse a doc whose signer is not its key.
    let foreign = profile.address(&hash20(1)).unwrap();
    let forged = String::from_utf8(batches[0].1.amino.clone()).unwrap().replace(&granter, &foreign);
    match phone.sign(&zigner_qr_hex(0, forged.as_bytes())) {
        Err(e) if e.contains("Source mismatch") => println!("foreign signer refused: {e}"),
        other => return Err(format!("phone signed for a foreign granter: {other:?}")),
    }
    Ok(())
}

fn finish(r: Result<(), String>) {
    crate::chain::clear_approval_chain();
    let _ = crate::terminal::set_approval_chain_id("morocco-1");
    r.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ZIGNER_PHONE_BIN (tools/zigner-phone)"]
async fn zigner_e2e_terp() { finish(run_chain(ChainProfile::terp().on_chain_id("zcinti-1")).await) }

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ZIGNER_PHONE_BIN (tools/zigner-phone)"]
async fn zigner_e2e_osmo() { finish(run_chain(ChainProfile::osmosis()).await) }

// juno/atone pass against Zigner branch `multichain-cosmos` (QR extension +
// KNOWN_COSMOS_CHAINS). On older Zigner they fail with "Source mismatch".
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ZIGNER_PHONE_BIN built against zigner multichain-cosmos"]
async fn zigner_e2e_juno() { finish(run_chain(ChainProfile::juno()).await) }

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ZIGNER_PHONE_BIN built against zigner multichain-cosmos"]
async fn zigner_e2e_atone() { finish(run_chain(ChainProfile::atomone()).await) }
