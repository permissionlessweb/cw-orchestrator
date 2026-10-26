//! Local e2e: script-driven IBC with cw-orch-kms sessions. No hermes daemon.
//!
//! Two terpd localnets on 127.0.0.1 (/tmp/localnet2.sh):
//!   e2ea-1  rpc 36657 grpc 39090     e2eb-1  rpc 46657 grpc 49090
//! Run:
//!   ZIGNER_PHONE_BIN=<tools/zigner-phone bin> LOCALNET_ROOT=/tmp/grokbot-ibc-e2e \
//!   cargo run -p cw-orch-hermes-relayer --example kms_self_relay
//!
//!  1. relayer (in-process ibc-relayer, key generated in memory) creates
//!     clients + connection + ics20 channel.
//!  2. cw-orch-kms session: the mock Zigner phone (granter) signs the scoped,
//!     expiring authz + feegrant on the loopback page; the ephemeral grantee
//!     broadcasts MsgExec{MsgTransfer from granter}, granter pays fees.
//!  3. the script relays recv + ack itself (HermesRelayer::wait_ibc_from_txhash).
//!  4. close() revokes; on-chain query asserts nothing remains.
//!  5. skip-if-exists: a covering retained grant is reused without the page.
//!  6. revoke-on-failure: panic / early return revokes in Drop.
//! Keys/mnemonics are never printed.
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cw_orch_core::environment::{ChainInfo, ChainKind, NetworkInfo};
use cw_orch_daemon::{Daemon, TxSender};
use cw_orch_hermes_relayer::HermesRelayer;
use cw_orch_interchain_core::InterchainEnv;
use cw_orch_kms::{enable_session, query_grantee_state, ApprovalSession, SigningRequest};
use futures_util::{SinkExt, StreamExt};
use ibc_relayer_types::core::ics24_host::identifier::PortId;
use tokio_tungstenite::tungstenite::Message;

const A: &str = "e2ea-1";
const B: &str = "e2eb-1";
const NODE_A: &str = "tcp://127.0.0.1:36657";
const NODE_B: &str = "tcp://127.0.0.1:46657";
const TRANSFER: &str = "/ibc.applications.transfer.v1.MsgTransfer";

fn net() -> NetworkInfo {
    NetworkInfo { chain_name: "terp", pub_address_prefix: "terp", coin_type: 118 }
}
fn chain_a() -> ChainInfo {
    ChainInfo { kind: ChainKind::Local, chain_id: A, gas_denom: "uthiol", gas_price: 0.05,
        grpc_urls: &["http://127.0.0.1:39090"], rpc_urls: &["http://127.0.0.1:36657"],
        network_info: net(), lcd_url: None, fcd_url: None }
}
fn chain_b() -> ChainInfo {
    ChainInfo { kind: ChainKind::Local, chain_id: B, gas_denom: "uthiol", gas_price: 0.05,
        grpc_urls: &["http://127.0.0.1:49090"], rpc_urls: &["http://127.0.0.1:46657"],
        network_info: net(), lcd_url: None, fcd_url: None }
}

// minimal ICS-20 MsgTransfer wire encoding
#[derive(Clone, PartialEq, prost::Message)]
struct Coin { #[prost(string, tag = "1")] denom: String, #[prost(string, tag = "2")] amount: String }
#[derive(Clone, PartialEq, prost::Message)]
struct Height { #[prost(uint64, tag = "1")] revision_number: u64, #[prost(uint64, tag = "2")] revision_height: u64 }
#[derive(Clone, PartialEq, prost::Message)]
struct MsgTransfer {
    #[prost(string, tag = "1")] source_port: String,
    #[prost(string, tag = "2")] source_channel: String,
    #[prost(message, optional, tag = "3")] token: Option<Coin>,
    #[prost(string, tag = "4")] sender: String,
    #[prost(string, tag = "5")] receiver: String,
    #[prost(message, optional, tag = "6")] timeout_height: Option<Height>,
    #[prost(uint64, tag = "7")] timeout_timestamp: u64,
    #[prost(string, tag = "8")] memo: String,
}

struct Phone { child: std::process::Child, stdin: std::process::ChildStdin, out: BufReader<std::process::ChildStdout> }
impl Phone {
    fn spawn() -> Self {
        let bin = std::env::var("ZIGNER_PHONE_BIN").expect("ZIGNER_PHONE_BIN");
        let mut child = Command::new(bin).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Self { child, stdin, out }
    }
    fn ask(&mut self, line: &str) -> String {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
        let mut s = String::new();
        self.out.read_line(&mut s).unwrap();
        s.trim().to_string()
    }
}
impl Drop for Phone { fn drop(&mut self) { let _ = self.child.kill(); } }

fn http_get(addr: &str) -> Option<String> {
    let mut s = std::net::TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(s, "GET / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").ok()?;
    let mut body = String::new();
    s.read_to_string(&mut body).ok()?;
    Some(body)
}

/// Doc hexes of the cold-key bundles in page order ("sign":true).
fn bundle_docs(html: &str) -> Vec<String> {
    let mut docs = Vec::new();
    for part in html.split("{\"sign\":").skip(1) {
        if !part.starts_with("true") { continue; }
        let k = "\"doc\":\"";
        let i = part.find(k).unwrap() + k.len();
        let j = part[i..].find('"').unwrap();
        docs.push(part[i..i + j].to_string());
    }
    docs
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Phone thread: whenever the page at `addr` comes up, sign every cold-key
/// bundle and submit the signatures over the page websocket.
fn phone_answers(phone: Arc<Mutex<Phone>>, addr: String, pages: Arc<AtomicUsize>, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let mut last: Vec<String> = vec![];
        while !stop.load(Ordering::SeqCst) {
            let Some(html) = http_get(&addr) else { std::thread::sleep(Duration::from_millis(100)); continue };
            let docs = bundle_docs(&html);
            if docs.is_empty() || docs == last { std::thread::sleep(Duration::from_millis(100)); continue; }
            last = docs.clone();
            pages.fetch_add(1, Ordering::SeqCst);
            rt.block_on(async {
                let stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
                let (mut ws, _) = tokio_tungstenite::client_async(format!("ws://{addr}/ws"), stream).await.unwrap();
                let _prompt = ws.next().await;
                for (i, doc) in docs.iter().enumerate() {
                    let qr = cw_orch_kms::zigner_qr_hex(0, &hex_decode(doc));
                    let reply = phone.lock().unwrap().ask(&format!("sign {qr}"));
                    let mut it = reply.split_whitespace();
                    if it.next() != Some("ok") { eprintln!("phone refused bundle {i}: {reply}"); return; }
                    let (pk, sig) = (it.next().unwrap().to_string(), it.next().unwrap().to_string());
                    ws.send(Message::Text(format!("check {i} {pk} {sig}").into())).await.unwrap();
                    loop {
                        match ws.next().await {
                            Some(Ok(Message::Text(t))) if !t.starts_with("log ") => {
                                println!("  phone -> page bundle {}/{}: {}", i + 1, docs.len(), t.lines().next().unwrap_or(""));
                                break;
                            }
                            Some(Ok(_)) => continue,
                            _ => break,
                        }
                    }
                }
                let _ = tokio::time::timeout(Duration::from_secs(5), async { while let Some(Ok(_)) = ws.next().await {} }).await;
            });
        }
    });
}

fn terpd(args: &[&str]) -> String {
    let bin = std::env::var("TERPD").unwrap_or("/tmp/zcinti-v640/terpd".into());
    let out = Command::new(bin).args(args).output().expect("terpd");
    String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr)
}

fn fund(chain: &str, node: &str, to: &str) {
    let root = std::env::var("LOCALNET_ROOT").unwrap_or("/tmp/grokbot-ibc-e2e".into());
    let home = format!("{root}/{chain}");
    let out = terpd(&["tx", "bank", "send", "faucet", to, "50000000uthiol,50000000uterp", "--keyring-backend", "test",
        "--home", &home, "--chain-id", chain, "--node", node, "--fees", "10000uthiol", "-y", "-o", "json"]);
    assert!(out.contains("\"code\":0"), "fund {to} on {chain} failed: {out}");
    std::thread::sleep(Duration::from_secs(3));
}

fn balances(node: &str, addr: &str) -> String {
    terpd(&["q", "bank", "balances", addr, "--node", node, "-o", "json"])
}

fn session(granter: &str, bind: &str, retain: bool) -> ApprovalSession {
    let mut s = ApprovalSession::open(granter).allow_sdk(TRANSFER).unwrap();
    s.ttl_secs = 600; // scoped + expiring
    s.allowance_limit = 5_000_000;
    s.bind = bind.parse().unwrap();
    s.retain = retain;
    s
}

fn assert_empty(d: &Daemon, granter: &str, grantee: &str, what: &str) {
    let st = query_grantee_state(d, granter, grantee).unwrap();
    assert!(st.authz.is_empty() && st.feegrant.is_none(),
        "{what}: grants remain: {} authz, feegrant {}", st.authz.len(), st.feegrant.is_some());
    println!("  on-chain after {what}: 0 authz grants, no fee allowance ✓");
}

fn e<E: std::fmt::Display>(x: E) -> anyhow::Error { anyhow::anyhow!("{x}") }

fn main() -> anyhow::Result<()> {
    std::env::set_var("STATE_FILE", "/tmp/grokbot-ibc-e2e/cw-orch-state.json");
    let rt = tokio::runtime::Runtime::new()?;
    // relayer key: generated in memory, never printed
    let relayer_mn = bip39::Mnemonic::generate(24)?.to_string();
    std::env::set_var("TEST_MNEMONIC", &relayer_mn);

    let mut relayer = HermesRelayer::new(rt.handle(), vec![
        (chain_a(), Some(relayer_mn.clone()), false, "http://127.0.0.1:36657".to_string()),
        (chain_b(), Some(relayer_mn.clone()), false, "http://127.0.0.1:46657".to_string()),
    ], HashMap::new())?;
    let da = relayer.get_chain(A)?;
    let db = relayer.get_chain(B)?;
    let raddr = da.sender().address().to_string();
    let raddr_b = db.sender().address().to_string();
    fund(A, NODE_A, &raddr);
    fund(B, NODE_B, &raddr_b);
    println!("[1] relayer funded on both chains ({raddr})");

    let t0 = std::time::Instant::now();
    let (ca, cb) = relayer.create_connection(A, B)?;
    println!("[1] clients + connection via cw-orch-hermes-relayer: {A}:{ca} <-> {B}:{cb} ({:?})", t0.elapsed());
    let ch = relayer.create_channel(A, B, &PortId::transfer(), &PortId::transfer(), "ics20-1", None).map_err(e)?;
    let (pa, pb) = ch.interchain_channel.get_ordered_ports_from(A).map_err(e)?;
    let (chan_a, chan_b) = (pa.channel.clone().unwrap().to_string(), pb.channel.clone().unwrap().to_string());
    println!("[1] ics20 channel: {A}:transfer/{chan_a} <-> {B}:transfer/{chan_b} ({:?})", t0.elapsed());

    let phone = Arc::new(Mutex::new(Phone::spawn()));
    let granter = phone.lock().unwrap().ask("addr terp").trim_start_matches("addr ").to_string();
    fund(A, NODE_A, &granter);
    println!("[2] granter (mock Zigner key) {granter} funded on {A}");
    let bind = "127.0.0.1:38741".to_string();
    let pages = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    phone_answers(phone.clone(), bind.clone(), pages.clone(), stop.clone());

    let builder = || { let mut b = Daemon::builder(chain_a()); b.handle(rt.handle()); b };
    let receiver = db.sender().address().to_string();

    // 2-4
    let run = enable_session(&builder(), session(&granter, &bind, false),
        vec![SigningRequest::new("session-key").body(format!("MsgExec{{MsgTransfer}} over transfer/{chan_a}"))]).map_err(e)?;
    let grantee = run.grantee().to_string();
    let st = run.remaining_grants().map_err(e)?;
    println!("[2] session armed: grantee {grantee}; on-chain {} authz grants, feegrant {} (cold-key pages signed: {})",
        st.authz.len(), st.feegrant.is_some(), pages.load(Ordering::SeqCst));
    let before = balances(NODE_A, &granter);
    let now_ns = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let msg = MsgTransfer { source_port: "transfer".into(), source_channel: chan_a.clone(),
        token: Some(Coin { denom: "uterp".into(), amount: "1234".into() }), sender: granter.clone(), receiver: receiver.clone(),
        timeout_height: None, timeout_timestamp: now_ns + 600_000_000_000, memo: "cw-orch-kms self-relay e2e".into() };
    let any = cosmrs::Any { type_url: TRANSFER.into(), value: prost::Message::encode_to_vec(&msg) };
    let tx = rt.block_on(run.daemon.sender().commit_tx_any(vec![any], Some("kms transfer")))?;
    println!("[2] MsgExec{{MsgTransfer}} signed by grantee, fee by granter: tx {} code {}", tx.txhash, tx.code);
    let t1 = std::time::Instant::now();
    let flow = relayer.wait_ibc_from_txhash(A, tx.txhash.clone())?;
    println!("[3] script relayed recv+ack in-process ({:?}); {} packet(s)", t1.elapsed(), flow.packets.len());
    for p in &flow.packets {
        match p {
            cw_orch_interchain_core::IbcPacketOutcome::Success { receive_tx, ack_tx, .. } =>
                println!("    recv tx {} on {B}; ack tx {} on {A}", receive_tx.tx_id.response.txhash, ack_tx.tx_id.response.txhash),
            _ => anyhow::bail!("packet timed out"),
        }
    }
    let got = balances(NODE_B, &receiver);
    assert!(got.contains("ibc/") && got.contains("1234"), "voucher missing on {B}: {got}");
    println!("[3] receiver on {B} holds 1234 ibc/… voucher ✓  {}", compact(&got));
    println!("    granter on {A} before {} / after {}", compact(&before), compact(&balances(NODE_A, &granter)));
    let da2 = run.daemon.clone();
    run.close().map_err(e)?;
    std::thread::sleep(Duration::from_secs(2));
    assert_empty(&da2, &granter, &grantee, "close()");

    // 5 skip-if-exists
    let p0 = pages.load(Ordering::SeqCst);
    let r1 = enable_session(&builder(), session(&granter, &bind, true), vec![]).map_err(e)?;
    let p1 = pages.load(Ordering::SeqCst);
    let n1 = r1.remaining_grants().map_err(e)?.authz.len();
    drop(r1);
    let mut s2 = session(&granter, &bind, true);
    s2.ttl_secs = 300; // existing grant (ttl 600) outlives this session => covered
    let r2 = enable_session(&builder(), s2, vec![]).map_err(e)?;
    let p2 = pages.load(Ordering::SeqCst);
    let n2 = r2.remaining_grants().map_err(e)?.authz.len();
    drop(r2);
    assert_eq!(p1, p0 + 1, "first retained session should sign once");
    assert_eq!(p2, p1, "covered grant must not open the page again");
    assert_eq!(n1, n2, "no duplicate grants");
    println!("[5] skip-if-exists: 2nd session reused {n2} grant(s); no MsgGrant/GrantAllowance; cold key not asked ✓");
    let r3 = enable_session(&builder(), session(&granter, &bind, false), vec![]).map_err(e)?;
    assert_eq!(pages.load(Ordering::SeqCst), p2 + 1, "retained grant lacks revoke rights: revoke-first + regrant");
    println!("[5] conflicting (retained, no revoke rights) grant replaced in one signed tx ✓");
    r3.close().map_err(e)?;
    std::thread::sleep(Duration::from_secs(2));
    assert_empty(&da2, &granter, &grantee, "replace + close");

    // 6 revoke on failure
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let r = enable_session(&builder(), session(&granter, &bind, false), vec![]).unwrap();
        println!("[6] session open with {} grants; panicking mid-flow", r.remaining_grants().unwrap().authz.len());
        panic!("simulated script failure");
    }));
    assert!(res.is_err());
    std::thread::sleep(Duration::from_secs(2));
    assert_empty(&da2, &granter, &grantee, "panic (Drop guard)");
    let early = || -> Result<(), String> {
        let _r = enable_session(&builder(), session(&granter, &bind, false), vec![])?;
        println!("[6] session open; returning Err early via ?");
        Err("simulated early return".into())
    };
    assert!(early().is_err());
    std::thread::sleep(Duration::from_secs(2));
    assert_empty(&da2, &granter, &grantee, "early return (Drop guard)");

    stop.store(true, Ordering::SeqCst);
    println!("ALL OK");
    Ok(())
}

fn compact(json: &str) -> String {
    json.split("\"balances\":").nth(1).and_then(|s| s.split(']').next()).unwrap_or(json).replace(['\n', ' '], "") + "]"
}
