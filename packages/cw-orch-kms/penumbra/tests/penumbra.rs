//! Offline tests. TEST-ONLY seed: derived from fixed bytes, holds nothing.
//! `zigner_sign` reimplements Zigner's `sign_penumbra_transaction`
//! (re-parse request, re-decode plan, recompute + compare effect hash, sign
//! each randomizer with ask.randomize(r)) so the wire formats are exercised
//! end to end without a phone.

use cw_orch_kms_penumbra::penumbra::{
    auth::{verify_response, ZignerResponse},
    custody::ZignerCustody,
    policy::Policy,
    page::{self, Approvals},
    qr::ZignerRequest,
    summary::summarize,
    PinnedAccount,
};
use decaf377::Fr;
use penumbra_sdk_asset::{asset::Cache, Value, STAKING_TOKEN_ASSET_ID};
use penumbra_sdk_dex::{
    lp::{action::PositionClose, plan::{PositionOpenPlan, PositionWithdrawPlan}, position::Position, Reserves},
    DirectedTradingPair,
};
use penumbra_sdk_fee::Fee;
use penumbra_sdk_keys::{keys::{Bip44Path, SeedPhrase, SpendKey}, Address, FullViewingKey};
use penumbra_sdk_proto::DomainType;
use penumbra_sdk_shielded_pool::{Ics20Withdrawal, Note, OutputPlan, SpendPlan};
use penumbra_sdk_transaction::{ActionPlan, TransactionParameters, TransactionPlan};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use cw_orch_kms_penumbra::{raptor_frames, zigner_frames};
use std::{str::FromStr, time::Duration};
use tonic012 as tonic;

const USER_DEST: &str = "penumbra1gmapdgqxe0s20trdqz0fulurzgk0agyzawp3ymtm4msks4mu9kvhm3ghw3rah3l7g727xuj5vw9jjg596ec2ecprw3hpta05rfx4djrl0y6e4ujj6cvmcf7t93ldcsquzmqf22";

fn test_key(tag: u8) -> SpendKey {
    let seed = SeedPhrase::from_randomness(&[tag; 32]);
    SpendKey::from_seed_phrase_bip44(seed, &Bip44Path::new(0))
}

fn params() -> TransactionParameters {
    TransactionParameters { expiry_height: 0, chain_id: "penumbra-1".into(), fee: Fee::from_staking_token_amount(2000u64.into()) }
}

fn upenumbra(n: u64) -> Value {
    Value { amount: n.into(), asset_id: *STAKING_TOKEN_ASSET_ID }
}

fn spend(rng: &mut ChaCha20Rng, fvk: &FullViewingKey, v: Value, pos: u64) -> SpendPlan {
    let (addr, _) = fvk.payment_address(0u32.into());
    let note = Note::generate(rng, &addr, v);
    SpendPlan::new(rng, note, pos.into())
}

fn ics20_plan(fvk: &FullViewingKey) -> TransactionPlan {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let (ret, _) = fvk.payment_address(1u32.into());
    let (me, _) = fvk.payment_address(0u32.into());
    let denom = Cache::with_known_assets().get_unit("upenumbra").unwrap().base();
    let w = Ics20Withdrawal {
        amount: 1_000_000u64.into(),
        denom,
        destination_chain_address: "terp1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqtestrecv".into(),
        return_address: ret,
        timeout_height: ibc_types::core::client::Height::new(1, 10_000_000).unwrap(),
        timeout_time: 1_899_999_960_000_000_000,
        source_channel: ibc_types::core::channel::ChannelId::from_str("channel-4").unwrap(),
        use_compat_address: true,
        ics20_memo: String::new(),
        use_transparent_address: false,
    };
    TransactionPlan {
        actions: vec![
            ActionPlan::Spend(spend(&mut rng, fvk, upenumbra(1_500_000), 3)),
            ActionPlan::Spend(spend(&mut rng, fvk, upenumbra(10_000), 9)),
            ActionPlan::Ics20Withdrawal(w),
            ActionPlan::Output(OutputPlan::new(&mut rng, upenumbra(508_000), me)),
        ],
        transaction_parameters: params(),
        detection_data: None,
        memo: None,
    }
}

fn lp_plan(fvk: &FullViewingKey) -> TransactionPlan {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let gm = Cache::with_known_assets().get_unit("ugm").unwrap().id();
    let pair = DirectedTradingPair::new(*STAKING_TOKEN_ASSET_ID, gm);
    let pos = Position::new(&mut rng, pair, 30, 1u64.into(), 1u64.into(), Reserves { r1: 1_000_000u64.into(), r2: 0u64.into() });
    let old = Position::new(&mut rng, pair, 50, 2u64.into(), 1u64.into(), Reserves { r1: 5u64.into(), r2: 7u64.into() });
    TransactionPlan {
        actions: vec![
            ActionPlan::Spend(spend(&mut rng, fvk, upenumbra(1_002_000), 1)),
            ActionPlan::PositionOpen(PositionOpenPlan { position: pos, metadata: None }),
            ActionPlan::PositionClose(PositionClose { position_id: old.id() }),
            ActionPlan::PositionWithdraw(PositionWithdrawPlan {
                reserves: old.reserves.clone(),
                position_id: old.id(),
                pair: old.phi.pair,
                sequence: 0,
                rewards: vec![],
            }),
        ],
        transaction_parameters: params(),
        detection_data: None,
        memo: None,
    }
}

/// What Zigner does with a scanned `53 03 10` request.
fn zigner_sign(request: &[u8], sk: &SpendKey) -> anyhow::Result<String> {
    let req = ZignerRequest::decode(request)?;
    let plan = TransactionPlan::decode(req.plan_bytes.as_slice())?;
    let eh = plan.effect_hash(sk.full_viewing_key())?;
    anyhow::ensure!(eh.as_bytes() == &req.effect_hash, "zigner: effect hash mismatch, refusing");
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let sign = |rs: &Vec<[u8; 32]>, rng: &mut ChaCha20Rng| -> Vec<[u8; 64]> {
        rs.iter().map(|r| {
            let r = Fr::from_le_bytes_mod_order(r);
            sk.spend_auth_key().randomize(&r).sign(&mut *rng, eh.as_bytes()).to_bytes()
        }).collect()
    };
    let resp = ZignerResponse {
        effect_hash: *eh.as_bytes(),
        spend_auths: sign(&req.spend_randomizers, &mut rng),
        delegator_vote_auths: sign(&req.delegator_vote_randomizers, &mut rng),
        lqt_vote_auths: sign(&req.lqt_vote_randomizers, &mut rng),
    };
    Ok(hex::encode(resp.encode())) // Android shows the hex string as the QR text
}

fn roundtrip(plan: &TransactionPlan, sk: &SpendKey) {
    let fvk = sk.full_viewing_key();
    Policy::default().check(plan, fvk).unwrap();
    let req = ZignerRequest::from_plan(plan, fvk, vec!["penumbra".into()]).unwrap();
    let bytes = req.encode().unwrap();
    assert_eq!(&bytes[..3], &[0x53, 0x03, 0x10]);
    assert_eq!(ZignerRequest::decode(&bytes).unwrap(), req);
    let hexresp = zigner_sign(&bytes, sk).unwrap();
    let resp = ZignerResponse::decode_text_or_bytes(hexresp.as_bytes()).unwrap();
    let data = verify_response(plan, fvk, &resp).unwrap();
    assert_eq!(data.spend_auths.len(), plan.spend_plans().count());
    // Same shape as the SDK's own authorizer output.
    let reference = plan.authorize(ChaCha20Rng::seed_from_u64(5), sk).unwrap();
    assert_eq!(data.effect_hash, reference.effect_hash);
    assert_eq!(data.spend_auths.len(), reference.spend_auths.len());
    // and the proto round-trips (what CustodyService returns)
    let back = penumbra_sdk_transaction::AuthorizationData::decode(data.encode_to_vec().as_slice()).unwrap();
    assert_eq!(back.spend_auths.len(), data.spend_auths.len());
}

#[test]
fn ics20_transfer_roundtrip() {
    let sk = test_key(7);
    roundtrip(&ics20_plan(sk.full_viewing_key()), &sk);
}

#[test]
fn lp_open_close_withdraw_roundtrip() {
    let sk = test_key(7);
    roundtrip(&lp_plan(sk.full_viewing_key()), &sk);
}

#[test]
fn summary_mentions_amounts_and_fee() {
    let sk = test_key(7);
    let s = summarize(&ics20_plan(sk.full_viewing_key()), sk.full_viewing_key());
    let t = s.to_text();
    println!("{t}");
    assert!(t.contains("ICS20 transfer out") && t.contains("channel-4") && t.contains("terp1"));
    assert!(s.fee.contains("penumbra"), "fee: {}", s.fee);
    assert!(!s.warnings.is_empty());
    let l = summarize(&lp_plan(sk.full_viewing_key()), sk.full_viewing_key()).to_text();
    println!("{l}");
    assert!(l.contains("LP open") && l.contains("LP close") && l.contains("LP withdraw"));
}

#[test]
fn other_account_on_phone_is_rejected() {
    let sk = test_key(7);
    let other = test_key(8);
    let plan = ics20_plan(sk.full_viewing_key());
    let bytes = ZignerRequest::from_plan(&plan, sk.full_viewing_key(), vec![]).unwrap().encode().unwrap();
    // Real Zigner refuses (its FVK gives another effect hash).
    assert!(zigner_sign(&bytes, &other).is_err());
    // A device that signs anyway with the wrong key is caught by us.
    let good = ZignerResponse::decode_text_or_bytes(zigner_sign(&bytes, &sk).unwrap().as_bytes()).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let mut forged = good.clone();
    for (s, p) in forged.spend_auths.iter_mut().zip(plan.spend_plans()) {
        *s = other.spend_auth_key().randomize(&p.randomizer).sign(&mut rng, &good.effect_hash).to_bytes();
    }
    let e = verify_response(&plan, sk.full_viewing_key(), &forged).unwrap_err();
    assert!(e.to_string().contains("does not verify"), "{e}");
}

#[test]
fn tampering_is_rejected() {
    let sk = test_key(7);
    let fvk = sk.full_viewing_key();
    let plan = ics20_plan(fvk);
    let bytes = ZignerRequest::from_plan(&plan, fvk, vec![]).unwrap().encode().unwrap();
    let good = ZignerResponse::decode_text_or_bytes(zigner_sign(&bytes, &sk).unwrap().as_bytes()).unwrap();
    let mut bad = good.clone();
    bad.spend_auths[1][5] ^= 1;
    assert!(verify_response(&plan, fvk, &bad).is_err());
    let mut bad = good.clone();
    bad.effect_hash[0] ^= 1;
    assert!(verify_response(&plan, fvk, &bad).unwrap_err().to_string().contains("effect hash"));
    let mut bad = good.clone();
    bad.spend_auths.pop();
    assert!(verify_response(&plan, fvk, &bad).is_err());
    // signatures for one plan don't authorize another
    let mut other_plan = plan.clone();
    other_plan.transaction_parameters.fee = Fee::from_staking_token_amount(1u64.into());
    assert!(verify_response(&other_plan, fvk, &good).is_err());
    let enc = good.encode();
    assert!(ZignerResponse::decode(&enc[..enc.len() - 1]).is_err());
    assert!(ZignerResponse::decode(&[enc.clone(), vec![0]].concat()).is_err());
}

#[test]
fn policy_and_pinning() {
    let sk = test_key(7);
    let fvk = sk.full_viewing_key();
    // the user's funding destination is not the test account → pin refuses
    assert!(Address::from_str(USER_DEST).is_ok());
    assert!(PinnedAccount::new(&fvk.to_string(), Some(USER_DEST)).is_err());
    let (mine, _) = fvk.payment_address(0u32.into());
    assert!(PinnedAccount::new(&fvk.to_string(), Some(&mine.to_string())).is_ok());

    let mut plan = ics20_plan(fvk);
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    plan.actions.push(ActionPlan::Output(OutputPlan::new(&mut rng, upenumbra(1), Address::from_str(USER_DEST).unwrap())));
    assert!(Policy::default().check(&plan, fvk).is_err());
    let p = Policy { allowed_output_addresses: vec![USER_DEST.into()], ..Default::default() };
    p.check(&plan, fvk).unwrap();

    let plan = ics20_plan(fvk);
    let p = Policy { allowed_ics20_receivers: vec!["terp1someoneelse".into()], ..Default::default() };
    assert!(p.check(&plan, fvk).is_err());
    let p = Policy { allowed_ics20_channels: vec!["channel-0".into()], ..Default::default() };
    assert!(p.check(&plan, fvk).is_err());
    let mut odd = ics20_plan(fvk);
    if let ActionPlan::Ics20Withdrawal(w) = &mut odd.actions[2] { w.timeout_time += 1; }
    assert!(Policy::default().check(&odd, fvk).is_err());
    let p = Policy { chain_id: "penumbra-testnet-phobos-2".into(), ..Default::default() };
    assert!(p.check(&plan, fvk).is_err());
    let p = Policy { allowed_actions: vec!["spend".into(), "output".into()], ..Default::default() };
    assert!(p.check(&plan, fvk).is_err());
}

#[test]
fn big_plan_goes_to_raptor_frames() {
    let sk = test_key(7);
    let fvk = sk.full_viewing_key();
    let mut plan = ics20_plan(fvk);
    let mut rng = ChaCha20Rng::seed_from_u64(6);
    for i in 0..40 {
        plan.actions.push(ActionPlan::Spend(spend(&mut rng, fvk, upenumbra(1), 100 + i)));
    }
    let bytes = ZignerRequest::from_plan(&plan, fvk, vec![]).unwrap().encode().unwrap();
    let frames = zigner_frames(&bytes).unwrap();
    assert!(frames.len() > 1, "{} bytes", bytes.len());
    let again = raptor_frames(&bytes, 1000).unwrap();
    // any ceil(len/1000) frames reconstruct the request
    let need = bytes.len().div_ceil(1000);
    let cfg = raptorq::ObjectTransmissionInformation::with_defaults(bytes.len() as u64, 1000);
    let mut dec = raptorq::Decoder::new(cfg);
    let mut out = None;
    for f in again.iter().rev().take(need + 1) {
        out = dec.decode(raptorq::EncodingPacket::deserialize(&f[4..]));
        if out.is_some() { break; }
    }
    assert_eq!(out.unwrap(), bytes);
}

// --- tiny HTTP client for the loopback page (no extra deps) ---
async fn http(addr: &str, method: &str, path: &str, token: Option<&str>, body: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tok = token.map(|t| format!("x-approval-token: {t}\r\n")).unwrap_or_default();
    let req = format!("{method} {path} HTTP/1.1\r\nhost: {addr}\r\n{tok}content-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).await.unwrap();
    let code = buf[9..12].parse().unwrap();
    (code, buf)
}

#[tokio::test]
async fn approval_page_and_custody_service_end_to_end() {
    use penumbra_sdk_proto::custody::v1::{self as pb, custody_service_server::CustodyService};
    let sk = test_key(7);
    let fvk = sk.full_viewing_key().clone();
    let plan = lp_plan(&fvk);
    let approvals = Approvals::new();
    let (url, stop, srv) = page::serve("127.0.0.1:0".parse().unwrap(), page::router(approvals.clone(), None, axum::Router::new())).await.unwrap();
    let addr = url.trim_start_matches("http://").trim_end_matches('/').to_string();
    let c = ZignerCustody::new(PinnedAccount { fvk: fvk.clone() }, Policy::default(), approvals, Duration::from_secs(30));

    // the shared page: layout, scanner and zxing from the zafu checkout
    let (code, page) = http(&addr, "GET", "/", None, "").await;
    assert_eq!(code, 200);
    assert!(page.contains("id=\"term-log\"") && page.contains("cwOrchScan") && page.contains("/zxing/index.min.js"));
    assert!(!page.contains("CW_ORCH_KMS_ZXING"));
    // zxing is served by the page itself (same vendored file as the Cosmos pages)
    let (zcode, zjs) = http(&addr, "GET", "/zxing/index.min.js", None, "").await;
    assert_eq!(zcode, 200);
    assert!(zjs.contains("text/javascript") && zjs.contains("BrowserQRCodeReader"));
    let token = page.split("id=\"page-token\">\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let req = ZignerRequest::from_plan(&plan, &fvk, vec![]).unwrap().encode().unwrap();
    let (a2, t2) = (addr.clone(), token.clone());
    let phone = tokio::spawn(async move {
        let view = wait_approval(&a2, &t2).await;
        assert!(view.contains("LP open") && view.contains("<svg"));
        // no token → refused
        assert_eq!(http(&a2, "POST", "/response", None, "00").await.0, 403);
        // garbage → 400, approval stays open
        assert_eq!(http(&a2, "POST", "/response", Some(&t2), "abcd").await.0, 400);
        let hexresp = zigner_sign(&req, &sk).unwrap();
        let (code, body) = http(&a2, "POST", "/response", Some(&t2), &hexresp).await;
        assert_eq!(code, 200, "{body}");
    });
    let resp = c
        .authorize(tonic::Request::new(pb::AuthorizeRequest { plan: Some(plan.clone().into()), pre_authorizations: vec![] }))
        .await
        .unwrap()
        .into_inner();
    phone.await.unwrap();
    let data = penumbra_sdk_transaction::AuthorizationData::try_from(resp.data.unwrap()).unwrap();
    assert_eq!(data.effect_hash.unwrap(), plan.effect_hash(&fvk).unwrap());
    assert_eq!(http(&addr, "GET", "/approval", Some(&token), "").await.1.rsplit("\r\n\r\n").next().unwrap(), "null");

    // refuse path
    let plan2 = ics20_plan(&fvk);
    let (a3, t3) = (addr.clone(), token.clone());
    let refuser = tokio::spawn(async move {
        wait_approval(&a3, &t3).await;
        http(&a3, "POST", "/refuse", Some(&t3), "").await;
    });
    let e = c.authorize_plan(&plan2).await.unwrap_err();
    refuser.await.unwrap();
    assert!(e.to_string().contains("refused"));
    let _ = stop.send(());
    let _ = srv.await;
}

async fn wait_approval(addr: &str, token: &str) -> String {
    loop {
        let (_, s) = http(addr, "GET", "/approval", Some(token), "").await;
        let body = s.rsplit("\r\n\r\n").next().unwrap_or("").to_string();
        if body != "null" && body.contains("\"frames\"") {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn page_refuses_non_loopback_and_reserved_port() {
    assert!(page::check_bind("0.0.0.0:8743".parse().unwrap()).is_err());
    assert!(page::check_bind("127.0.0.1:8741".parse().unwrap()).is_err());
    assert!(page::check_bind("127.0.0.1:8743".parse().unwrap()).is_ok());
}

// ---------------- cold-wallet view session ----------------
use cw_orch_kms_penumbra::penumbra::session;

fn zigner_fvk_binary(fvk: &FullViewingKey) -> Vec<u8> {
    // Zigner FvkExportData::encode_qr: 53 03 01 | acct u32LE | label | fvk64 | wallet_id32 | 01 zid32
    let mut b = vec![0x53, 0x03, 0x01];
    b.extend_from_slice(&0u32.to_le_bytes());
    b.push(4);
    b.extend_from_slice(b"cold");
    let inner = penumbra_sdk_proto::core::keys::v1::FullViewingKey::from(fvk.clone()).inner;
    b.extend_from_slice(&inner);
    b.extend_from_slice(&fvk.wallet_id().0);
    b.push(0x01);
    b.extend_from_slice(&[9u8; 32]);
    b
}

fn zigner_fvk_ur(fvk: &FullViewingKey) -> Vec<u8> {
    // CBOR as Zigner builds it: {1: wallet_id, 2: [#49302({1: fvk_str, 2: 0})]}
    let s = fvk.to_string();
    let mut c = vec![0xa2, 0x01, 0x58, 0x20];
    c.extend_from_slice(&fvk.wallet_id().0);
    c.extend_from_slice(&[0x02, 0x81, 0xd9, 0xc0, 0x96, 0xa2, 0x01, 0x78, s.len() as u8]);
    c.extend_from_slice(s.as_bytes());
    c.extend_from_slice(&[0x02, 0x00]);
    c
}

#[test]
fn fvk_export_formats_and_pinning() {
    let fvk = test_key(7).full_viewing_key().clone();
    let me = fvk.payment_address(0u32.into()).0;
    let bin = zigner_fvk_binary(&fvk);
    for input in [
        fvk.to_string().into_bytes(),
        bin.clone(),
        hex::encode(&bin).into_bytes(),
        bin.iter().map(|&b| b as char).collect::<String>().into_bytes(), // zxing latin-1
        ur::ur::encode(&zigner_fvk_ur(&fvk), &ur::Type::Custom("penumbra-accounts")).into_bytes(),
    ] {
        let got = session::parse_fvk_export(&input).unwrap();
        assert_eq!(got, fvk);
        assert!(session::pin(got, &me).is_ok());
    }
    // multi-part UR
    let mut enc = ur::Encoder::new(&zigner_fvk_ur(&fvk), 60, "penumbra-accounts").unwrap();
    let mut col = session::UrCollector::default();
    let mut got = None;
    for _ in 0..50 {
        if let Some(f) = col.receive(&enc.next_part().unwrap()).unwrap() { got = Some(f); break; }
    }
    assert_eq!(got.unwrap(), fvk);
    // tampered wallet id
    let mut bad = bin.clone();
    bad[3 + 4 + 1 + 4 + 64] ^= 1;
    assert!(session::parse_fvk_export(&bad).is_err());
    // other wallet's FVK never pins to the user's cold address
    let user = Address::from_str(USER_DEST).unwrap();
    let e = session::pin(fvk.clone(), &user).unwrap_err().to_string();
    assert!(!e.contains(&fvk.to_string()), "error must not echo the FVK");
}

#[test]
fn ownership_any_account_and_randomized_address() {
    use penumbra_sdk_keys::keys::AddressIndex;
    let fvk = test_key(7).full_viewing_key().clone();
    // non-zero account
    let a5 = fvk.payment_address(AddressIndex::from(5u32)).0;
    let o = session::Ownership::of(&fvk, &a5);
    assert_eq!((o.owned(), o.account(), o.randomized()), (true, Some(5), Some(false)));
    assert!(session::pin(fvk.clone(), &a5).is_ok());
    // randomized (ephemeral / IBC deposit) address on account 0 and on account 3
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    for acct in [0u32, 3] {
        let (eph, _) = fvk.ephemeral_address(&mut rng, AddressIndex::from(acct));
        let o = session::Ownership::of(&fvk, &eph);
        assert_eq!((o.owned(), o.account(), o.randomized()), (true, Some(acct), Some(true)));
        assert!(session::pin(fvk.clone(), &eph).is_ok());
        assert!(o.describe().contains("randomized"));
    }
    // a foreign wallet's address (other seed) is rejected; messages carry only the short wallet id
    let other = test_key(8).full_viewing_key().clone();
    let foreign = other.payment_address(0u32.into()).0;
    let o = session::Ownership::of(&fvk, &foreign);
    assert!(!o.owned() && o.account().is_none());
    let e = session::pin(fvk.clone(), &foreign).unwrap_err().to_string();
    assert!(e.contains(&o.wallet_id) && !e.contains(&fvk.to_string()));
    assert!(!o.describe().contains("penumbrafullviewingkey"));
    // export format + Zigner account field are reported
    let (_, info) = session::parse_fvk_export_info(&hex::encode(zigner_fvk_binary(&fvk)).into_bytes()).unwrap();
    assert_eq!(info.format, "zigner-hex");
    assert!(info.zigner_account.is_some());
}

/// Byte-exact Zigner `export_penumbra_fvk` UR (rust/signer/src/lib.rs): wallet id,
/// tag 49302, fvk text, index, name, zid. Zigner derives the exported key as
/// penumbra-sdk does (pbkdf2 + BIP32 m/44h/6532h/{account}h), so the FVK owns
/// `payment_address(0)` of the SDK derivation.
fn zigner_exact_ur(fvk: &FullViewingKey, account: u8, label: &str) -> String {
    let s = fvk.to_string();
    let mut c = vec![0xa2, 0x01, 0x58, 0x20];
    c.extend_from_slice(&fvk.wallet_id().0);
    c.extend_from_slice(&[0x02, 0x81, 0xd9, 0xc0, 0x96, 0xa0 + 4, 0x01, 0x78, s.len() as u8]);
    c.extend_from_slice(s.as_bytes());
    c.extend_from_slice(&[0x02, account]);
    c.extend_from_slice(&[0x03, 0x60 + label.len() as u8]);
    c.extend_from_slice(label.as_bytes());
    c.extend_from_slice(&[0x04, 0x58, 0x20]);
    c.extend_from_slice(&[7u8; 32]);
    ur::ur::encode(&c, &ur::Type::Custom("penumbra-accounts"))
}

#[test]
fn zigner_exact_ur_export_regression() {
    use penumbra_sdk_keys::keys::{Bip44Path, SeedPhrase, SpendKey};
    // public BIP39 test vector, never a real wallet
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let sk = SpendKey::from_seed_phrase_bip44(SeedPhrase::from_str(m).unwrap(), &Bip44Path::new(0));
    let fvk = sk.full_viewing_key().clone();
    let ur = zigner_exact_ur(&fvk, 0, "cold");
    let (got, info) = session::parse_fvk_export_info(ur.as_bytes()).unwrap();
    assert_eq!(got, fvk);
    assert_eq!((info.format, info.zigner_account), ("ur", Some(0)));
    let sdk_addr = fvk.payment_address(0u32.into()).0;
    assert!(session::pin(got.clone(), &sdk_addr).is_ok());
    // Zigner receive screen (db_handling::penumbra::keys, blake2b "PenumbraSpendKey"
    // + AES-ECB diversifier) for this seed: NOT a key-owned address. Same seed, refused.
    let zigner_receive = Address::from_str(ZIGNER_DB_HANDLING_ADDR_ABANDON).unwrap();
    assert_ne!(zigner_receive, sdk_addr);
    let o = session::Ownership::of(&got, &zigner_receive);
    assert!(!o.owned());
    // wallet-id-only payloads are rejected with a pointer to the right screen
    let e = session::parse_fvk_export(fvk.wallet_id().to_string().as_bytes()).unwrap_err().to_string();
    assert!(e.contains("wallet id, not the viewing key"));
    let mut c = vec![0xa1, 0x01, 0x58, 0x20];
    c.extend_from_slice(&fvk.wallet_id().0);
    let e = session::parse_fvk_export(ur::ur::encode(&c, &ur::Type::Custom("penumbra-accounts")).as_bytes()).unwrap_err().to_string();
    assert!(e.contains("wallet id, not the viewing key"));
    // tampered wallet id inside the UR
    let mut c2 = ur::ur::decode(&ur).unwrap().1;
    c2[4] ^= 1;
    assert!(session::parse_fvk_export(ur::ur::encode(&c2, &ur::Type::Custom("penumbra-accounts")).as_bytes()).is_err());
}

#[test]
fn session_home_is_remote_custody_only_and_wipes() {
    let fvk = test_key(7).full_viewing_key().clone();
    let d = std::env::temp_dir().join(format!("pzc-test-{}", std::process::id()));
    let home = d.join("home");
    session::write_pcli_home(&home, &fvk, "https://node.example", "127.0.0.1:8742".parse().unwrap()).unwrap();
    let cfg = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert!(cfg.contains("backend = \"Remote\"") && cfg.contains("grpc_url = \"http://127.0.0.1:8742/\""));
    for bad in ["SoftKms", "spend_key", "Encrypted", "Threshold", "governance_custody"] {
        assert!(!cfg.contains(bad));
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&home).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(std::fs::metadata(home.join("config.toml")).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(session::write_pcli_home(&d.join("h2"), &fvk, "x", "10.0.0.1:8742".parse().unwrap()).is_err());
    assert!(session::write_pcli_home(&d.join("h3"), &fvk, "x\"\n[custody]", "127.0.0.1:8742".parse().unwrap()).is_err());
    std::fs::write(home.join("pcli-view.sqlite"), vec![1u8; 100_000]).unwrap();
    session::wipe(&home).unwrap();
    assert!(!home.exists());
    let _ = std::fs::remove_dir_all(&d);
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[tokio::test]
async fn view_session_import_sign_end_wipe() {
    use penumbra_sdk_proto::custody::v1::{self as pb, custody_service_client::CustodyServiceClient};
    let sk = test_key(7);
    let fvk = sk.full_viewing_key().clone();
    let me = fvk.payment_address(0u32.into()).0.to_string();
    let state = std::env::temp_dir().join(format!("pzc-sess-{}", std::process::id()));
    let custody_port = free_port();
    let r = session::start(session::SessionConfig {
        pinned_address: me.clone(),
        policy: Policy::wallet_template("penumbra-1", vec![]),
        node_grpc_url: "https://node.example".into(),
        page: "127.0.0.1:0".parse().unwrap(),
        custody: format!("127.0.0.1:{custody_port}").parse().unwrap(),
        ttl: Duration::from_secs(60),
        approval_timeout: Duration::from_secs(30),
        state_dir: state.clone(),
    })
    .await
    .unwrap();
    let page = r.page_url.trim_start_matches("http://").trim_end_matches('/').to_string();
    let (_, html) = http(&page, "GET", "/", None, "").await;
    let tok = html.split("id=\"page-token\">\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    assert!(html.contains(&me));
    // no token / wrong wallet
    assert_eq!(http(&page, "POST", "/fvk", None, "x").await.0, 403);
    let other = test_key(8).full_viewing_key().to_string();
    let (c, body) = http(&page, "POST", "/fvk", Some(&tok), &other).await;
    assert_eq!(c, 400);
    assert!(!body.contains(&other));
    // Zigner binary export as the page sends it (hex)
    let (c, b) = http(&page, "POST", "/fvk", Some(&tok), &hex::encode(zigner_fvk_binary(&fvk))).await;
    assert_eq!(c, 200, "{b}");
    // wait for active
    let mut home = String::new();
    for _ in 0..50 {
        let (_, s) = http(&page, "GET", "/status", Some(&tok), "").await;
        if s.contains("\"state\":\"active\"") {
            home = s.split("\"home\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
            assert!(!s.contains("penumbrafullviewingkey"), "status must not leak FVK");
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(std::path::Path::new(&home).join("config.toml").exists());
    assert_eq!(std::fs::read_to_string(state.join("current-home")).unwrap(), home);

    // pcli-side: custody over loopback gRPC
    let mut client = CustodyServiceClient::connect(format!("http://127.0.0.1:{custody_port}")).await.unwrap();
    assert!(client.export_full_viewing_key(pb::ExportFullViewingKeyRequest {}).await.is_err());
    let plan = ics20_plan(&fvk);
    let req = ZignerRequest::from_plan(&plan, &fvk, vec![]).unwrap().encode().unwrap();
    let (p2, t2) = (page.clone(), tok.clone());
    let phone = tokio::spawn(async move {
        // the plan appears on the same session page
        let (_, st) = http(&p2, "GET", "/status", Some(&t2), "").await;
        assert!(st.contains("\"pending_approval\""));
        wait_approval(&p2, &t2).await;
        let (c, b) = http(&p2, "POST", "/response", Some(&t2), &zigner_sign(&req, &sk).unwrap()).await;
        assert_eq!(c, 200, "{b}");
    });
    let resp = client
        .authorize(pb::AuthorizeRequest { plan: Some(plan.clone().into()), pre_authorizations: vec![] })
        .await
        .unwrap()
        .into_inner();
    phone.await.unwrap();
    let data = penumbra_sdk_transaction::AuthorizationData::try_from(resp.data.unwrap()).unwrap();
    assert_eq!(data.effect_hash.unwrap(), plan.effect_hash(&fvk).unwrap());

    // end → wiped
    assert_eq!(http(&page, "POST", "/end", Some(&tok), "").await.0, 200);
    r.done.await.unwrap().unwrap();
    assert!(!std::path::Path::new(&home).exists());
    assert!(!state.join("current-home").exists());
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn wallet_template_policy_covers_wallet_actions() {
    let p = Policy::wallet_template("penumbra-1", vec![USER_DEST.into()]);
    for a in ["spend", "output", "ics20_withdrawal", "position_open", "position_close", "position_withdraw", "swap", "swap_claim", "delegate", "undelegate", "undelegate_claim"] {
        assert!(p.allowed_actions.iter().any(|x| x == a));
    }
    assert!(!p.allowed_actions.iter().any(|x| x == "delegator_vote" || x == "unsupported"));
    let shipped: Policy = serde_json::from_str(include_str!("../../config/penumbra/penumbra-1.policy.json")).unwrap();
    assert_eq!(shipped.allowed_actions, p.allowed_actions);
    assert_eq!(shipped.allowed_output_addresses, vec![USER_DEST.to_string()]);
    assert_eq!(shipped.chain_id, "penumbra-1");
}

/// Address Zigner's receive screen shows for the public "abandon ... about" vector
/// (computed with zigner rust/db_handling/src/penumbra/keys.rs at e064470d).
const ZIGNER_DB_HANDLING_ADDR_ABANDON: &str = "penumbra1q9xh805r9tqznerjk0r7ffmyv9u9kwftyslphe6ym7gd88hyx9fzr5rdxwnj68prshpx3530kvxkkpzenvnl0rm4vdkmj7nrw0rjr5u3979cm6258893kjtxvzmssjjwkw58vw";
