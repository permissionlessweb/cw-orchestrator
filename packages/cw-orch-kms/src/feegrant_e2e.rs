//! Local-devnet e2e for the batched cold-key setup: one Zigner document
//! carries MsgGrantAllowance + every MsgGrant, a second plan skips what is
//! live, the session key acts through MsgExec on the feegrant, and one
//! session-key tx revokes every grant and the allowance.
//!
//! The granter key is a fixed test secret standing in for the phone: it
//! signs exactly the amino document the phone would get. Never use it off a
//! local chain.
//!
//! ```sh
//! FEEGRANT_E2E_GRPC=http://127.0.0.1:<grpc> FEEGRANT_E2E_CHAIN_ID=<id> \
//!   cargo test -p cw-orch-kms --lib feegrant_e2e -- --ignored --nocapture
//! ```

use cosmrs::crypto::secp256k1::SigningKey;
use cosmrs::proto::cosmos::authz::v1beta1::MsgExec;
use cosmrs::proto::cosmos::bank::v1beta1::MsgSend;
use cosmrs::proto::cosmos::tx::v1beta1::{
    service_client::ServiceClient, BroadcastMode, BroadcastTxRequest, GetTxRequest,
};
use cosmrs::tx::{Body, Fee, SignDoc, SignerInfo};
use cosmrs::{AccountId, Coin};
use prost::Message;
use tonic::transport::Channel;

use crate::allowlist::RunAllowlist;
use crate::approval::{grantee_state, legacy_amino_raw, SignedGrant};
use crate::grant::{
    pack_qr_batches, plan_session_setup, revoke_exec_anys, SessionSetup, SetupChain,
    REVOKE_ALLOWANCE, REVOKE_AUTHZ,
};
use crate::session::{ApprovalFactor, SessionGrant};

const DENOM: &str = "uterp";

fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn addr(k: &SigningKey) -> String {
    k.public_key().account_id("terp").unwrap().to_string()
}

async fn account(channel: Channel, address: &str) -> Result<(u64, u64), String> {
    let acct = crate::approval::granter_account(channel, address).await?;
    Ok((acct.account_number, acct.sequence))
}

async fn broadcast(channel: Channel, tx_bytes: Vec<u8>, what: &str) -> Result<String, String> {
    let mut client = ServiceClient::new(channel);
    #[allow(deprecated)]
    let resp = client
        .broadcast_tx(BroadcastTxRequest { tx_bytes, mode: BroadcastMode::Sync as i32 })
        .await
        .map_err(|e| format!("{what}: broadcast: {e}"))?
        .into_inner()
        .tx_response
        .ok_or("no tx response")?;
    if resp.code != 0 {
        return Err(format!("{what}: checktx code {} {}", resp.code, resp.raw_log));
    }
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if let Ok(r) = client.get_tx(GetTxRequest { hash: resp.txhash.clone() }).await {
            let t = r.into_inner().tx_response.unwrap();
            if t.code != 0 {
                return Err(format!("{what}: deliver code {} {}", t.code, t.raw_log));
            }
            println!("{what}: {} (gas used {})", t.txhash, t.gas_used);
            return Ok(t.txhash);
        }
    }
    Err(format!("{what}: not committed"))
}

/// Session key: direct-mode tx, fee paid by the granter's allowance.
async fn session_tx(
    channel: Channel,
    chain_id: &str,
    grantee: &SigningKey,
    granter: &str,
    msgs: Vec<cosmrs::Any>,
    what: &str,
) -> Result<String, String> {
    let (num, seq) = account(channel.clone(), &addr(grantee)).await?;
    let exec = MsgExec { grantee: addr(grantee), msgs };
    let any = cosmrs::Any { type_url: "/cosmos.authz.v1beta1.MsgExec".into(), value: exec.encode_to_vec() };
    let body = Body::new(vec![any], what, 0u32);
    let mut fee = Fee::from_amount_and_gas(Coin { denom: DENOM.parse().unwrap(), amount: 20_000 }, 400_000u64);
    fee.granter = Some(granter.parse::<AccountId>().unwrap());
    let auth = SignerInfo::single_direct(Some(grantee.public_key()), seq).auth_info(fee);
    let doc = SignDoc::new(&body, &auth, &chain_id.parse().unwrap(), num).map_err(|e| e.to_string())?;
    let raw = doc.sign(grantee).map_err(|e| e.to_string())?;
    broadcast(channel, raw.to_bytes().unwrap(), what).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a local terp devnet: FEEGRANT_E2E_GRPC, FEEGRANT_E2E_CHAIN_ID"]
async fn batched_feegrant_on_local_devnet() {
    let (Ok(grpc), Ok(chain_id)) = (std::env::var("FEEGRANT_E2E_GRPC"), std::env::var("FEEGRANT_E2E_CHAIN_ID")) else {
        panic!("set FEEGRANT_E2E_GRPC and FEEGRANT_E2E_CHAIN_ID");
    };
    assert!(grpc.contains("127.0.0.1") || grpc.contains("localhost"), "local devnet only");
    let channel = Channel::from_shared(grpc).unwrap().connect().await.unwrap();
    let (cold, hot) = (key(0x42), key(0x43));
    let (granter, grantee) = (addr(&cold), addr(&hot));
    println!("granter {granter} grantee {grantee}");
    let (num, seq) = account(channel.clone(), &granter).await.expect("fund the granter first");
    account(channel.clone(), &grantee).await.expect("fund the grantee (account must exist)");

    let types = [
        "/cosmos.bank.v1beta1.MsgSend",
        "/cosmos.staking.v1beta1.MsgDelegate",
        REVOKE_AUTHZ,
        REVOKE_ALLOWANCE,
    ];
    let mut allow = RunAllowlist::default();
    for t in types {
        allow = allow.allow_type(t.to_string());
    }
    let grant = SessionGrant {
        grantee: grantee.clone(),
        expiration_unix: crate::policy::now_unix() + 900,
        session_id: "feegrant-e2e".into(),
        allowlist: allow,
        factor: ApprovalFactor::Zafu,
        nonce: [0u8; 32],
    };
    let setup = SetupChain {
        chain_id: chain_id.clone(),
        account_number: num,
        sequence: seq,
        gas: 600_000,
        fee_denom: DENOM.into(),
        fee_amount: 30_000,
    };

    // 1. One cold-key document: allowance + 4 authz grants.
    let before = grantee_state(channel.clone(), &granter, &grantee).await.unwrap();
    assert!(before.authz.is_empty() && before.feegrant.is_none(), "start clean: {before:?}");
    let SessionSetup::Sign(tx) = plan_session_setup(&granter, &grant, &before, DENOM, 5_000_000, &setup).unwrap() else {
        panic!("empty chain must ask for a signature");
    };
    let batches = pack_qr_batches(&setup, &tx, 0, "terp").unwrap();
    for (i, (_, b)) in batches.iter().enumerate() {
        let names: Vec<&str> = b.pieces.iter().map(|p| p.split('"').nth(3).unwrap_or("?")).collect();
        println!("zigner scan {}/{}: {} msgs {:?} ({} sign-doc bytes)", i + 1, batches.len(), b.pieces.len(), names, b.amino.len());
    }
    assert_eq!(batches.len(), 1, "authz + feegrant must share one scan");
    for (batch_chain, batch) in &batches {
        // What the phone does: secp256k1 over sha256(amino doc).
        let sig: k256::ecdsa::Signature = k256::ecdsa::signature::Signer::sign(
            &k256::ecdsa::SigningKey::from_slice(&[0x42; 32]).unwrap(),
            &batch.amino,
        );
        let signed = SignedGrant { pubkey: cold.public_key().to_bytes(), signature: sig.to_bytes().to_vec() };
        let raw = legacy_amino_raw(&granter, &signed, batch, batch_chain).unwrap();
        broadcast(channel.clone(), raw.to_bytes().unwrap(), "cold setup").await.unwrap();
    }
    let live = grantee_state(channel.clone(), &granter, &grantee).await.unwrap();
    assert_eq!(live.authz.len(), types.len());
    assert!(live.feegrant.is_some());

    // 2. Skip-existing: the same plan now signs nothing (zero scans).
    let (_, seq2) = account(channel.clone(), &granter).await.unwrap();
    let again = SetupChain { sequence: seq2, ..setup.clone() };
    assert_eq!(plan_session_setup(&granter, &grant, &live, DENOM, 5_000_000, &again).unwrap(), SessionSetup::Ready);
    println!("second plan: Ready (existing grants skipped, 0 scans)");

    // 3. Action: MsgExec(MsgSend) paid by the allowance.
    let send = MsgSend {
        from_address: granter.clone(),
        to_address: grantee.clone(),
        amount: vec![cosmrs::proto::cosmos::base::v1beta1::Coin { denom: DENOM.into(), amount: "1".into() }],
    };
    let any = cosmrs::Any { type_url: "/cosmos.bank.v1beta1.MsgSend".into(), value: send.encode_to_vec() };
    session_tx(channel.clone(), &chain_id, &hot, &granter, vec![any], "session action").await.unwrap();

    // 4. One session-key tx revokes everything (zero scans).
    let urls: Vec<String> = types.iter().map(|t| t.to_string()).collect();
    let revokes = revoke_exec_anys(&granter, &grantee, &urls).unwrap();
    let inner: Vec<cosmrs::Any> = revokes;
    session_tx(channel.clone(), &chain_id, &hot, &granter, inner, "session revoke").await.unwrap();
    let after = grantee_state(channel.clone(), &granter, &grantee).await.unwrap();
    println!("after revoke: {} authz, feegrant {:?}", after.authz.len(), after.feegrant);
    assert!(after.authz.is_empty(), "authz left: {:?}", after.authz);
    assert!(after.feegrant.is_none());
}
