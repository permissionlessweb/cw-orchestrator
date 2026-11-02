//! Authz and feegrant for one script session.
//!
//! `build_session_grants` encodes the full grant set and does not broadcast.
//! `plan_session_setup` is the opt-in session path. It reuses the ephemeral
//! wallet already on chain when that authz and feegrant cover this run.
//! Otherwise it builds one amino sign document, revokes first, for the cold
//! key to sign. The phone does not submit the transaction.

use chrono::{DateTime, SecondsFormat, Utc};
use cosmrs::proto::cosmos::authz::v1beta1::{GenericAuthorization, Grant, MsgGrant, MsgRevoke};
use cosmrs::proto::cosmos::feegrant::v1beta1::{
    BasicAllowance, MsgGrantAllowance, MsgRevokeAllowance,
};
use cosmrs::proto::traits::Message;
use cosmrs::Coin;
use prost::Name;

use crate::session::SessionGrant;

/// Encoded grants. Cosmos authz stores one type URL per `MsgGrant`, so a
/// run with several type URLs produces one grant each. The feegrant is one
/// `MsgGrantAllowance`.
pub struct SessionGrants {
    pub authz: Vec<Vec<u8>>,
    pub feegrant: Vec<u8>,
}

pub fn build_session_grants(
    granter: &str,
    grant: &SessionGrant,
    fee_denom: &str,
    fee_amount: u128,
) -> Result<SessionGrants, String> {
    if granter.is_empty() {
        return Err("grant refused: empty granter".into());
    }
    if grant.allowlist_type_urls().is_empty() {
        return Err(format!(
            "grant refused: session {} has no type urls",
            grant.session_id
        ));
    }
    let expiration = Some(cosmrs::proto::tendermint::google::protobuf::Timestamp {
        seconds: grant.expiration_unix as i64,
        nanos: 0,
    });
    let mut authz = Vec::new();
    let expiration_text = rfc3339(grant.expiration_unix)?;
    for type_url in grant.allowlist_type_urls() {
        refuse_broad(&type_url, grant)?;
        let (_, bytes) = encode_planned_grant(
            granter,
            &grant.grantee,
            &type_url,
            grant,
            &expiration_text,
            grant.expiration_unix,
        )?;
        authz.push(bytes);
    }
    let allowance = BasicAllowance {
        spend_limit: vec![Coin {
            denom: fee_denom
                .parse()
                .map_err(|err| format!("grant denom refused: {err}"))?,
            amount: fee_amount,
        }
        .into()],
        expiration: expiration.clone(),
    };
    let mut allowance_bytes = Vec::new();
    allowance
        .encode(&mut allowance_bytes)
        .map_err(|err| format!("feegrant allowance encode refused: {err}"))?;
    let fee = MsgGrantAllowance {
        granter: granter.to_string(),
        grantee: grant.grantee.clone(),
        allowance: Some(cosmrs::Any {
            type_url: BasicAllowance::type_url(),
            value: allowance_bytes,
        }),
    };
    let mut feegrant = Vec::new();
    fee.encode(&mut feegrant)
        .map_err(|err| format!("feegrant encode refused: {err}"))?;
    Ok(SessionGrants { authz, feegrant })
}

/// One authz grant already stored for this grantee. `None` expiration does
/// not expire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveAuthz {
    pub type_url: String,
    pub expiration_unix: Option<u64>,
    /// `Generic` allows every message of `type_url`. A checksum or contract
    /// scope does not treat that as coverage.
    pub scope: GrantScope,
}

/// How narrow an on-chain authorization is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantScope {
    Generic,
    /// Lowercase hex checksums of Wasm the grantee may store.
    Codes(Vec<String>),
    /// Contract addresses the grantee may execute or migrate.
    Contracts(Vec<LiveContract>),
}

/// One contract inside a wasm execution or migration authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveContract {
    pub address: String,
    /// Empty means every message key.
    pub keys: Vec<String>,
    pub calls: u64,
}

impl LiveAuthz {
    pub fn generic(type_url: impl Into<String>, expiration_unix: Option<u64>) -> Self {
        Self {
            type_url: type_url.into(),
            expiration_unix,
            scope: GrantScope::Generic,
        }
    }
}

/// One basic fee allowance for this grantee. `None` limit is unlimited.
/// `None` expiration does not expire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveFeegrant {
    pub expiration_unix: Option<u64>,
    pub denom: String,
    pub limit: Option<u128>,
}

/// What a chain query reported for the ephemeral wallet. An empty authz list
/// and no feegrant means the query ran and found nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GranteeState {
    pub grantee: String,
    pub authz: Vec<LiveAuthz>,
    pub feegrant: Option<LiveFeegrant>,
}

/// Account data for the cold key that signs the setup transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupChain {
    pub chain_id: String,
    pub account_number: u64,
    pub sequence: u64,
    pub gas: u64,
    pub fee_denom: String,
    pub fee_amount: u128,
}

/// Amino bytes are the cosmjs sign-doc preimage of every message. Proto
/// bytes are the same messages, revoke first, encoded as sdk `Msg` bodies.
/// `pieces` is one amino object per message so a large grant can be split
/// into several Zigner codes without planning the session again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupTx {
    pub amino: Vec<u8>,
    pub proto: Vec<Vec<u8>>,
    pub pieces: Vec<String>,
}

/// `Ready` means this session can run on the grants already stored. `Sign`
/// is the one transaction the cold key signs to bootstrap or replace them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionSetup {
    Ready,
    Sign(SetupTx),
}

pub fn plan_session_setup(
    granter: &str,
    session: &SessionGrant,
    on_chain: &GranteeState,
    allowance_denom: &str,
    allowance_limit: u128,
    chain: &SetupChain,
) -> Result<SessionSetup, String> {
    plan_session_setup_with(
        granter,
        session,
        on_chain,
        allowance_denom,
        allowance_limit,
        chain,
        true,
    )
}

/// `prune_unlisted` revokes grants whose type URL is not in this session.
/// A retained session leaves those grants in place and signs nothing when
/// the wanted set is already covered.
pub fn plan_session_setup_with(
    granter: &str,
    session: &SessionGrant,
    on_chain: &GranteeState,
    allowance_denom: &str,
    allowance_limit: u128,
    chain: &SetupChain,
    prune_unlisted: bool,
) -> Result<SessionSetup, String> {
    if granter.is_empty() {
        return Err("grant refused: empty granter".into());
    }
    if session.grantee.is_empty() {
        return Err("grant refused: empty grantee".into());
    }
    if on_chain.grantee != session.grantee {
        return Err("ephemeral wallet mismatch".into());
    }
    if session.allowlist_type_urls().is_empty() {
        return Err(format!(
            "grant refused: session {} has no type urls",
            session.session_id
        ));
    }
    if allowance_denom.is_empty() {
        return Err("grant denom refused: empty".into());
    }
    if chain.chain_id.is_empty() {
        return Err("session setup refused: empty chain id".into());
    }
    if chain.gas == 0 {
        return Err("session setup refused: gas is 0".into());
    }
    if chain.fee_denom.is_empty() {
        return Err("session setup refused: empty fee denom".into());
    }

    let wanted = session.allowlist_type_urls();
    let mut revoke_urls = Vec::new();
    let mut grant_urls = Vec::new();
    for url in &wanted {
        refuse_broad(url, session)?;
        let existing: Vec<&LiveAuthz> = on_chain
            .authz
            .iter()
            .filter(|grant| grant.type_url == *url)
            .collect();
        if existing.is_empty() {
            grant_urls.push(url.clone());
            continue;
        }
        let time_ok = existing
            .iter()
            .all(|grant| covers(grant.expiration_unix, session.expiration_unix));
        let shape_ok = existing.iter().any(|grant| scope_covers(grant, session));
        if time_ok && shape_ok {
            continue;
        }
        revoke_urls.push(url.clone());
        grant_urls.push(url.clone());
    }
    if prune_unlisted {
        for grant in &on_chain.authz {
            if !wanted.iter().any(|url| url == &grant.type_url) {
                revoke_urls.push(grant.type_url.clone());
            }
        }
    }
    revoke_urls.sort();
    revoke_urls.dedup();

    let fee_covers = match &on_chain.feegrant {
        Some(fee) => {
            fee.denom == allowance_denom
                && fee.limit.map(|limit| limit >= allowance_limit).unwrap_or(false)
                && covers(fee.expiration_unix, session.expiration_unix)
        }
        None => false,
    };
    let revoke_fee = on_chain.feegrant.is_some() && !fee_covers;
    let grant_fee = !fee_covers;
    if revoke_urls.is_empty() && grant_urls.is_empty() && !revoke_fee && !grant_fee {
        return Ok(SessionSetup::Ready);
    }

    let expiration = rfc3339(session.expiration_unix)?;
    let mut amino_msgs = Vec::new();
    let mut proto = Vec::new();
    for url in &revoke_urls {
        let (amino, bytes) = encode_revoke(granter, &session.grantee, url)?;
        amino_msgs.push(amino);
        proto.push(bytes);
    }
    if revoke_fee {
        let (amino, bytes) = encode_revoke_allowance(granter, &session.grantee)?;
        amino_msgs.push(amino);
        proto.push(bytes);
    }
    // The fee allowance rides in front of the authz grants, so it always
    // lands in the first Zigner document and never needs a scan of its own.
    if grant_fee {
        let (amino, bytes) = encode_allowance(
            granter,
            &session.grantee,
            allowance_denom,
            allowance_limit,
            &expiration,
            session.expiration_unix,
        )?;
        amino_msgs.push(amino);
        proto.push(bytes);
    }
    for url in &grant_urls {
        let (amino, bytes) = encode_planned_grant(
            granter,
            &session.grantee,
            url,
            session,
            &expiration,
            session.expiration_unix,
        )?;
        amino_msgs.push(amino);
        proto.push(bytes);
    }
    let amino = amino_sign_doc(chain, &amino_msgs.join(","), chain.sequence);
    Ok(SessionSetup::Sign(SetupTx {
        amino,
        proto,
        pieces: amino_msgs,
    }))
}

/// Gas charged for one authz or feegrant message when a cold-key transaction
/// is bundled. A bundle stops only before the sign document would no longer
/// fit in one Zigner code; its gas is `count * MSG_GAS` at `chain`'s price.
const MSG_GAS: u64 = 200_000;

/// uterp reserved per transaction the ephemeral key broadcasts, including
/// the closing revoke.
pub const FEE_PER_TX: u128 = 5_000_000;

pub fn planned_spend_limit(tx_count: u64) -> u128 {
    FEE_PER_TX.saturating_mul(u128::from(tx_count))
}

/// Revoke every type URL in this session and the fee allowance.
/// The cold key signs this after the session key has broadcast the run.
pub const REVOKE_AUTHZ: &str = "/cosmos.authz.v1beta1.MsgRevoke";
pub const REVOKE_ALLOWANCE: &str = "/cosmos.feegrant.v1beta1.MsgRevokeAllowance";

/// Messages the ephemeral key broadcasts to drop this session.
///
/// `MsgRevoke` of [`REVOKE_AUTHZ`] is last, so the same transaction can still
/// revoke every earlier type. The fee allowance is revoked before that, after
/// the chain has already charged this transaction to the feegrant.
pub fn revoke_exec_anys(
    granter: &str,
    grantee: &str,
    type_urls: &[String],
) -> Result<Vec<cosmrs::Any>, String> {
    let mut urls: Vec<&str> = type_urls
        .iter()
        .map(String::as_str)
        .filter(|url| *url != REVOKE_AUTHZ && *url != REVOKE_ALLOWANCE)
        .collect();
    urls.sort();
    urls.dedup();
    let mut anys = Vec::new();
    for url in urls {
        let (_, bytes) = encode_revoke(granter, grantee, url)?;
        anys.push(cosmrs::Any {
            type_url: REVOKE_AUTHZ.to_string(),
            value: bytes,
        });
    }
    let (_, allowance) = encode_revoke_allowance(granter, grantee)?;
    anys.push(cosmrs::Any {
        type_url: REVOKE_ALLOWANCE.to_string(),
        value: allowance,
    });
    let (_, fee_grant) = encode_revoke(granter, grantee, REVOKE_ALLOWANCE)?;
    anys.push(cosmrs::Any {
        type_url: REVOKE_AUTHZ.to_string(),
        value: fee_grant,
    });
    let (_, self_grant) = encode_revoke(granter, grantee, REVOKE_AUTHZ)?;
    anys.push(cosmrs::Any {
        type_url: REVOKE_AUTHZ.to_string(),
        value: self_grant,
    });
    Ok(anys)
}

#[allow(dead_code)]
pub fn build_revoke_tx(
    granter: &str,
    grantee: &str,
    type_urls: &[String],
    chain: &SetupChain,
) -> Result<SetupTx, String> {
    let mut pieces = Vec::new();
    let mut proto = Vec::new();
    for url in type_urls {
        let (amino, bytes) = encode_revoke(granter, grantee, url)?;
        pieces.push(amino);
        proto.push(bytes);
    }
    let (amino, bytes) = encode_revoke_allowance(granter, grantee)?;
    pieces.push(amino);
    proto.push(bytes);
    let amino = amino_sign_doc(chain, &pieces.join(","), chain.sequence);
    Ok(SetupTx {
        amino,
        proto,
        pieces,
    })
}

/// Split one planned setup into Zigner-sized sign documents.
///
/// Only the Zigner QR size splits documents. Sequences are `chain.sequence`, then the next, and so on. The fee on each
/// document is that bundle's gas at `chain`'s gas price. The feegrant
/// message is planned first, so it is always in the first document.
pub fn pack_qr_batches(
    chain: &SetupChain,
    tx: &SetupTx,
    account_index: u32,
    chain_name: &str,
) -> Result<Vec<(SetupChain, SetupTx)>, String> {
    if tx.pieces.is_empty() || tx.pieces.len() != tx.proto.len() {
        return Err(format!(
            "session grant refused: {} amino pieces and {} proto messages",
            tx.pieces.len(),
            tx.proto.len()
        ));
    }
    let mut batches = Vec::new();
    let mut start = 0;
    while start < tx.pieces.len() {
        let sequence = chain
            .sequence
            .checked_add(batches.len() as u64)
            .ok_or_else(|| "session grant refused: sequence overflow".to_string())?;
        let mut end = start + 1;
        while end < tx.pieces.len() {
            // Only the QR size splits a document. Gas grows with the
            // bundle (fee scales at the same price), so authz and feegrant
            // messages share one scan instead of spilling into a second.
            let count = (end - start + 1) as u64;
            let candidate = bundle_chain(chain, sequence, count);
            let amino = amino_sign_doc(&candidate, &tx.pieces[start..=end].join(","), sequence);
            if !crate::terminal::zigner_request_fits(account_index, chain_name, &amino) {
                break;
            }
            end += 1;
        }
        let count = (end - start) as u64;
        let batch_chain = bundle_chain(chain, sequence, count);
        // The cold key signs this document. The broadcast fee has to be these
        // same numbers, or the chain rebuilds different bytes and rejects it.
        let amino = amino_sign_doc(&batch_chain, &tx.pieces[start..end].join(","), sequence);
        if !crate::terminal::zigner_request_fits(account_index, chain_name, &amino) {
            return Err(
                "session grant refused: one message does not fit in a zigner code".into(),
            );
        }
        batches.push((
            batch_chain,
            SetupTx {
                amino,
                proto: tx.proto[start..end].to_vec(),
                pieces: tx.pieces[start..end].to_vec(),
            },
        ));
        start = end;
    }
    Ok(batches)
}

fn bundle_chain(chain: &SetupChain, sequence: u64, count: u64) -> SetupChain {
    let gas = count.saturating_mul(MSG_GAS).max(MSG_GAS);
    let mut batch = chain.clone();
    batch.sequence = sequence;
    batch.gas = gas;
    batch.fee_amount = if chain.gas == 0 {
        chain.fee_amount
    } else {
        chain
            .fee_amount
            .saturating_mul(u128::from(gas))
            .div_ceil(u128::from(chain.gas))
    };
    batch
}

/// A grant with no expiration never counts as coverage: it is revoked and
/// replaced by one that expires with this session, so a lost revoke still
/// ends on its own. An expired or shorter grant is replaced the same way.
fn covers(expiration: Option<u64>, needed: u64) -> bool {
    match expiration {
        None => false,
        Some(at) => at >= needed,
    }
}

fn rfc3339(unix: u64) -> Result<String, String> {
    let seconds = i64::try_from(unix)
        .map_err(|_| format!("grant expiration refused: {unix}"))?;
    let stamp = DateTime::<Utc>::from_timestamp(seconds, 0)
        .ok_or_else(|| format!("grant expiration refused: {unix}"))?;
    Ok(stamp.to_rfc3339_opts(SecondsFormat::Secs, true))
}

pub fn parse_wasm_grant(type_url: &str, value: &[u8]) -> Result<Option<LiveAuthz>, String> {
    use cosmos_sdk_proto::cosmwasm::wasm::v1::{
        AcceptedMessageKeysFilter, AllowAllMessagesFilter, CombinedLimit,
        ContractExecutionAuthorization, ContractMigrationAuthorization, MaxCallsLimit,
        StoreCodeAuthorization,
    };
    use crate::allowlist::{MSG_EXECUTE, MSG_MIGRATE, MSG_STORE_CODE};
    if type_url == StoreCodeAuthorization::type_url() {
        let auth = StoreCodeAuthorization::decode(value)
            .map_err(|err| format!("authz grant refused: {err}"))?;
        let codes = auth
            .grants
            .into_iter()
            .map(|grant| hex_encode(&grant.code_hash))
            .collect();
        return Ok(Some(LiveAuthz {
            type_url: MSG_STORE_CODE.into(),
            expiration_unix: None,
            scope: GrantScope::Codes(codes),
        }));
    }
    let contracts = if type_url == ContractExecutionAuthorization::type_url() {
        let auth = ContractExecutionAuthorization::decode(value)
            .map_err(|err| format!("authz grant refused: {err}"))?;
        Some((MSG_EXECUTE, auth.grants))
    } else if type_url == ContractMigrationAuthorization::type_url() {
        let auth = ContractMigrationAuthorization::decode(value)
            .map_err(|err| format!("authz grant refused: {err}"))?;
        Some((MSG_MIGRATE, auth.grants))
    } else {
        None
    };
    let Some((msg, grants)) = contracts else {
        return Ok(None);
    };
    let mut live = Vec::new();
    for grant in grants {
        let calls = match grant.limit {
            Some(any) if any.type_url == MaxCallsLimit::type_url() => {
                MaxCallsLimit::decode(any.value.as_slice())
                    .map_err(|err| format!("authz grant refused: {err}"))?
                    .remaining
            }
            Some(any) if any.type_url == CombinedLimit::type_url() => {
                CombinedLimit::decode(any.value.as_slice())
                    .map_err(|err| format!("authz grant refused: {err}"))?
                    .calls_remaining
            }
            _ => 0,
        };
        let keys = match grant.filter {
            // Live allow-all grants are treated as keyless, which matches nothing.
            Some(any) if any.type_url == AllowAllMessagesFilter::type_url() => Vec::new(),
            Some(any) if any.type_url == AcceptedMessageKeysFilter::type_url() => {
                AcceptedMessageKeysFilter::decode(any.value.as_slice())
                    .map_err(|err| format!("authz grant refused: {err}"))?
                    .keys
            }
            _ => Vec::new(),
        };
        live.push(LiveContract {
            address: grant.contract,
            keys,
            calls,
        });
    }
    Ok(Some(LiveAuthz {
        type_url: msg.into(),
        expiration_unix: None,
        scope: GrantScope::Contracts(live),
    }))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn refuse_broad(url: &str, session: &SessionGrant) -> Result<(), String> {
    use crate::allowlist::{MSG_EXECUTE, MSG_MIGRATE, MSG_STORE_CODE};
    const FORBIDDEN: &[&str] = &[
        "/cosmos.authz.v1beta1.MsgGrant",
        "/cosmos.authz.v1beta1.MsgExec",
        "/cosmos.feegrant.v1beta1.MsgGrantAllowance",
    ];
    let nested = url == crate::allowlist::MSG_AUTHZ_EXEC && session.allowlist.nested_exec();
    if FORBIDDEN.contains(&url) && !nested {
        return Err(format!("grant refused: {url} is not granted to a session key"));
    }
    for call in session.allowlist.executes().iter().chain(session.allowlist.migrates()) {
        crate::policy::validate_calls(&call.address, call.calls)
            .map_err(|e| format!("grant refused: {e}"))?;
    }
    if url == MSG_STORE_CODE && !session.allowlist.has_store_scope() {
        return Err("grant refused: store needs the wasm checksum".into());
    }
    if url == MSG_EXECUTE && !session.allowlist.has_execute_scope() {
        return Err("grant refused: execute needs a contract address".into());
    }
    if url == MSG_MIGRATE && !session.allowlist.has_migrate_scope() {
        return Err("grant refused: migrate needs a contract address".into());
    }
    Ok(())
}

fn scope_covers(live: &LiveAuthz, session: &SessionGrant) -> bool {
    use crate::allowlist::{MSG_EXECUTE, MSG_MIGRATE, MSG_STORE_CODE};
    let allow = &session.allowlist;
    match &live.scope {
        GrantScope::Generic => {
            (live.type_url != MSG_STORE_CODE || !allow.has_store_scope())
                && (live.type_url != MSG_EXECUTE || !allow.has_execute_scope())
                && (live.type_url != MSG_MIGRATE || !allow.has_migrate_scope())
        }
        GrantScope::Codes(have) => {
            allow.has_store_scope()
                && allow
                    .stores()
                    .iter()
                    .all(|want| have.iter().any(|code| code == want))
        }
        GrantScope::Contracts(have) => {
            let wanted = if live.type_url == MSG_EXECUTE {
                allow.executes()
            } else if live.type_url == MSG_MIGRATE {
                allow.migrates()
            } else {
                return false;
            };
            !wanted.is_empty()
                && wanted.iter().all(|want| {
                    have.iter().any(|grant| {
                        grant.address == want.address
                            && grant.calls >= want.calls
                            && ((grant.keys.is_empty() && live.type_url == MSG_MIGRATE)
                                || want.keys.iter().all(|key| grant.keys.iter().any(|have| have == key)))
                    })
                })
        }
    }
}

fn encode_planned_grant(
    granter: &str,
    grantee: &str,
    url: &str,
    session: &SessionGrant,
    expiration_text: &str,
    expiration_unix: u64,
) -> Result<(String, Vec<u8>), String> {
    use crate::allowlist::{MSG_EXECUTE, MSG_MIGRATE, MSG_STORE_CODE};
    if url == MSG_STORE_CODE {
        return encode_store_grant(granter, grantee, session, expiration_text, expiration_unix);
    }
    if url == MSG_EXECUTE {
        return encode_contract_grant(
            granter,
            grantee,
            session.allowlist.executes(),
            false,
            expiration_text,
            expiration_unix,
        );
    }
    if url == MSG_MIGRATE {
        return encode_contract_grant(
            granter,
            grantee,
            session.allowlist.migrates(),
            true,
            expiration_text,
            expiration_unix,
        );
    }
    encode_grant(granter, grantee, url, expiration_text, expiration_unix)
}

fn encode_revoke(granter: &str, grantee: &str, type_url: &str) -> Result<(String, Vec<u8>), String> {
    let msg = MsgRevoke {
        granter: granter.to_string(),
        grantee: grantee.to_string(),
        msg_type_url: type_url.to_string(),
    };
    let mut bytes = Vec::new();
    msg.encode(&mut bytes)
        .map_err(|err| format!("revoke encode refused: {err}"))?;
    let amino = format!(
        "{{\"type\":\"cosmos-sdk/MsgRevoke\",\"value\":{{\"grantee\":{grantee},\"granter\":{granter},\"msg_type_url\":{type_url}}}}}",
        grantee = json_string(grantee),
        granter = json_string(granter),
        type_url = json_string(type_url),
    );
    Ok((amino, bytes))
}

fn encode_revoke_allowance(granter: &str, grantee: &str) -> Result<(String, Vec<u8>), String> {
    let msg = MsgRevokeAllowance {
        granter: granter.to_string(),
        grantee: grantee.to_string(),
    };
    let mut bytes = Vec::new();
    msg.encode(&mut bytes)
        .map_err(|err| format!("revoke allowance encode refused: {err}"))?;
    let amino = format!(
        "{{\"type\":\"cosmos-sdk/MsgRevokeAllowance\",\"value\":{{\"grantee\":{grantee},\"granter\":{granter}}}}}",
        grantee = json_string(grantee),
        granter = json_string(granter),
    );
    Ok((amino, bytes))
}

fn proto_any(type_url: &str, value: Vec<u8>) -> cosmrs::Any {
    // cosmrs::Any is the tendermint-proto copy cosmos-sdk-proto was built
    // against. The workspace path copy is a different crate.
    cosmrs::Any {
        type_url: type_url.to_string(),
        value,
    }
}

fn encode_message<M: Message>(message: &M) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    message
        .encode(&mut bytes)
        .map_err(|err| format!("grant encode refused: {err}"))?;
    Ok(bytes)
}

fn encode_store_grant(
    granter: &str,
    grantee: &str,
    session: &SessionGrant,
    expiration_text: &str,
    expiration_unix: u64,
) -> Result<(String, Vec<u8>), String> {
    use cosmos_sdk_proto::cosmwasm::wasm::v1::{CodeGrant, StoreCodeAuthorization};
    let mut grants = Vec::new();
    let mut hashes = Vec::new();
    for hex_sum in session.allowlist.stores() {
        let code_hash = hex_decode(&hex_sum)?;
        hashes.push(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &code_hash,
        ));
        grants.push(CodeGrant {
            code_hash,
            instantiate_permission: None,
        });
    }
    let auth = StoreCodeAuthorization { grants };
    let value = encode_message(&auth)?;
    let (amino_auth, bytes) = wrap_grant(
        granter,
        grantee,
        StoreCodeAuthorization::type_url(),
        "wasm/StoreCodeAuthorization",
        &value,
        &format!("{{\"grants\":[{}]}}", store_grant_amino(&hashes)),
        expiration_text,
        expiration_unix,
    )?;
    Ok((amino_auth, bytes))
}

fn store_grant_amino(hashes_b64: &[String]) -> String {
    hashes_b64
        .iter()
        .map(|hash| format!("{{\"code_hash\":{}}}", json_string(hash)))
        .collect::<Vec<_>>()
        .join(",")
}

fn encode_contract_grant(
    granter: &str,
    grantee: &str,
    calls: &[crate::allowlist::ScopedCall],
    migrate: bool,
    expiration_text: &str,
    expiration_unix: u64,
) -> Result<(String, Vec<u8>), String> {
    use cosmos_sdk_proto::cosmwasm::wasm::v1::{
        AcceptedMessageKeysFilter, AllowAllMessagesFilter, ContractExecutionAuthorization,
        ContractGrant, ContractMigrationAuthorization, MaxCallsLimit,
    };
    let mut grants = Vec::new();
    let mut amino_grants = Vec::new();
    for call in calls {
        let (limit_url, limit_bytes, limit_amino) = if call.funds.is_empty() {
            let limit = MaxCallsLimit {
                remaining: call.calls,
            };
            (
                MaxCallsLimit::type_url(),
                encode_message(&limit)?,
                format!(
                    "{{\"type\":\"wasm/MaxCallsLimit\",\"value\":{{\"remaining\":{}}}}}",
                    json_string(&call.calls.to_string())
                ),
            )
        } else {
            use cosmos_sdk_proto::cosmwasm::wasm::v1::CombinedLimit;
            let amounts: Vec<_> = call
                .funds
                .iter()
                .map(|(denom, amount)| cosmos_sdk_proto::cosmos::base::v1beta1::Coin {
                    denom: denom.clone(),
                    amount: amount.to_string(),
                })
                .collect();
            let listed = call
                .funds
                .iter()
                .map(|(denom, amount)| {
                    format!(
                        "{{\"amount\":{},\"denom\":{}}}",
                        json_string(&amount.to_string()),
                        json_string(denom)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let limit = CombinedLimit {
                calls_remaining: call.calls,
                amounts,
            };
            (
                CombinedLimit::type_url(),
                encode_message(&limit)?,
                format!(
                    "{{\"type\":\"wasm/CombinedLimit\",\"value\":{{\"amounts\":[{listed}],\"calls_remaining\":{}}}}}",
                    json_string(&call.calls.to_string())
                ),
            )
        };
        // An empty key list is a deny, never AllowAllMessagesFilter: a scoped
        // call with no keys would otherwise grant every execute message.
        let (filter_url, filter_bytes, filter_amino) = if call.keys.is_empty() && !migrate {
            return Err(format!(
                "authz grant refused: contract {} has no message keys; an empty key list denies",
                call.address
            ));
        } else if call.keys.is_empty() {
            // Migrate grants are scoped by contract address; the filter only
            // sees migrate msg keys, so allow-all is kept for migrate only.
            (
                AllowAllMessagesFilter::type_url(),
                encode_message(&AllowAllMessagesFilter {})?,
                "{\"type\":\"wasm/AllowAllMessagesFilter\",\"value\":{}}".to_string(),
            )
        } else {
            let mut keys = call.keys.clone();
            keys.sort();
            keys.dedup();
            let filter = AcceptedMessageKeysFilter { keys: keys.clone() };
            let listed = keys
                .iter()
                .map(|key| json_string(key))
                .collect::<Vec<_>>()
                .join(",");
            (
                AcceptedMessageKeysFilter::type_url(),
                encode_message(&filter)?,
                format!(
                    "{{\"type\":\"wasm/AcceptedMessageKeysFilter\",\"value\":{{\"keys\":[{listed}]}}}}"
                ),
            )
        };
        grants.push(ContractGrant {
            contract: call.address.clone(),
            limit: Some(proto_any(&limit_url, limit_bytes)),
            filter: Some(proto_any(&filter_url, filter_bytes)),
        });
        amino_grants.push(format!(
            "{{\"contract\":{address},\"filter\":{filter_amino},\"limit\":{limit_amino}}}",
            address = json_string(&call.address),
        ));
    }
    let (type_url, amino_type, value) = if migrate {
        (
            ContractMigrationAuthorization::type_url(),
            "wasm/ContractMigrationAuthorization",
            encode_message(&ContractMigrationAuthorization { grants })?,
        )
    } else {
        (
            ContractExecutionAuthorization::type_url(),
            "wasm/ContractExecutionAuthorization",
            encode_message(&ContractExecutionAuthorization { grants })?,
        )
    };
    wrap_grant(
        granter,
        grantee,
        type_url,
        amino_type,
        &value,
        &format!("{{\"grants\":[{}]}}", amino_grants.join(",")),
        expiration_text,
        expiration_unix,
    )
}

fn wrap_grant(
    granter: &str,
    grantee: &str,
    proto_type: String,
    amino_type: &str,
    authorization: &[u8],
    amino_value: &str,
    expiration_text: &str,
    expiration_unix: u64,
) -> Result<(String, Vec<u8>), String> {
    let seconds = i64::try_from(expiration_unix)
        .map_err(|_| format!("grant expiration refused: {expiration_unix}"))?;
    let msg = MsgGrant {
        granter: granter.to_string(),
        grantee: grantee.to_string(),
        grant: Some(Grant {
            authorization: Some(cosmrs::Any {
                type_url: proto_type,
                value: authorization.to_vec(),
            }),
            expiration: Some(cosmrs::proto::tendermint::google::protobuf::Timestamp {
                seconds,
                nanos: 0,
            }),
        }),
    };
    let bytes = encode_message(&msg)?;
    let amino = format!(
        "{{\"type\":\"cosmos-sdk/MsgGrant\",\"value\":{{\"grant\":{{\"authorization\":{{\"type\":{amino_type},\"value\":{amino_value}}},\"expiration\":{expiration}}},\"grantee\":{grantee},\"granter\":{granter}}}}}",
        amino_type = json_string(amino_type),
        expiration = json_string(expiration_text),
        grantee = json_string(grantee),
        granter = json_string(granter),
    );
    Ok((amino, bytes))
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("grant refused: checksum {text} is not hex"));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("grant refused: checksum is not hex".into()),
    }
}

fn encode_grant(
    granter: &str,
    grantee: &str,
    type_url: &str,
    expiration_text: &str,
    expiration_unix: u64,
) -> Result<(String, Vec<u8>), String> {
    let seconds = i64::try_from(expiration_unix)
        .map_err(|_| format!("grant expiration refused: {expiration_unix}"))?;
    let mut value = Vec::new();
    GenericAuthorization {
        msg: type_url.to_string(),
    }
    .encode(&mut value)
    .map_err(|err| format!("grant authorization encode refused: {err}"))?;
    let msg = MsgGrant {
        granter: granter.to_string(),
        grantee: grantee.to_string(),
        grant: Some(Grant {
            authorization: Some(cosmrs::Any {
                type_url: GenericAuthorization::type_url(),
                value,
            }),
            expiration: Some(cosmrs::proto::tendermint::google::protobuf::Timestamp {
                seconds,
                nanos: 0,
            }),
        }),
    };
    let mut bytes = Vec::new();
    msg.encode(&mut bytes)
        .map_err(|err| format!("grant encode refused: {err}"))?;
    let amino = format!(
        "{{\"type\":\"cosmos-sdk/MsgGrant\",\"value\":{{\"grant\":{{\"authorization\":{{\"type\":\"cosmos-sdk/GenericAuthorization\",\"value\":{{\"msg\":{type_url}}}}},\"expiration\":{expiration}}},\"grantee\":{grantee},\"granter\":{granter}}}}}",
        type_url = json_string(type_url),
        expiration = json_string(expiration_text),
        grantee = json_string(grantee),
        granter = json_string(granter),
    );
    Ok((amino, bytes))
}

fn encode_allowance(
    granter: &str,
    grantee: &str,
    denom: &str,
    amount: u128,
    expiration_text: &str,
    expiration_unix: u64,
) -> Result<(String, Vec<u8>), String> {
    let seconds = i64::try_from(expiration_unix)
        .map_err(|_| format!("grant expiration refused: {expiration_unix}"))?;
    let allowance = BasicAllowance {
        spend_limit: vec![Coin {
            denom: denom
                .parse()
                .map_err(|err| format!("grant denom refused: {err}"))?,
            amount,
        }
        .into()],
        expiration: Some(cosmrs::proto::tendermint::google::protobuf::Timestamp {
            seconds,
            nanos: 0,
        }),
    };
    let mut allowance_bytes = Vec::new();
    allowance
        .encode(&mut allowance_bytes)
        .map_err(|err| format!("feegrant allowance encode refused: {err}"))?;
    let msg = MsgGrantAllowance {
        granter: granter.to_string(),
        grantee: grantee.to_string(),
        allowance: Some(cosmrs::Any {
            type_url: BasicAllowance::type_url(),
            value: allowance_bytes,
        }),
    };
    let mut bytes = Vec::new();
    msg.encode(&mut bytes)
        .map_err(|err| format!("feegrant encode refused: {err}"))?;
    let amino = format!(
        "{{\"type\":\"cosmos-sdk/MsgGrantAllowance\",\"value\":{{\"allowance\":{{\"type\":\"cosmos-sdk/BasicAllowance\",\"value\":{{\"expiration\":{expiration},\"spend_limit\":[{{\"amount\":{amount},\"denom\":{denom}}}]}}}},\"grantee\":{grantee},\"granter\":{granter}}}}}",
        expiration = json_string(expiration_text),
        amount = json_string(&amount.to_string()),
        denom = json_string(denom),
        grantee = json_string(grantee),
        granter = json_string(granter),
    );
    Ok((amino, bytes))
}

fn amino_sign_doc(chain: &SetupChain, msgs: &str, sequence: u64) -> Vec<u8> {
    let json = format!(
        "{{\"account_number\":{account},\"chain_id\":{chain_id},\"fee\":{{\"amount\":[{{\"amount\":{fee_amount},\"denom\":{fee_denom}}}],\"gas\":{gas}}},\"memo\":\"cw-orch-session:v1\",\"msgs\":[{msgs}],\"sequence\":{sequence}}}",
        account = json_string(&chain.account_number.to_string()),
        chain_id = json_string(&chain.chain_id),
        fee_amount = json_string(&chain.fee_amount.to_string()),
        fee_denom = json_string(&chain.fee_denom),
        gas = json_string(&chain.gas.to_string()),
        sequence = json_string(&sequence.to_string()),
    );
    json.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .into_bytes()
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::{MSG_EXECUTE, MSG_INSTANTIATE};
    use crate::session::{ApprovalFactor, Clock, ScriptSession};
    use cosmrs::proto::traits::Message;
    use prost::Name;

    struct FixedClock;
    impl Clock for FixedClock {
        fn unix_secs(&self) -> u64 {
            5_000
        }
    }

    #[test]
    fn grants_name_the_grantee_the_type_urls_and_the_expiration() {
        let allow = crate::allowlist::RunAllowlist::default()
            .allow_type(MSG_INSTANTIATE)
            .allow_store(b"\0asm-session")
            .unwrap();
        let session =
            ScriptSession::open(allow, ApprovalFactor::Zafu, 90, &FixedClock, "run-g").unwrap();
        let built = build_session_grants("terp1granter", session.grant(), "uterp", 25).unwrap();
        assert_eq!(built.authz.len(), 2);
        let mut urls = Vec::new();
        for bytes in &built.authz {
            let msg = MsgGrant::decode(bytes.as_slice()).unwrap();
            assert_eq!(msg.granter, "terp1granter");
            assert_eq!(msg.grantee, session.grantee());
            let inner = msg.grant.unwrap();
            assert_eq!(inner.expiration.unwrap().seconds, 5_090);
            let any = inner.authorization.unwrap();
            urls.push(any.type_url);
        }
        urls.sort();
        assert!(urls.iter().any(|url| url.contains("StoreCodeAuthorization")));
        assert!(urls.iter().any(|url| url == &GenericAuthorization::type_url()));

        let fee = MsgGrantAllowance::decode(built.feegrant.as_slice()).unwrap();
        assert_eq!(fee.grantee, session.grantee());
        assert_eq!(fee.granter, "terp1granter");
        let any = fee.allowance.unwrap();
        let allowance = BasicAllowance::decode(any.value.as_slice()).unwrap();
        assert_eq!(allowance.expiration.unwrap().seconds, 5_090);
        assert_eq!(allowance.spend_limit[0].denom, "uterp");
        assert_eq!(allowance.spend_limit[0].amount, "25");
    }

    fn chain() -> SetupChain {
        SetupChain {
            chain_id: "120u-1".into(),
            account_number: 7,
            sequence: 3,
            gas: 200_000,
            fee_denom: "uterp".into(),
            fee_amount: 5_000,
        }
    }

    fn session() -> ScriptSession {
        let allow = crate::allowlist::RunAllowlist::default()
            .allow_type(MSG_INSTANTIATE)
            .allow_type("/cosmos.bank.v1beta1.MsgSend");
        ScriptSession::open(allow, ApprovalFactor::Zafu, 90, &FixedClock, "run-g").unwrap()
    }

    fn covered(session: &ScriptSession) -> GranteeState {
        GranteeState {
            grantee: session.grantee().into(),
            authz: vec![
                LiveAuthz::generic("/cosmos.bank.v1beta1.MsgSend", Some(5_090)),
                LiveAuthz::generic(MSG_INSTANTIATE, Some(5_090)),
            ],
            feegrant: Some(LiveFeegrant {
                expiration_unix: Some(5_090),
                denom: "uterp".into(),
                limit: Some(25),
            }),
        }
    }

    fn sign(setup: SessionSetup) -> SetupTx {
        match setup {
            SessionSetup::Sign(tx) => tx,
            SessionSetup::Ready => panic!("expected a signature"),
        }
    }

    #[test]
    fn an_empty_chain_bootstraps_grants_in_one_amino_document() {
        let session = session();
        let state = GranteeState {
            grantee: session.grantee().into(),
            authz: Vec::new(),
            feegrant: None,
        };
        let tx = sign(
            plan_session_setup("a<b", session.grant(), &state, "uterp", 25, &chain()).unwrap(),
        );
        let text = std::str::from_utf8(&tx.amino).unwrap();
        assert!(text.contains("a\\u003cb"));
        assert!(!text.contains("a<b"));
        assert!(text.contains("\"account_number\":\"7\""));
        assert!(text.contains("\"sequence\":\"3\""));
        assert!(text.contains("\"chain_id\":\"120u-1\""));
        assert!(text.contains("\"memo\":\"cw-orch-session:v1\""));
        assert!(!text.contains("cw-orch-approval"));
        assert!(text.find("\"account_number\"").unwrap() < text.find("\"chain_id\"").unwrap());
        assert!(text.contains("1970-01-01T01:24:50Z"));
        let doc: serde_json::Value = serde_json::from_slice(&tx.amino).unwrap();
        let msgs = doc["msgs"].as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0]["type"], "cosmos-sdk/MsgGrantAllowance");
        assert_eq!(msgs[1]["type"], "cosmos-sdk/MsgGrant");
        assert_eq!(msgs[2]["type"], "cosmos-sdk/MsgGrant");
        assert_eq!(
            msgs[1]["value"]["grant"]["authorization"]["value"]["msg"],
            "/cosmos.bank.v1beta1.MsgSend"
        );
        assert_eq!(
            msgs[2]["value"]["grant"]["authorization"]["value"]["msg"],
            MSG_INSTANTIATE
        );
        assert_eq!(msgs[0]["value"]["allowance"]["value"]["spend_limit"][0]["amount"], "25");
        assert_eq!(tx.proto.len(), 3);
        let first = MsgGrant::decode(tx.proto[1].as_slice()).unwrap();
        assert_eq!(first.grantee, session.grantee());
        assert_eq!(first.granter, "a<b");
        let auth = GenericAuthorization::decode(
            first.grant.unwrap().authorization.unwrap().value.as_slice(),
        )
        .unwrap();
        assert_eq!(auth.msg, "/cosmos.bank.v1beta1.MsgSend");
        let fee = MsgGrantAllowance::decode(tx.proto[0].as_slice()).unwrap();
        let allowance = BasicAllowance::decode(fee.allowance.unwrap().value.as_slice()).unwrap();
        assert_eq!(allowance.expiration.unwrap().seconds, 5_090);
        assert_eq!(allowance.spend_limit[0].amount, "25");
    }

    #[test]
    fn a_covering_grant_does_not_ask_the_cold_key() {
        let session = session();
        let state = covered(&session);
        let setup = plan_session_setup("terp1granter", session.grant(), &state, "uterp", 25, &chain())
            .unwrap();
        assert_eq!(setup, SessionSetup::Ready);

        // A longer, still-expiring grant is reused as is.
        let mut longer = state.clone();
        longer.authz[0].expiration_unix = Some(9_999);
        longer.feegrant.as_mut().unwrap().limit = Some(1_000);
        let setup =
            plan_session_setup("terp1granter", session.grant(), &longer, "uterp", 25, &chain())
                .unwrap();
        assert_eq!(setup, SessionSetup::Ready);
    }

    #[test]
    fn a_non_expiring_or_unlimited_grant_is_revoked_then_replaced() {
        let session = session();
        let mut state = covered(&session);
        state.authz[0].expiration_unix = None;
        let tx = sign(
            plan_session_setup("terp1granter", session.grant(), &state, "uterp", 25, &chain())
                .unwrap(),
        );
        assert_eq!(tx.proto.len(), 2);
        let revoke = MsgRevoke::decode(tx.proto[0].as_slice()).unwrap();
        assert_eq!(revoke.msg_type_url, "/cosmos.bank.v1beta1.MsgSend");
        let grant = MsgGrant::decode(tx.proto[1].as_slice()).unwrap();
        assert!(grant.grant.unwrap().expiration.is_some());

        let mut state = covered(&session);
        state.feegrant.as_mut().unwrap().limit = None;
        let tx = sign(
            plan_session_setup("terp1granter", session.grant(), &state, "uterp", 25, &chain())
                .unwrap(),
        );
        assert_eq!(tx.proto.len(), 2);
        MsgRevokeAllowance::decode(tx.proto[0].as_slice()).unwrap();
        MsgGrantAllowance::decode(tx.proto[1].as_slice()).unwrap();

        let mut state = covered(&session);
        state.feegrant.as_mut().unwrap().expiration_unix = None;
        let tx = sign(
            plan_session_setup("terp1granter", session.grant(), &state, "uterp", 25, &chain())
                .unwrap(),
        );
        assert_eq!(tx.proto.len(), 2);
        MsgRevokeAllowance::decode(tx.proto[0].as_slice()).unwrap();
    }

    #[test]
    fn an_expired_grant_is_revoked_then_replaced_and_no_duplicate_allowance() {
        let session = session();
        let mut state = covered(&session);
        // Expired before this session even starts.
        for grant in &mut state.authz {
            grant.expiration_unix = Some(10);
        }
        state.feegrant.as_mut().unwrap().expiration_unix = Some(10);
        let tx = sign(
            plan_session_setup("terp1granter", session.grant(), &state, "uterp", 25, &chain())
                .unwrap(),
        );
        // 2 revokes + 1 revoke allowance + 2 grants + 1 allowance; the revoke
        // allowance precedes the grant allowance so the chain never sees a
        // second allowance ("fee allowance already exists").
        assert_eq!(tx.proto.len(), 6);
        MsgRevoke::decode(tx.proto[0].as_slice()).unwrap();
        MsgRevoke::decode(tx.proto[1].as_slice()).unwrap();
        MsgRevokeAllowance::decode(tx.proto[2].as_slice()).unwrap();
        MsgGrantAllowance::decode(tx.proto[3].as_slice()).unwrap();
        let text = String::from_utf8(tx.amino.clone()).unwrap();
        assert!(text.find("MsgRevokeAllowance").unwrap() < text.find("MsgGrantAllowance").unwrap());
    }

    #[test]
    fn a_grant_for_another_session_is_revoked_then_replaced() {
        let session = session();
        let mut state = covered(&session);
        state.authz[1].expiration_unix = Some(5_089);
        state.authz.push(LiveAuthz::generic("/extra.Msg", None));
        let tx = sign(
            plan_session_setup("terp1granter", session.grant(), &state, "uterp", 25, &chain())
                .unwrap(),
        );
        assert_eq!(tx.proto.len(), 3);
        let first = MsgRevoke::decode(tx.proto[0].as_slice()).unwrap();
        let second = MsgRevoke::decode(tx.proto[1].as_slice()).unwrap();
        assert_eq!(first.msg_type_url, MSG_INSTANTIATE);
        assert_eq!(second.msg_type_url, "/extra.Msg");
        let grant = MsgGrant::decode(tx.proto[2].as_slice()).unwrap();
        let auth = GenericAuthorization::decode(
            grant.grant.unwrap().authorization.unwrap().value.as_slice(),
        )
        .unwrap();
        assert_eq!(auth.msg, MSG_INSTANTIATE);
        let text = std::str::from_utf8(&tx.amino).unwrap();
        assert!(text.find("MsgRevoke").unwrap() < text.find("MsgGrant\"").unwrap());
        assert!(!text.contains("MsgGrantAllowance"));
        assert!(!text.contains("MsgRevokeAllowance"));
    }

    #[test]
    fn a_short_feegrant_is_replaced_and_a_missing_one_is_added() {
        let session = session();
        let mut state = covered(&session);
        state.feegrant.as_mut().unwrap().limit = Some(10);
        let tx = sign(
            plan_session_setup("terp1granter", session.grant(), &state, "uterp", 25, &chain())
                .unwrap(),
        );
        assert_eq!(tx.proto.len(), 2);
        MsgRevokeAllowance::decode(tx.proto[0].as_slice()).unwrap();
        let fee = MsgGrantAllowance::decode(tx.proto[1].as_slice()).unwrap();
        assert_eq!(fee.grantee, session.grantee());

        state.feegrant = None;
        let tx = sign(
            plan_session_setup("terp1granter", session.grant(), &state, "uterp", 25, &chain())
                .unwrap(),
        );
        assert_eq!(tx.proto.len(), 1);
        MsgGrantAllowance::decode(tx.proto[0].as_slice()).unwrap();

        state.feegrant = Some(LiveFeegrant {
            expiration_unix: Some(5_090),
            denom: "uthiol".into(),
            limit: Some(25),
        });
        let tx = sign(
            plan_session_setup("terp1granter", session.grant(), &state, "uterp", 25, &chain())
                .unwrap(),
        );
        assert_eq!(tx.proto.len(), 2);
        MsgRevokeAllowance::decode(tx.proto[0].as_slice()).unwrap();
    }

    #[test]
    fn a_retained_session_leaves_an_extra_grant_in_place() {
        let session = session();
        let mut state = covered(&session);
        state.authz.push(LiveAuthz::generic("/cosmos.gov.v1.MsgVote", Some(9_000)));
        let ready = plan_session_setup_with(
            "terp1granter",
            session.grant(),
            &state,
            "uterp",
            25,
            &chain(),
            false,
        )
        .unwrap();
        assert_eq!(ready, SessionSetup::Ready);
        let SessionSetup::Sign(tx) = plan_session_setup(
            "terp1granter",
            session.grant(),
            &state,
            "uterp",
            25,
            &chain(),
        )
        .unwrap() else {
            panic!("pruning an extra grant signs a revoke");
        };
        let text = String::from_utf8(tx.amino).unwrap();
        assert!(text.contains("/cosmos.gov.v1.MsgVote"));
    }

    #[test]
    fn revoke_exec_revokes_the_revoke_authority_last() {
        let anys = revoke_exec_anys(
            "terp1granter",
            "terp1grantee",
            &[
                REVOKE_AUTHZ.to_string(),
                "/cosmwasm.wasm.v1.MsgStoreCode".to_string(),
                REVOKE_ALLOWANCE.to_string(),
            ],
        )
        .unwrap();
        assert_eq!(anys.len(), 4);
        assert_eq!(anys[0].type_url, REVOKE_AUTHZ);
        assert_eq!(anys[1].type_url, REVOKE_ALLOWANCE);
        assert_eq!(anys[2].type_url, REVOKE_AUTHZ);
        assert_eq!(anys[3].type_url, REVOKE_AUTHZ);
        let first = MsgRevoke::decode(anys[0].value.as_slice()).unwrap();
        let self_revoke = MsgRevoke::decode(anys[3].value.as_slice()).unwrap();
        assert_eq!(first.msg_type_url, "/cosmwasm.wasm.v1.MsgStoreCode");
        assert_eq!(self_revoke.msg_type_url, REVOKE_AUTHZ);
    }

    #[test]
    fn a_store_only_plan_pins_the_checksum_and_skips_execute() {
        let wasm = b"\0asm-only";
        let allow = crate::allowlist::RunAllowlist::default()
            .allow_store(wasm)
            .unwrap();
        let session =
            ScriptSession::open(allow, ApprovalFactor::Zafu, 90, &FixedClock, "store").unwrap();
        let built = build_session_grants("terp1granter", session.grant(), "uterp", 25).unwrap();
        assert_eq!(built.authz.len(), 1);
        let msg = MsgGrant::decode(built.authz[0].as_slice()).unwrap();
        let any = msg.grant.unwrap().authorization.unwrap();
        assert!(any.type_url.ends_with("StoreCodeAuthorization"));
        let auth = cosmos_sdk_proto::cosmwasm::wasm::v1::StoreCodeAuthorization::decode(
            any.value.as_slice(),
        )
        .unwrap();
        let expect = crate::allowlist::wasm_checksum(wasm).unwrap();
        assert_eq!(auth.grants[0].code_hash, expect);
        let text = String::from_utf8(
            sign(plan_session_setup(
                "terp1granter",
                session.grant(),
                &GranteeState {
                    grantee: session.grantee().into(),
                    authz: vec![],
                    feegrant: None,
                },
                "uterp",
                planned_spend_limit(1),
                &chain(),
            ).unwrap())
            .amino,
        )
        .unwrap();
        assert!(!text.contains("MsgExecuteContract"));
        assert!(!text.contains("MsgInstantiateContract"));
        assert!(!text.contains("MsgMigrateContract"));
        assert!(text.contains(&base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &expect,
        )));
    }

    #[test]
    fn a_setup_plan_puts_instantiate2_and_the_predicted_execute_in_one_grant() {
        use crate::allowlist::{instantiate2_bech32, wasm_checksum, ScopedCall, MSG_INSTANTIATE2};
        let wasm = b"\0asm-setup";
        let creator = [7u8; 20];
        let salt = b"app-setup/bounty-escrow";
        let predicted = instantiate2_bech32("terp", &wasm_checksum(wasm).unwrap(), &creator, salt)
            .unwrap();
        let allow = crate::allowlist::RunAllowlist::default()
            .allow_store(wasm)
            .unwrap()
            .allow_type(MSG_INSTANTIATE2)
            .allow_execute(ScopedCall {
                address: predicted.clone(),
                keys: vec!["update_config".into()],
                calls: 1,
                funds: vec![],
            })
            .unwrap();
        let session =
            ScriptSession::open(allow, ApprovalFactor::Zafu, 90, &FixedClock, "setup").unwrap();
        let built = build_session_grants("terp1granter", session.grant(), "uterp", 25).unwrap();
        let urls: Vec<_> = built
            .authz
            .iter()
            .map(|bytes| {
                MsgGrant::decode(bytes.as_slice())
                    .unwrap()
                    .grant
                    .unwrap()
                    .authorization
                    .unwrap()
                    .type_url
            })
            .collect();
        assert!(urls.iter().any(|url| url.ends_with("StoreCodeAuthorization")));
        assert!(urls.iter().any(|url| url.ends_with("GenericAuthorization")));
        assert!(urls.iter().any(|url| url.ends_with("ContractExecutionAuthorization")));
        let text = String::from_utf8(
            sign(plan_session_setup(
                "terp1granter",
                session.grant(),
                &GranteeState {
                    grantee: session.grantee().into(),
                    authz: vec![],
                    feegrant: None,
                },
                "uterp",
                planned_spend_limit(3),
                &chain(),
            ).unwrap())
            .amino,
        )
        .unwrap();
        assert!(text.contains("MsgInstantiateContract2"));
        assert!(text.contains(&predicted));
        assert!(!text.contains("MsgInstantiateContract\""));
    }

    #[test]
    fn execute_without_an_address_is_refused() {
        let err = crate::allowlist::RunAllowlist::default()
            .allow_execute(crate::allowlist::ScopedCall {
                address: String::new(),
                keys: vec!["mint".into()],
                calls: 1,
                funds: vec![],
            })
            .unwrap_err();
        assert!(err.contains("address"));
    }

    #[test]
    fn an_execute_grant_names_one_address_and_one_key() {
        let allow = crate::allowlist::RunAllowlist::default()
            .allow_execute(crate::allowlist::ScopedCall {
                address: "terp1contract".into(),
                keys: vec!["mint".into()],
                calls: 2,
                funds: vec![],
            })
            .unwrap();
        let session =
            ScriptSession::open(allow, ApprovalFactor::Zafu, 90, &FixedClock, "exec").unwrap();
        let built = build_session_grants("terp1granter", session.grant(), "uterp", 4).unwrap();
        let msg = MsgGrant::decode(built.authz[0].as_slice()).unwrap();
        let any = msg.grant.unwrap().authorization.unwrap();
        let auth = cosmos_sdk_proto::cosmwasm::wasm::v1::ContractExecutionAuthorization::decode(
            any.value.as_slice(),
        )
        .unwrap();
        assert_eq!(auth.grants.len(), 1);
        assert_eq!(auth.grants[0].contract, "terp1contract");
        let filter = cosmos_sdk_proto::cosmwasm::wasm::v1::AcceptedMessageKeysFilter::decode(
            auth.grants[0].filter.as_ref().unwrap().value.as_slice(),
        )
        .unwrap();
        assert_eq!(filter.keys, vec!["mint".to_string()]);
    }

    #[test]
    fn a_generic_execute_grant_is_not_coverage() {
        let allow = crate::allowlist::RunAllowlist::default()
            .allow_execute(crate::allowlist::ScopedCall {
                address: "terp1contract".into(),
                keys: vec!["mint".into()],
                calls: 1,
                funds: vec![],
            })
            .unwrap();
        let session =
            ScriptSession::open(allow, ApprovalFactor::Zafu, 90, &FixedClock, "exec").unwrap();
        let state = GranteeState {
            grantee: session.grantee().into(),
            authz: vec![LiveAuthz::generic(MSG_EXECUTE, Some(5_090))],
            feegrant: Some(LiveFeegrant {
                expiration_unix: Some(5_090),
                denom: "uterp".into(),
                limit: Some(25),
            }),
        };
        let tx = sign(
            plan_session_setup("terp1granter", session.grant(), &state, "uterp", 25, &chain())
                .unwrap(),
        );
        let text = String::from_utf8(tx.amino).unwrap();
        assert!(text.contains("MsgRevoke"));
        assert!(text.contains("ContractExecutionAuthorization"));
    }

    #[test]
    fn the_wallet_catalog_is_not_a_session_grant() {
        let session = crate::approval::ApprovalSession::wallet("terp1cold");
        assert!(session.type_urls.is_empty());
        assert!(session.stores.is_empty());
        assert!(session.executes.is_empty());
    }

    #[test]
    fn the_fee_limit_is_the_planned_transaction_count() {
        assert_eq!(planned_spend_limit(4), 20_000_000);
    }

    #[test]
    fn a_different_ephemeral_wallet_is_refused() {
        let session = session();
        let mut state = covered(&session);
        state.grantee = "terp1other".into();
        let err = plan_session_setup("terp1granter", session.grant(), &state, "uterp", 25, &chain())
            .unwrap_err();
        assert_eq!(err, "ephemeral wallet mismatch");
        assert!(plan_session_setup("", session.grant(), &covered(&session), "uterp", 25, &chain())
            .unwrap_err()
            .contains("empty granter"));
    }

    #[test]
    fn a_wallet_catalog_packs_into_zigner_codes() {
        use crate::capabilities::WALLET_TYPE_URLS;
        use crate::session::{ApprovalFactor, SessionGrant};

        let mut allow = crate::allowlist::RunAllowlist::default();
        let skipped = [
            "/cosmos.authz.v1beta1.MsgGrant",
            "/cosmos.authz.v1beta1.MsgExec",
            "/cosmos.feegrant.v1beta1.MsgGrantAllowance",
            "/cosmwasm.wasm.v1.MsgStoreCode",
            "/cosmwasm.wasm.v1.MsgExecuteContract",
            "/cosmwasm.wasm.v1.MsgMigrateContract",
        ];
        let mut granted = 0usize;
        for url in WALLET_TYPE_URLS {
            if skipped.contains(url) {
                continue;
            }
            allow = allow.allow_type((*url).to_string());
            granted += 1;
        }
        let grant = SessionGrant {
            grantee: "terp1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4wf6ea".into(),
            expiration_unix: 1_900_000_000,
            session_id: "wallet".into(),
            allowlist: allow,
            factor: ApprovalFactor::Zafu,
            nonce: [0u8; 32],
        };
        let setup = SetupChain {
            chain_id: "morocco-1".into(),
            account_number: 3,
            sequence: 4,
            gas: 1_500_000,
            fee_denom: "uthiol".into(),
            fee_amount: 75_000,
        };
        let empty = GranteeState {
            grantee: grant.grantee.clone(),
            authz: vec![],
            feegrant: None,
        };
        let tx = sign(
            plan_session_setup("terp1granter", &grant, &empty, "uthiol", 100_000_000, &setup)
                .unwrap(),
        );
        assert_eq!(tx.pieces.len(), granted + 1);
        let batches = pack_qr_batches(&setup, &tx, 0, "terp").unwrap();
        assert!(batches.len() > 1);
        let mut seen = 0;
        for (index, (batch_chain, batch)) in batches.iter().enumerate() {
            assert_eq!(batch_chain.sequence, setup.sequence + index as u64);
            assert_eq!(batch_chain.gas, 200_000 * batch.pieces.len() as u64);
            assert!(crate::terminal::zigner_request_fits(
                0,
                "terp",
                &batch.amino
            ));
            seen += batch.pieces.len();
            let text = std::str::from_utf8(&batch.amino).unwrap();
            assert!(text.contains(&format!("\"sequence\":\"{}\"", batch_chain.sequence)));
            assert!(text.contains(&format!("\"gas\":\"{}\"", batch_chain.gas)));
            assert!(text.contains(&format!(
                "\"amount\":\"{}\"",
                batch_chain.fee_amount
            )));
        }
        assert_eq!(seen, tx.pieces.len());
        assert!(batches[0].1.pieces.iter().any(|piece| piece.contains("MsgGrantAllowance")));
        assert_eq!(
            batches
                .iter()
                .flat_map(|(_, batch)| batch.pieces.iter())
                .filter(|piece| piece.contains("\"type\":\"cosmos-sdk/MsgGrantAllowance\""))
                .count(),
            1
        );
    }

    #[test]
    fn the_fee_allowance_shares_the_authz_scan_at_default_gas() {
        use crate::session::{ApprovalFactor, SessionGrant};
        // Three authz grants + the allowance = 4 messages. With the default
        // 600k session gas the old packer split at 3 msgs, so the allowance
        // needed its own Zigner scan.
        let allow = crate::allowlist::RunAllowlist::default()
            .allow_type("/cosmos.bank.v1beta1.MsgSend".to_string())
            .allow_type("/cosmos.staking.v1beta1.MsgDelegate".to_string())
            .allow_type("/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward".to_string());
        let grant = SessionGrant {
            grantee: "terp1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4wf6ea".into(),
            expiration_unix: 1_900_000_000,
            session_id: "s".into(),
            allowlist: allow,
            factor: ApprovalFactor::Zafu,
            nonce: [0u8; 32],
        };
        let setup = SetupChain {
            chain_id: "morocco-1".into(),
            account_number: 3,
            sequence: 4,
            gas: 600_000,
            fee_denom: "uthiol".into(),
            fee_amount: 30_000,
        };
        let empty = GranteeState { grantee: grant.grantee.clone(), authz: vec![], feegrant: None };
        let tx = sign(plan_session_setup("terp1granter", &grant, &empty, "uthiol", 100, &setup).unwrap());
        assert_eq!(tx.pieces.len(), 4);
        assert!(tx.pieces[0].contains("cosmos-sdk/MsgGrantAllowance"));
        let batches = pack_qr_batches(&setup, &tx, 0, "terp").unwrap();
        assert_eq!(batches.len(), 1, "one scan carries authz + feegrant");
        let (chain, batch) = &batches[0];
        assert_eq!(batch.pieces.len(), 4);
        assert_eq!(chain.gas, 800_000);
        // Same gas price as the session: 30_000 / 600_000 per gas unit.
        assert_eq!(chain.fee_amount, 40_000);
        assert_eq!(chain.sequence, 4);

        // Skip-existing: once those grants are live, nothing is signed.
        let live = GranteeState {
            grantee: grant.grantee.clone(),
            authz: grant
                .allowlist_type_urls()
                .into_iter()
                .map(|url| LiveAuthz::generic(url, Some(1_900_000_000)))
                .collect(),
            feegrant: Some(LiveFeegrant {
                denom: "uthiol".into(),
                limit: Some(100),
                expiration_unix: Some(1_900_000_000),
            }),
        };
        assert_eq!(
            plan_session_setup("terp1granter", &grant, &live, "uthiol", 100, &setup).unwrap(),
            SessionSetup::Ready
        );
        // Only a missing allowance: one message, still one scan.
        let mut no_fee = live.clone();
        no_fee.feegrant = None;
        let tx = sign(plan_session_setup("terp1granter", &grant, &no_fee, "uthiol", 100, &setup).unwrap());
        assert_eq!(tx.pieces.len(), 1);
        assert!(tx.pieces[0].contains("cosmos-sdk/MsgGrantAllowance"));
    }
}
