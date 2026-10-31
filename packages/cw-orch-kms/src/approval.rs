//! Turn a daemon script into an authz and feegrant session.
//!
//! The daemon wallet is the grantee. It already has an account, so
//! `upload_if_needed` can broadcast. The cold key is the granter. This
//! function opens the loopback approval page for the one setup transaction,
//! broadcasts that signature, then sets the daemon's authz granter and fee
//! granter. Later messages in the same process are `MsgExec` paid by the
//! feegrant.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use cosmrs::proto::cosmos::auth::v1beta1::BaseAccount;
use cosmrs::proto::cosmos::authz::v1beta1::{
    GenericAuthorization, Grant, QueryGrantsRequest, QueryGrantsResponse,
};
use cosmrs::proto::cosmos::feegrant::v1beta1::{BasicAllowance, QueryAllowanceRequest};
use cosmrs::proto::traits::Message;
use cosmrs::tx::{Body, Fee, ModeInfo, Raw, SignMode, SignerInfo};
use cosmrs::Coin;
use cosmwasm_std::Addr;
use cw_orch_daemon::senders::tx::TxSender;
use cw_orch_daemon::{Daemon, DaemonBuilder};
use prost::Name;
use tonic::transport::Channel;

use crate::allowlist::{
    RunAllowlist, ScopedCall, SigningRequest, MSG_INSTANTIATE, MSG_STORE_CODE,
};
use crate::grant::{
    pack_qr_batches, plan_session_setup, plan_session_setup_with, revoke_exec_anys, GranteeState,
    LiveAuthz, LiveFeegrant, SetupChain, SetupTx, REVOKE_ALLOWANCE, REVOKE_AUTHZ,
};
use crate::session::{ApprovalFactor, Clock, SessionGrant};
use crate::terminal::{listen_bundles, listen_sign_doc, PageBundle, Terminal, TerminalOutcome};

struct SystemClock;

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }
}

/// What `enable_approval` asks the cold key to allow.
pub struct ApprovalSession {
    /// Cold bech32 address that signs the grant.
    pub granter: String,
    /// How long the authz and feegrant remain valid.
    pub ttl_secs: u64,
    /// Message types the grantee may send. Store, execute, and migrate are
    /// not enough on their own: those need `stores`, `executes`, or `migrates`.
    pub type_urls: Vec<String>,
    /// Hex checksums of the Wasm this session may store.
    pub stores: Vec<String>,
    /// Contract executions this session may perform.
    pub executes: Vec<ScopedCall>,
    /// Contract migrations this session may perform.
    pub migrates: Vec<ScopedCall>,
    /// Fee allowance, in the chain's gas denom. The cold key pays this later.
    pub allowance_limit: u128,
    /// Gas limit on the grant transaction itself.
    pub gas: u64,
    /// Loopback page. `127.0.0.1:8741` is the usual page.
    pub bind: SocketAddr,
    /// Zigner account index for the Terp key. Absent on the QR means 0.
    pub account_index: u32,
    /// Leave the authz and feegrant in place after the script. The default
    /// grants the ephemeral key the right to revoke them, then that key
    /// broadcasts the revoke. No second cold signature.
    pub retain: bool,
    /// Grant `MsgExec` (nested authz). See [`ApprovalSession::allow_nested_exec`].
    pub nested_exec: bool,
    /// This grant is held by an operator wallet, not burned at the end of one run.
    pub operator_grant: bool,
}

impl ApprovalSession {
    /// A session with no grants yet. Add only the messages this run sends.
    pub fn open(granter: impl Into<String>) -> Self {
        Self::new(granter, Vec::new(), 600_000)
    }

    /// Store these Wasm bytes and no other code. The checksum is what the
    /// chain computes after gunzip.
    pub fn allow_store(mut self, wasm: &[u8]) -> Result<Self, String> {
        let allow = RunAllowlist::default().allow_store(wasm)?;
        for sum in allow.stores() {
            if !self.stores.contains(&sum) {
                self.stores.push(sum);
            }
        }
        self.push_type(MSG_STORE_CODE);
        Ok(self)
    }

    /// Let the session key send `MsgExec` as the granter, so it can relay a
    /// grant the granter itself holds from another wallet:
    /// `MsgExec(session key){MsgExec(granter){MsgExecuteContract(owner)}}`.
    /// This is a GenericAuthorization on `MsgExec`: for the session's TTL the
    /// session key can use every grant the granter holds. Keep the TTL short;
    /// the default close revokes it. `allow_sdk` still refuses `MsgExec`.
    pub fn allow_nested_exec(mut self) -> Self {
        self.nested_exec = true;
        self.push_type(crate::allowlist::MSG_AUTHZ_EXEC);
        self
    }

    /// Instantiate is type-wide. The chain has no code-id authorization.
    pub fn allow_instantiate(mut self) -> Self {
        self.push_type(MSG_INSTANTIATE);
        self
    }

    /// `MsgInstantiateContract2` is also type-wide.
    pub fn allow_instantiate2(mut self) -> Self {
        self.push_type(crate::allowlist::MSG_INSTANTIATE2);
        self
    }

    /// Client open, handshake, and packet lifecycle. The same grant belongs
    /// on every chain the relayer signs.
    pub fn allow_relay(mut self) -> Result<Self, String> {
        for url in crate::capabilities::RELAY_TYPE_URLS {
            self = self.allow_sdk(*url)?;
        }
        Ok(self)
    }

    /// Execute one existing contract. An empty address is refused.
    pub fn allow_execute(mut self, call: ScopedCall) -> Result<Self, String> {
        if call.address.is_empty() {
            return Err("grant refused: execute needs a contract address".into());
        }
        self.executes.push(call);
        self.push_type(crate::allowlist::MSG_EXECUTE);
        Ok(self)
    }

    /// Migrate one existing contract.
    pub fn allow_migrate(mut self, call: ScopedCall) -> Result<Self, String> {
        if call.address.is_empty() {
            return Err("grant refused: migrate needs a contract address".into());
        }
        self.migrates.push(call);
        self.push_type(crate::allowlist::MSG_MIGRATE);
        Ok(self)
    }

    /// One sdk message type. Store, execute, and migrate stay on their
    /// scoped methods. `MsgGrant`, `MsgExec`, and `MsgGrantAllowance` are refused.
    pub fn allow_sdk(mut self, type_url: impl Into<String>) -> Result<Self, String> {
        let type_url = type_url.into();
        const FORBIDDEN: &[&str] = &[
            "/cosmos.authz.v1beta1.MsgGrant",
            "/cosmos.authz.v1beta1.MsgExec",
            "/cosmos.feegrant.v1beta1.MsgGrantAllowance",
            MSG_STORE_CODE,
            crate::allowlist::MSG_EXECUTE,
            crate::allowlist::MSG_MIGRATE,
        ];
        if FORBIDDEN.contains(&type_url.as_str()) {
            return Err(format!("grant refused: {type_url} is not a generic session grant"));
        }
        self.push_type(&type_url);
        Ok(self)
    }

    /// The registered wallet catalog is not a session grant.
    pub fn wallet(granter: impl Into<String>) -> Self {
        Self::open(granter)
    }

    fn push_type(&mut self, type_url: &str) {
        if !self.type_urls.iter().any(|have| have == type_url) {
            self.type_urls.push(type_url.to_string());
        }
    }

    fn new(granter: impl Into<String>, type_urls: Vec<String>, gas: u64) -> Self {
        Self {
            granter: granter.into(),
            ttl_secs: 2 * 60 * 60,
            type_urls,
            stores: Vec::new(),
            executes: Vec::new(),
            migrates: Vec::new(),
            allowance_limit: 100_000_000,
            gas,
            bind: "127.0.0.1:8741".parse().expect("loopback port"),
            account_index: 0,
            retain: false,
            nested_exec: false,
            operator_grant: false,
        }
    }
}

/// Default approval on a daemon builder. cw-orch-daemon does not depend on
/// this crate, so the method lives here.
pub trait DaemonApproval {
    /// Wallet grant for `CW_ORCH_GRANTER`.
    fn approve(self) -> Result<Daemon, String>;

    /// Wallet grant signed by `granter`.
    fn approve_granter(self, granter: impl Into<String>) -> Result<Daemon, String>;
}

impl DaemonApproval for &DaemonBuilder {
    fn approve(self) -> Result<Daemon, String> {
        let granter = std::env::var(crate::CW_ORCH_GRANTER_ENV).map_err(|_| {
            "session refused: set CW_ORCH_GRANTER or call approve_granter".to_string()
        })?;
        self.approve_granter(granter)
    }

    fn approve_granter(self, granter: impl Into<String>) -> Result<Daemon, String> {
        enable_approval(self, ApprovalSession::open(granter))
    }
}

/// A daemon whose broadcasts are `MsgExec` under the cold key's grant.
/// [`AuthzSession::close`] revokes that grant with the ephemeral key unless
/// [`ApprovalSession::retain`] was set.
pub struct AuthzSession {
    pub daemon: Daemon,
    retain: bool,
    granter: String,
    grantee: String,
    type_urls: Vec<String>,
    page: Option<Terminal>,
    /// Set once the revoke was broadcast (or the grant was retained). Drop
    /// revokes when this is still false, so an early `?` or a panic between
    /// `enable_session` and `close` does not leave the grant behind.
    closed: bool,
}

impl AuthzSession {
    /// One line on the approval page log, flushed onto the open socket.
    pub fn note(&self, line: &str) {
        let Some(page) = &self.page else {
            return;
        };
        page.note(line);
        let _ = self.daemon.rt_handle.block_on(async {
            tokio::task::yield_now().await;
        });
    }

    pub fn granter(&self) -> &str {
        &self.granter
    }

    pub fn grantee(&self) -> &str {
        &self.grantee
    }

    /// Keep the page up after [`Self::close`] so a later line can still land.
    pub fn detach_page(&mut self) -> Option<Terminal> {
        self.page.take()
    }

    /// Revoke the session grant. The ephemeral key signs this. A retained
    /// session leaves the grant in place.
    pub fn close(mut self) -> Result<(), String> {
        let result = self.revoke_now();
        // Close was called: Drop must not retry, even after an error. The
        // grant's expiration is the backstop when the revoke failed.
        self.closed = true;
        result
    }

    fn revoke_now(&mut self) -> Result<(), String> {
        if self.retain {
            if let Some(page) = &self.page {
                page.note("ok session grant retained");
            }
            println!("session grant retained");
            return Ok(());
        }
        let msgs = revoke_exec_anys(&self.granter, &self.grantee, &self.type_urls)?;
        let handle = self.daemon.rt_handle.clone();
        let sender = self.daemon.sender();
        let mut attempt = 0;
        let commit = loop {
            attempt += 1;
            let c = handle.block_on(sender.commit_tx_any(msgs.clone(), Some("cw-orch session revoke")));
            match &c {
                Err(e) if is_height_race(&e.to_string()) && attempt < HEIGHT_RACE_TRIES => {
                    // Rejected at CheckTx, so nothing is in the mempool; the rebuilt tx reuses the sequence.
                    println!("session revoke: invalid-height race (sdk code 26), retry {attempt}/{}", HEIGHT_RACE_TRIES - 1);
                    std::thread::sleep(HEIGHT_RACE_BACKOFF);
                }
                _ => break c,
            }
        };
        if let Err(err) = commit {
            if let Some(page) = &self.page {
                page.note(&format!("err session revoke refused: {err}"));
            }
            return Err(format!("session revoke refused: {err}"));
        }
        if let Some(page) = &self.page {
            page.note("ok session revoke broadcast");
            let _ = handle.block_on(async {
                tokio::task::yield_now().await;
            });
        }
        println!("session revoke broadcast");
        Ok(())
    }

    /// What the chain still stores for this granter and session key.
    pub fn remaining_grants(&self) -> Result<GranteeState, String> {
        let channel = self.daemon.sender().channel();
        let (granter, grantee) = (self.granter.clone(), self.grantee.clone());
        run_off_runtime(&self.daemon.rt_handle, async move {
            grantee_state(channel, &granter, &grantee).await
        })
    }
}

impl Drop for AuthzSession {
    fn drop(&mut self) {
        if self.closed || self.retain {
            return;
        }
        self.closed = true;
        let why = if std::thread::panicking() { "panic" } else { "early return" };
        eprintln!("session dropped without close ({why}): revoking the session grant");
        let handle = self.daemon.rt_handle.clone();
        let msgs = match revoke_exec_anys(&self.granter, &self.grantee, &self.type_urls) {
            Ok(msgs) => msgs,
            Err(err) => {
                eprintln!("session revoke on drop refused: {err}; the grant expires on its own");
                return;
            }
        };
        let daemon = self.daemon.clone();
        let result = run_off_runtime(&handle, async move {
            daemon
                .sender()
                .commit_tx_any(msgs, Some("cw-orch session revoke (drop)"))
                .await
                .map(|_| ())
                .map_err(|err| err.to_string())
        });
        match result {
            Ok(()) => eprintln!("session revoke broadcast (drop)"),
            Err(err) => eprintln!("session revoke on drop refused: {err}; the grant expires on its own"),
        }
    }
}

/// `block_on` panics on a runtime worker thread, so run on a scoped thread
/// when this is called from inside the runtime (Drop can be).
fn run_off_runtime<T: Send>(
    handle: &tokio::runtime::Handle,
    fut: impl std::future::Future<Output = Result<T, String>> + Send,
) -> Result<T, String> {
    if tokio::runtime::Handle::try_current().is_err() {
        return handle.block_on(fut);
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| handle.block_on(fut))
            .join()
            .unwrap_or_else(|_| Err("revoke thread panicked".into()))
    })
}

/// Query what the chain stores for `granter` -> `grantee` (authz grants and
/// the fee allowance). Used to assert a flow left nothing behind.
pub fn query_grantee_state(daemon: &Daemon, granter: &str, grantee: &str) -> Result<GranteeState, String> {
    let channel = daemon.sender().channel();
    let (granter, grantee) = (granter.to_string(), grantee.to_string());
    run_off_runtime(&daemon.rt_handle, async move { grantee_state(channel, &granter, &grantee).await })
}

/// One cold signature for the whole session. That signature grants the script
/// messages and, unless [`ApprovalSession::retain`] is set, the right for the
/// ephemeral key to revoke the grant. [`AuthzSession::close`] broadcasts that
/// revoke after the script work. A retained session that is already covered
/// does not open the page.
/// Open the relay grant on every chain before any client or packet send.
/// Each chain gets its own page, then the page is released so the next chain
/// can use the same port. A later failure closes the grants already opened.
pub fn enable_relay_sessions(
    granter: &str,
    chains: Vec<(&str, DaemonBuilder)>,
    account_index: u32,
    ttl_secs: u64,
) -> Result<Vec<AuthzSession>, String> {
    if granter.is_empty() {
        return Err("relay grant refused: empty granter".into());
    }
    if chains.is_empty() {
        return Err("relay grant refused: no chains".into());
    }
    let mut opened = Vec::new();
    for (chain_id, builder) in chains {
        let mut session = ApprovalSession::open(granter).allow_relay()?;
        session.account_index = account_index;
        session.ttl_secs = ttl_secs;
        session.allowance_limit =
            crate::planned_spend_limit(crate::capabilities::RELAY_TYPE_URLS.len() as u64 + 1);
        let actions = vec![SigningRequest::new("session-key").body(format!("relay on {chain_id}"))];
        match enable_session(&builder, session, actions) {
            Ok(mut run) => {
                drop(run.detach_page());
                opened.push(run);
            }
            Err(err) => {
                for run in opened {
                    let _ = run.close();
                }
                return Err(format!("relay grant on {chain_id} refused: {err}"));
            }
        }
    }
    Ok(opened)
}

fn prepare_builder(builder: &DaemonBuilder) -> Result<(), String> {
    if builder.has_mnemonic() {
        return Ok(());
    }
    crate::ensure_ephemeral_mnemonic(builder.chain_kind())
}

pub fn enable_session(
    builder: &DaemonBuilder,
    mut session: ApprovalSession,
    automatic: Vec<SigningRequest>,
) -> Result<AuthzSession, String> {
    if session.granter.is_empty() {
        return Err("session refused: empty granter".into());
    }
    crate::policy::validate_ttl(session.ttl_secs).map_err(|e| format!("session refused: {e}"))?;
    if session.type_urls.is_empty() {
        return Err("session refused: no message types".into());
    }
    if !session.retain {
        for url in [REVOKE_AUTHZ, REVOKE_ALLOWANCE] {
            if !session.type_urls.iter().any(|have| have == url) {
                session.type_urls.push(url.to_string());
            }
        }
    }
    prepare_builder(builder)?;
    let daemon = builder
        .build()
        .map_err(|err| format!("session refused: {err}"))?;
    let grantee = daemon.sender().address().into_string();
    if grantee == session.granter {
        return Err("session refused: granter and grantee are the same key".into());
    }
    let handle = daemon.rt_handle.clone();
    handle.block_on(open_authz_session(daemon, session, grantee, automatic))
}

/// Grant **another wallet** (`grantee`, e.g. an operator's own cold key) the
/// session scope, signed by the cold key on the loopback page. The grant is
/// retained: the grantee later relays it from its own short session
/// ([`ApprovalSession::allow_nested_exec`]) and the granter revokes it with a
/// revoke session.
/// The daemon key only broadcasts the cold-signed grant.
pub fn grant_to(
    builder: &DaemonBuilder,
    session: ApprovalSession,
    grantee: &str,
    automatic: Vec<SigningRequest>,
) -> Result<(), String> {
    if session.granter.is_empty() {
        return Err("grant refused: empty granter".into());
    }
    if session.operator_grant {
        crate::policy::validate_operator_grant_ttl(session.ttl_secs)
            .map_err(|e| format!("grant refused: {e}"))?;
    } else {
        crate::policy::validate_ttl(session.ttl_secs).map_err(|e| format!("grant refused: {e}"))?;
    }
    if session.type_urls.is_empty() {
        return Err("grant refused: no message types".into());
    }
    if !session.retain {
        return Err("grant refused: a grant to another wallet must be retained".into());
    }
    crate::policy::validate_chain_address(grantee).map_err(|e| format!("grant refused: {e}"))?;
    if grantee == session.granter {
        return Err("grant refused: granter and grantee are the same key".into());
    }
    prepare_builder(builder)?;
    let daemon = builder.build().map_err(|err| format!("grant refused: {err}"))?;
    let handle = daemon.rt_handle.clone();
    let run = handle.block_on(open_authz_session(daemon, session, grantee.to_string(), automatic))?;
    run.close()
}

/// Build `builder`'s daemon, approve the session grant on the loopback page
/// when the chain does not already cover it, and return the daemon ready to
/// broadcast under that grant.
pub fn enable_approval(builder: &DaemonBuilder, session: ApprovalSession) -> Result<Daemon, String> {
    if session.granter.is_empty() {
        return Err("session refused: empty granter".into());
    }
    crate::policy::validate_ttl(session.ttl_secs).map_err(|e| format!("session refused: {e}"))?;
    if session.type_urls.is_empty() {
        return Err("session refused: no type urls".into());
    }
    prepare_builder(builder)?;
    let mut daemon = builder
        .build()
        .map_err(|err| format!("daemon refused: {err}"))?;
    let grantee = daemon.sender().address().into_string();
    if grantee == session.granter {
        return Err("session refused: granter and grantee are the same key".into());
    }
    let handle = daemon.rt_handle.clone();
    handle
        .block_on(open_session(&mut daemon, &session, &grantee))
        .map_err(|err| format!("session refused: {err}"))?;
    Ok(daemon)
}

/// Use the daemon's prefix and gas settings for the pages. A known preset keeps
/// its Zigner chain_name; otherwise the prefix is the closest guess.
pub(crate) fn select_chain(daemon: &Daemon, chain_id: &str) -> Result<(), String> {
    let info = &daemon.sender().chain_info;
    let prefix = info.network_info.pub_address_prefix.to_string();
    let base = crate::chain::ChainProfile::for_prefix(&prefix).unwrap_or_else(|| {
        crate::chain::ChainProfile::new(chain_id, prefix.clone(), info.gas_denom.clone(), info.gas_price, prefix.clone(), prefix.clone())
    });
    let mut profile = base.on_chain_id(chain_id);
    profile.fee_denom = info.gas_denom.clone();
    profile.gas_price = info.gas_price;
    profile.coin_type = info.network_info.coin_type;
    crate::chain::set_approval_chain(profile)
}

async fn open_session(
    daemon: &mut Daemon,
    session: &ApprovalSession,
    grantee: &str,
) -> Result<(), String> {
    let chain_id = daemon.sender().chain_info.chain_id.clone();
    let reported = node_chain_id(daemon.sender().channel()).await?;
    crate::policy::ensure_chain_id(&chain_id, &reported).map_err(|e| format!("session refused: {e}"))?;
    select_chain(daemon, &chain_id)?;
    let fee_denom = daemon.sender().chain_info.gas_denom.clone();
    let gas_price = daemon.sender().chain_info.gas_price;
    if !gas_price.is_finite() || gas_price < 0.0 {
        return Err("session refused: gas price is not set".into());
    }
    let fee_amount = (gas_price * session.gas as f64).ceil() as u128;
    let account = granter_account(daemon.sender().channel(), &session.granter).await?;
    let on_chain = grantee_state(daemon.sender().channel(), &session.granter, grantee).await?;
    let allow = allowlist_from_session(session);
    let grant = SessionGrant {
        grantee: grantee.to_string(),
        expiration_unix: SystemClock.unix_secs().saturating_add(session.ttl_secs),
        session_id: format!("wallet-{grantee}"),
        allowlist: allow,
        factor: ApprovalFactor::Zafu,
        nonce: [0u8; 32],
    };
    let setup = SetupChain {
        chain_id,
        account_number: account.account_number,
        sequence: account.sequence,
        gas: session.gas,
        fee_denom: fee_denom.clone(),
        fee_amount,
    };
    match plan_session_setup(
        &session.granter,
        &grant,
        &on_chain,
        &fee_denom,
        session.allowance_limit,
        &setup,
    )? {
        crate::grant::SessionSetup::Ready => {
            arm(daemon, &session.granter);
            Ok(())
        }
        crate::grant::SessionSetup::Sign(tx) => {
            let batches = crate::grant::pack_qr_batches(&setup, &tx, session.account_index, &crate::chain::approval_chain().zigner_chain_name)?;
            let total = batches.len();
            for (index, (batch_chain, batch)) in batches.into_iter().enumerate() {
                println!("approval page http://{} ({}/{})", session.bind, index + 1, total);
                let signed = approve_grant(session, &batch).await?;
                broadcast_grant(daemon, &session.granter, &signed, &batch, &batch_chain).await?;
            }
            arm(daemon, &session.granter);
            Ok(())
        }
    }
}

async fn open_authz_session(
    mut daemon: Daemon,
    session: ApprovalSession,
    grantee: String,
    automatic: Vec<SigningRequest>,
) -> Result<AuthzSession, String> {
    let chain_id = daemon.sender().chain_info.chain_id.clone();
    let reported = node_chain_id(daemon.sender().channel()).await?;
    crate::policy::ensure_chain_id(&chain_id, &reported).map_err(|e| format!("session refused: {e}"))?;
    select_chain(&daemon, &chain_id)?;
    let fee_denom = daemon.sender().chain_info.gas_denom.clone();
    let gas_price = daemon.sender().chain_info.gas_price;
    if !gas_price.is_finite() || gas_price < 0.0 {
        return Err("session refused: gas price is not set".into());
    }
    let fee_amount = (gas_price * session.gas as f64).ceil() as u128;
    let account = granter_account(daemon.sender().channel(), &session.granter).await?;
    let on_chain = grantee_state(daemon.sender().channel(), &session.granter, &grantee).await?;
    let allow = allowlist_from_session(&session);
    let grant = SessionGrant {
        grantee: grantee.clone(),
        expiration_unix: SystemClock.unix_secs().saturating_add(session.ttl_secs),
        session_id: format!("wallet-{grantee}"),
        allowlist: allow,
        factor: ApprovalFactor::Zafu,
        nonce: [0u8; 32],
    };
    let setup = SetupChain {
        chain_id,
        account_number: account.account_number,
        sequence: account.sequence,
        gas: session.gas,
        fee_denom,
        fee_amount,
    };
    let grant_batches = match plan_session_setup_with(
        &session.granter,
        &grant,
        &on_chain,
        &setup.fee_denom,
        session.allowance_limit,
        &setup,
        !session.retain,
    )? {
        crate::grant::SessionSetup::Ready => Vec::new(),
        crate::grant::SessionSetup::Sign(tx) => {
            pack_qr_batches(&setup, &tx, session.account_index, &crate::chain::approval_chain().zigner_chain_name)?
        }
    };
    if grant_batches.is_empty() {
        arm(&mut daemon, &session.granter);
        println!("session grant already covers this run");
        return Ok(finished(daemon, session, grantee, None));
    }
    let mut bundles = Vec::new();
    for (index, (_, batch)) in grant_batches.iter().enumerate() {
        bundles.push(PageBundle {
            title: format!("authorize {}/{}", index + 1, grant_batches.len()),
            sign_doc: batch.amino.clone(),
            messages: piece_requests(&batch.pieces),
        });
    }
    let mut shown = automatic;
    if shown.is_empty() {
        shown.push(SigningRequest::new("session-key").body(
            "the ephemeral key broadcasts the script after this authorization",
        ));
    }
    bundles.push(PageBundle {
        title: "session key".into(),
        sign_doc: Vec::new(),
        messages: shown,
    });
    println!(
        "approval page http://{} — one page, {} cold-key bundle{}",
        session.bind,
        grant_batches.len(),
        if grant_batches.len() == 1 { "" } else { "s" }
    );
    let grant_count = grant_batches.len();
    let (terminal, incoming, _revoked) = listen_bundles(
        session.bind,
        &session.granter,
        bundles,
        session.account_index,
        grant_count,
    )
    .await?;
    let signatures = incoming
        .await
        .map_err(|_| "session refused: the approval page closed".to_string())?;
    if signatures.len() != grant_count {
        return Err("session refused: missing authorization signature".into());
    }
    for (signed, (chain, tx)) in signatures.into_iter().zip(grant_batches) {
        if signed.signer != session.granter {
            return Err(format!("session refused: signer {}", signed.signer));
        }
        match broadcast_grant(
            &daemon,
            &session.granter,
            &SignedGrant {
                pubkey: signed.pubkey,
                signature: signed.signature,
            },
            &tx,
            &chain,
        )
        .await
        {
            Ok(hash) => {
                terminal.note(&format!("ok session grant {hash}"));
                tokio::task::yield_now().await;
            }
            Err(err) => {
                terminal.note(&format!("err {err}"));
                tokio::task::yield_now().await;
                return Err(err);
            }
        }
    }
    arm(&mut daemon, &session.granter);
    Ok(finished(daemon, session, grantee, Some(terminal)))
}

fn allowlist_from_session(session: &ApprovalSession) -> RunAllowlist {
    let mut allow = RunAllowlist::default();
    for url in &session.type_urls {
        allow = allow.allow_type(url.clone());
    }
    for sum in &session.stores {
        allow = allow.allow_store_checksum(sum.clone());
    }
    for call in &session.executes {
        allow = allow.allow_execute_unchecked(call.clone());
    }
    for call in &session.migrates {
        allow = allow.allow_migrate_unchecked(call.clone());
    }
    if session.nested_exec {
        allow = allow.allow_nested_exec();
    }
    allow
}

fn finished(
    daemon: Daemon,
    session: ApprovalSession,
    grantee: String,
    page: Option<Terminal>,
) -> AuthzSession {
    AuthzSession {
        daemon,
        retain: session.retain,
        granter: session.granter,
        grantee,
        type_urls: session.type_urls,
        page,
        closed: false,
    }
}

fn piece_requests(pieces: &[String]) -> Vec<SigningRequest> {
    pieces
        .iter()
        .cloned()
        .map(|piece| SigningRequest::new("cw-orch-session:v1").body(piece))
        .collect()
}

fn arm(daemon: &mut Daemon, granter: &str) {
    let granter = Addr::unchecked(granter);
    daemon.sender_mut().set_authz_granter(&granter);
    daemon.sender_mut().set_fee_granter(&granter);
}

struct SignedGrant {
    pubkey: Vec<u8>,
    signature: Vec<u8>,
}

async fn approve_grant(session: &ApprovalSession, tx: &SetupTx) -> Result<SignedGrant, String> {
    let messages = if tx.pieces.is_empty() {
        let text = String::from_utf8(tx.amino.clone())
            .map_err(|_| "session grant is not utf-8".to_string())?;
        vec![SigningRequest::new("cw-orch-session:v1").body(text)]
    } else {
        tx.pieces
            .iter()
            .cloned()
            .map(|piece| SigningRequest::new("cw-orch-session:v1").body(piece))
            .collect()
    };
    let mut terminal = listen_sign_doc(
        session.bind,
        &session.granter,
        tx.amino.clone(),
        messages,
        session.account_index,
    )
    .await?;
    match terminal.outcome().await? {
        TerminalOutcome::Signed {
            signer,
            pubkey,
            signature,
        } => {
            if signer != session.granter {
                return Err(format!("session refused: signer {signer}"));
            }
            if pubkey.len() != 33 || signature.len() != 64 {
                return Err("session refused: signature is not a cosmos secp256k1 signature".into());
            }
            Ok(SignedGrant { pubkey, signature })
        }
        TerminalOutcome::Approved { .. } => {
            Err("session refused: the page returned an off-chain approval".into())
        }
        TerminalOutcome::Refused => Err("session refused: the cold key declined the grant".into()),
    }
}

/// Bounded retry for CheckTx racing a commit (sdk code 26 "invalid height").
const HEIGHT_RACE_TRIES: u32 = 3;
const HEIGHT_RACE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(2500);

fn is_height_race(s: &str) -> bool {
    s.contains("invalid height") && s.contains("26")
}

async fn tx_on_chain(daemon: &Daemon, hash: &str) -> bool {
    let mut client = cosmrs::proto::cosmos::tx::v1beta1::service_client::ServiceClient::new(daemon.sender().channel());
    client.get_tx(cosmrs::proto::cosmos::tx::v1beta1::GetTxRequest { hash: hash.into() }).await.is_ok()
}

async fn broadcast_grant(
    daemon: &Daemon,
    granter: &str,
    signed: &SignedGrant,
    tx: &SetupTx,
    setup: &SetupChain,
) -> Result<String, String> {
    let raw = legacy_amino_raw(granter, signed, tx, setup)?;
    let bytes = raw.to_bytes().map_err(|e| format!("grant encode: {e}"))?;
    let hash = {
        use sha2::Digest;
        sha2::Sha256::digest(&bytes).iter().map(|b| format!("{b:02X}")).collect::<String>()
    };
    let mut attempt = 0;
    let response = loop {
        attempt += 1;
        let raw: cosmrs::proto::cosmos::tx::v1beta1::TxRaw = prost::Message::decode(bytes.as_slice()).map_err(|e| format!("grant decode: {e}"))?;
        let res = daemon.sender().broadcast_tx(raw.into()).await.map_err(|err| format!("{err}"));
        let race = match &res {
            Err(e) => is_height_race(e),
            Ok(r) => r.code != 0 && is_height_race(&r.raw_log),
        };
        if !race || attempt >= HEIGHT_RACE_TRIES {
            break res.map_err(|err| format!("grant broadcast refused: {err}"))?;
        }
        // CheckTx hit a commit boundary. The same signed bytes are retried only
        // after confirming they are not already on chain.
        tokio::time::sleep(HEIGHT_RACE_BACKOFF).await;
        if tx_on_chain(daemon, &hash).await {
            println!("session grant {hash} (already on chain after a height race)");
            break cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse { txhash: hash.clone(), ..Default::default() };
        }
        println!("grant broadcast: invalid-height race (sdk code 26), retry {attempt}/{}", HEIGHT_RACE_TRIES - 1);
    };
    if response.code != 0 {
        return Err(format!(
            "grant broadcast refused: code {} {}",
            response.code, response.raw_log
        ));
    }
    // Sync broadcast returns after CheckTx. The upload must wait until the
    // grant is in a block, or the feegrant lookup finds nothing.
    let sender = daemon.sender();
    let committed = cw_orch_daemon::http_broadcast::find_tx_with_fallback(
        sender.channel(),
        &response.txhash,
        &sender.rpc_urls(),
        sender.lcd_url().as_deref(),
    )
    .await
        .map_err(|err| format!("grant broadcast refused: {err}"))?;
    if committed.code != 0 {
        return Err(format!(
            "grant broadcast refused: code {} {}",
            committed.code, committed.raw_log
        ));
    }
    println!("session grant {}", committed.txhash);
    Ok(committed.txhash)
}

fn legacy_amino_raw(
    _granter: &str,
    signed: &SignedGrant,
    tx: &SetupTx,
    setup: &SetupChain,
) -> Result<Raw, String> {
    let msgs = sdk_anys(&tx.amino, &tx.proto)?;
    let body = Body::new(msgs, "cw-orch-session:v1", 0u32);
    let body_bytes = body
        .into_bytes()
        .map_err(|err| format!("grant body refused: {err}"))?;
    let verifying = k256::ecdsa::VerifyingKey::from_sec1_bytes(&signed.pubkey)
        .map_err(|err| format!("grant pubkey refused: {err}"))?;
    let public_key = cosmrs::crypto::PublicKey::from(verifying);
    let fee = Fee::from_amount_and_gas(
        Coin {
            denom: setup
                .fee_denom
                .parse()
                .map_err(|err| format!("grant denom refused: {err}"))?,
            amount: setup.fee_amount,
        },
        setup.gas,
    );
    let auth = SignerInfo {
        public_key: Some(public_key.into()),
        mode_info: ModeInfo::single(SignMode::LegacyAminoJson),
        sequence: setup.sequence,
    }
    .auth_info(fee);
    let auth_info_bytes = auth
        .into_bytes()
        .map_err(|err| format!("grant auth info refused: {err}"))?;
    Ok(Raw::from(cosmrs::proto::cosmos::tx::v1beta1::TxRaw {
        body_bytes,
        auth_info_bytes,
        signatures: vec![signed.signature.clone()],
    }))
}

fn sdk_anys(amino: &[u8], proto: &[Vec<u8>]) -> Result<Vec<cosmrs::Any>, String> {
    let text = std::str::from_utf8(amino).map_err(|_| "session grant is not utf-8".to_string())?;
    let types = amino_msg_types(text);
    if types.len() != proto.len() {
        return Err(format!(
            "session grant refused: {} amino messages and {} proto messages",
            types.len(),
            proto.len()
        ));
    }
    let mut anys = Vec::with_capacity(proto.len());
    for (sdk_type, bytes) in types.iter().zip(proto.iter()) {
        let type_url = match sdk_type.as_str() {
            "cosmos-sdk/MsgRevoke" => "/cosmos.authz.v1beta1.MsgRevoke",
            "cosmos-sdk/MsgGrant" => "/cosmos.authz.v1beta1.MsgGrant",
            "cosmos-sdk/MsgRevokeAllowance" => "/cosmos.feegrant.v1beta1.MsgRevokeAllowance",
            "cosmos-sdk/MsgGrantAllowance" => "/cosmos.feegrant.v1beta1.MsgGrantAllowance",
            other => return Err(format!("session grant refused: {other}")),
        };
        anys.push(cosmrs::Any {
            type_url: type_url.to_string(),
            value: bytes.clone(),
        });
    }
    Ok(anys)
}

fn amino_msg_types(amino: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = amino;
    while let Some(index) = rest.find("\"type\":\"cosmos-sdk/") {
        let start = index + "\"type\":\"".len();
        let tail = &rest[start..];
        let Some(end) = tail.find('"') else {
            break;
        };
        let name = &tail[..end];
        if matches!(
            name,
            "cosmos-sdk/MsgRevoke"
                | "cosmos-sdk/MsgGrant"
                | "cosmos-sdk/MsgRevokeAllowance"
                | "cosmos-sdk/MsgGrantAllowance"
        ) {
            out.push(name.to_string());
        }
        rest = &tail[end..];
    }
    out
}

pub(crate) async fn granter_account(channel: Channel, granter: &str) -> Result<BaseAccount, String> {
    let mut client =
        cosmrs::proto::cosmos::auth::v1beta1::query_client::QueryClient::new(channel);
    let response = client
        .account(cosmrs::proto::cosmos::auth::v1beta1::QueryAccountRequest {
            address: granter.to_string(),
        })
        .await
        .map_err(|err| format!("granter account refused: {err}"))?
        .into_inner();
    let any = response
        .account
        .ok_or_else(|| format!("granter account refused: {granter} has no account"))?;
    decode_signer_account(granter, &any)
}

/// Account number / sequence / pubkey of a signing account. Accepts
/// `BaseAccount` and the x/auth vesting accounts (their inner
/// `BaseVestingAccount.base_account`). Module and unknown types are refused.
pub(crate) fn decode_signer_account(granter: &str, any: &cosmrs::Any) -> Result<BaseAccount, String> {
    use cosmrs::proto::cosmos::vesting::v1beta1::{
        BaseVestingAccount, ContinuousVestingAccount, DelayedVestingAccount, PeriodicVestingAccount,
        PermanentLockedAccount,
    };
    let bytes = any.value.as_slice();
    let err = |e: prost::DecodeError| format!("granter account refused: {granter} ({}): {e}", any.type_url);
    let inner = |b: Option<BaseVestingAccount>| -> Result<BaseAccount, String> {
        b.and_then(|v| v.base_account)
            .ok_or_else(|| format!("granter account refused: {granter} is {} with no base account", any.type_url))
    };
    match any.type_url.as_str() {
        "/cosmos.auth.v1beta1.BaseAccount" => BaseAccount::decode(bytes).map_err(err),
        "/cosmos.vesting.v1beta1.DelayedVestingAccount" => {
            inner(DelayedVestingAccount::decode(bytes).map_err(err)?.base_vesting_account)
        }
        "/cosmos.vesting.v1beta1.ContinuousVestingAccount" => {
            inner(ContinuousVestingAccount::decode(bytes).map_err(err)?.base_vesting_account)
        }
        "/cosmos.vesting.v1beta1.PeriodicVestingAccount" => {
            inner(PeriodicVestingAccount::decode(bytes).map_err(err)?.base_vesting_account)
        }
        "/cosmos.vesting.v1beta1.PermanentLockedAccount" => {
            inner(PermanentLockedAccount::decode(bytes).map_err(err)?.base_vesting_account)
        }
        other => Err(format!(
            "granter account refused: {granter} is {other}; only BaseAccount and vesting accounts can sign a session"
        )),
    }
}

#[cfg(test)]
mod signer_account_tests {
    use super::*;
    use cosmrs::proto::cosmos::auth::v1beta1::ModuleAccount;
    use cosmrs::proto::cosmos::vesting::v1beta1::*;

    fn base() -> BaseAccount {
        BaseAccount {
            address: "terp1granter".into(),
            pub_key: Some(cosmrs::proto::Any { type_url: "/cosmos.crypto.secp256k1.PubKey".into(), value: vec![10, 33, 2, 7] }),
            account_number: 19,
            sequence: 241,
        }
    }
    fn bva() -> Option<BaseVestingAccount> {
        Some(BaseVestingAccount { base_account: Some(base()), end_time: 1, ..Default::default() })
    }
    fn any<M: prost::Message>(t: &str, m: &M) -> cosmrs::Any {
        cosmrs::Any { type_url: t.into(), value: m.encode_to_vec() }
    }
    fn check(a: cosmrs::Any) {
        let got = decode_signer_account("terp1granter", &a).unwrap();
        assert_eq!((got.account_number, got.sequence), (19, 241), "{}", a.type_url);
        assert_eq!(got.pub_key, base().pub_key, "{}", a.type_url);
    }

    #[test]
    fn base_and_vesting_accounts_decode() {
        check(any("/cosmos.auth.v1beta1.BaseAccount", &base()));
        check(any("/cosmos.vesting.v1beta1.DelayedVestingAccount", &DelayedVestingAccount { base_vesting_account: bva() }));
        check(any("/cosmos.vesting.v1beta1.ContinuousVestingAccount", &ContinuousVestingAccount { base_vesting_account: bva(), start_time: 0 }));
        check(any("/cosmos.vesting.v1beta1.PeriodicVestingAccount", &PeriodicVestingAccount { base_vesting_account: bva(), start_time: 0, vesting_periods: vec![] }));
        check(any("/cosmos.vesting.v1beta1.PermanentLockedAccount", &PermanentLockedAccount { base_vesting_account: bva() }));
    }

    #[test]
    fn module_unknown_and_empty_vesting_refused() {
        let m = ModuleAccount { base_account: Some(base()), name: "gov".into(), permissions: vec![] };
        let e = decode_signer_account("terp1granter", &any("/cosmos.auth.v1beta1.ModuleAccount", &m)).unwrap_err();
        assert!(e.contains("ModuleAccount"), "{e}");
        assert!(decode_signer_account("terp1granter", &cosmrs::Any { type_url: "/x.Unknown".into(), value: vec![] }).is_err());
        let empty = any("/cosmos.vesting.v1beta1.DelayedVestingAccount", &DelayedVestingAccount { base_vesting_account: None });
        assert!(decode_signer_account("terp1granter", &empty).unwrap_err().contains("no base account"));
    }
}

async fn grantee_state(
    channel: Channel,
    granter: &str,
    grantee: &str,
) -> Result<GranteeState, String> {
    let authz = query_grants(channel.clone(), granter, grantee).await?;
    let feegrant = query_allowance(channel, granter, grantee).await?;
    Ok(GranteeState {
        grantee: grantee.to_string(),
        authz,
        feegrant,
    })
}

async fn query_grants(
    channel: Channel,
    granter: &str,
    grantee: &str,
) -> Result<Vec<LiveAuthz>, String> {
    let mut client =
        cosmrs::proto::cosmos::authz::v1beta1::query_client::QueryClient::new(channel);
    let mut next_key = Vec::new();
    let mut live = Vec::new();
    loop {
        let response = client
            .grants(QueryGrantsRequest {
                granter: granter.to_string(),
                grantee: grantee.to_string(),
                msg_type_url: String::new(),
                pagination: Some(cosmrs::proto::cosmos::base::query::v1beta1::PageRequest {
                    key: next_key,
                    offset: 0,
                    limit: 100,
                    count_total: false,
                    reverse: false,
                }),
            })
            .await;
        let response = match response {
            Ok(response) => response.into_inner(),
            Err(status) if grant_is_absent(&status) => QueryGrantsResponse {
                grants: vec![],
                pagination: None,
            },
            Err(status) => return Err(format!("authz query refused: {status}")),
        };
        for grant in response.grants {
            if let Some(parsed) = grant_type_url(&grant)? {
                live.push(parsed);
            }
        }
        next_key = response
            .pagination
            .map(|page| page.next_key)
            .unwrap_or_default();
        if next_key.is_empty() {
            break;
        }
        if live.len() > 10_000 {
            return Err("authz query refused: too many grants".into());
        }
    }
    Ok(live)
}

fn grant_is_absent(status: &tonic::Status) -> bool {
    status.code() == tonic::Code::NotFound
        || status.message().contains("not found")
        || status.message().contains("NotFound")
}

fn grant_type_url(grant: &Grant) -> Result<Option<LiveAuthz>, String> {
    let Some(any) = &grant.authorization else {
        return Ok(None);
    };
    let expiration_unix = grant
        .expiration
        .map(|stamp| u64::try_from(stamp.seconds).unwrap_or(0));
    if any.type_url == GenericAuthorization::type_url() {
        let auth = GenericAuthorization::decode(any.value.as_slice())
            .map_err(|err| format!("authz grant refused: {err}"))?;
        return Ok(Some(LiveAuthz::generic(auth.msg, expiration_unix)));
    }
    if let Some(parsed) = crate::grant::parse_wasm_grant(&any.type_url, &any.value)? {
        return Ok(Some(LiveAuthz {
            expiration_unix,
            ..parsed
        }));
    }
    Ok(Some(LiveAuthz::generic(any.type_url.clone(), expiration_unix)))
}

async fn query_allowance(
    channel: Channel,
    granter: &str,
    grantee: &str,
) -> Result<Option<LiveFeegrant>, String> {
    let mut client =
        cosmrs::proto::cosmos::feegrant::v1beta1::query_client::QueryClient::new(channel);
    let response = client
        .allowance(QueryAllowanceRequest {
            granter: granter.to_string(),
            grantee: grantee.to_string(),
        })
        .await;
    let response = match response {
        Ok(response) => response.into_inner(),
        Err(status) if grant_is_absent(&status) => {
            return Ok(None);
        }
        Err(status) => return Err(format!("feegrant query refused: {status}")),
    };
    let Some(grant) = response.allowance else {
        return Ok(None);
    };
    let Some(any) = grant.allowance else {
        return Ok(None);
    };
    if any.type_url != BasicAllowance::type_url() {
        return Err(format!(
            "feegrant refused: {} is not a basic allowance",
            any.type_url
        ));
    }
    let allowance = BasicAllowance::decode(any.value.as_slice())
        .map_err(|err| format!("feegrant refused: {err}"))?;
    let coin = allowance.spend_limit.first();
    Ok(Some(LiveFeegrant {
        expiration_unix: allowance
            .expiration
            .as_ref()
            .map(|stamp| u64::try_from(stamp.seconds).unwrap_or(0)),
        denom: coin.map(|coin| coin.denom.clone()).unwrap_or_default(),
        limit: coin.and_then(|coin| coin.amount.parse().ok()),
    }))
}

#[cfg(test)]
mod height_race_tests {
    #[test]
    fn detects_only_code_26_invalid_height() {
        assert!(super::is_height_race("codespace sdk code 26: invalid height: context did not contain latest block height in either check state or finalize block state (24144875)"));
        assert!(!super::is_height_race("codespace sdk code 32: account sequence mismatch"));
        assert!(!super::is_height_race("authorization not found"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{plan_session_setup, SessionSetup};
    use crate::session::ApprovalFactor;

    #[test]
    fn a_store_code_grant_packs_one_legacy_message_per_proto_body() {
        let allow = RunAllowlist::default()
            .allow_store(b"\0asm-upload")
            .unwrap();
        let grant = SessionGrant {
            grantee: "terp1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4wf6ea".into(),
            expiration_unix: 5_090,
            session_id: "dao-upload".into(),
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
        let empty = GranteeState {
            grantee: grant.grantee.clone(),
            authz: vec![],
            feegrant: None,
        };
        let SessionSetup::Sign(tx) = plan_session_setup(
            "terp1granter",
            &grant,
            &empty,
            "uthiol",
            100,
            &setup,
        )
        .unwrap()
        else {
            panic!("an empty chain asks for a signature");
        };
        let anys = sdk_anys(&tx.amino, &tx.proto).unwrap();
        assert_eq!(anys.len(), 2);
        assert_eq!(anys[0].type_url, "/cosmos.authz.v1beta1.MsgGrant");
        assert_eq!(anys[1].type_url, "/cosmos.feegrant.v1beta1.MsgGrantAllowance");
        let types = amino_msg_types(std::str::from_utf8(&tx.amino).unwrap());
        assert!(!types.iter().any(|name| name.contains("thorchain")));
        let key = k256::ecdsa::SigningKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let raw = legacy_amino_raw(
            "terp1granter",
            &SignedGrant {
                pubkey,
                signature: vec![7u8; 64],
            },
            &tx,
            &setup,
        )
        .unwrap();
        let packed = raw.to_bytes().unwrap();
        let decoded = cosmrs::proto::cosmos::tx::v1beta1::TxRaw::decode(packed.as_slice()).unwrap();
        assert_eq!(decoded.signatures, vec![vec![7u8; 64]]);
        let body = cosmrs::proto::cosmos::tx::v1beta1::TxBody::decode(decoded.body_bytes.as_slice())
            .unwrap();
        assert_eq!(body.memo, "cw-orch-session:v1");
        assert_eq!(body.messages.len(), 2);
        let auth =
            cosmrs::proto::cosmos::tx::v1beta1::AuthInfo::decode(decoded.auth_info_bytes.as_slice())
                .unwrap();
        assert_eq!(
            auth.signer_infos[0].mode_info.as_ref().unwrap().sum,
            Some(cosmrs::proto::cosmos::tx::v1beta1::mode_info::Sum::Single(
                cosmrs::proto::cosmos::tx::v1beta1::mode_info::Single {
                    mode: SignMode::LegacyAminoJson.into(),
                }
            ))
        );
    }
}

/// Chain-id the node itself reports (tendermint GetNodeInfo), compared against config.
pub(crate) async fn node_chain_id(channel: tonic::transport::Channel) -> Result<String, String> {
    use cosmrs::proto::cosmos::base::tendermint::v1beta1::{service_client::ServiceClient, GetNodeInfoRequest};
    let mut client = ServiceClient::new(channel);
    let info = client
        .get_node_info(GetNodeInfoRequest {})
        .await
        .map_err(|e| format!("session refused: node info: {e}"))?
        .into_inner();
    info.default_node_info
        .map(|n| n.network)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| "session refused: node reports no chain-id".to_string())
}

#[cfg(test)]
mod nested_exec_tests {
    use super::*;

    #[test]
    fn nested_exec_is_opt_in_and_reaches_the_allowlist() {
        let plain = ApprovalSession::open("terp1x");
        assert!(!plain.nested_exec);
        assert!(!allowlist_from_session(&plain).nested_exec());
        assert!(ApprovalSession::open("terp1x").allow_sdk("/cosmos.authz.v1beta1.MsgExec").is_err());
        let s = ApprovalSession::open("terp1x").allow_nested_exec();
        assert!(s.type_urls.iter().any(|u| u == "/cosmos.authz.v1beta1.MsgExec"));
        let allow = allowlist_from_session(&s);
        assert!(allow.nested_exec());
        assert!(allow.type_urls().iter().any(|u| u == "/cosmos.authz.v1beta1.MsgExec"));
    }
}
