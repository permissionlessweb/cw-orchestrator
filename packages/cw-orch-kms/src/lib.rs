//! cw-orch sender for a terp-frost smart account.
//!
//! The quorum signs `SIGN_MODE_DIRECT` bytes. The chain selects the contract
//! through `TxExtension.selected_authenticators`.

mod allowlist;
mod chain;
mod direct;
mod ephemeral;
mod policy;
mod approval;
mod capabilities;
mod grant;
mod spawn_plan;
#[cfg(feature = "ict")]
mod spawn;
mod sender;
mod session;
mod terminal;
pub mod port;
pub mod progress;
mod ui_shared;
mod tx_extension;
mod wire;
#[cfg(test)]
mod zigner_e2e;
#[cfg(test)]
mod feegrant_e2e;

pub use ephemeral::ensure_ephemeral_mnemonic;
pub use port::{page_addr, PORT_ENV, PORT_RANGE};
pub use chain::{approval_chain, clear_approval_chain, set_approval_chain, validate_address, ChainProfile, DEFAULT_COIN_TYPE};
pub use policy::*;
pub use approval::{
    enable_approval, enable_relay_sessions, enable_session, grant_to, query_grantee_state, ApprovalSession, AuthzSession,
    DaemonApproval,
};
#[cfg(feature = "ict")]
pub use spawn::SpawnedTerp;
pub use spawn_plan::{
    resolve_image_version, CW_ORCH_GRANTER_ENV, DEFAULT_TERP_IMAGE, SPAWN_CHAIN_ID, SPAWN_FUND,
};
pub use capabilities::{relay_grants, wallet_type_urls, RELAY_TYPE_URLS, WALLET_TYPE_URLS};
pub use allowlist::{
    Authorization, AuthorizationError, Authorizer, Principal, RunAllowlist, ScopedCall,
    SignDocDigest, SigningRequest, instantiate2_bech32, wasm_checksum, MSG_EXECUTE,
    MSG_INSTANTIATE, MSG_INSTANTIATE2, MSG_STORE_CODE,
};
pub use grant::{
    build_session_grants, plan_session_setup, planned_spend_limit, GranteeState, LiveAuthz,
    LiveFeegrant, SessionGrants, SessionSetup, SetupChain, SetupTx, FEE_PER_TX,
};
pub use sender::{FrostKmsOptions, FrostKmsSender};
pub use session::{ApprovalFactor, Clock, FrostSession, ScriptSession, SessionGrant};
pub use terminal::zigner_qr_hex;
pub use ui_shared::{raptor_frames, zigner_frames, ZIGNER_FRAME_BYTES};
pub use terminal::{
    approval_chain_id, capture_granter, capture_granter_for_chain_sync, capture_granter_sync, listen,
    set_approval_chain_id, ApprovalView, Approver, Terminal,
    TerminalOutcome, TestApprover,
};
pub use tx_extension::add_authenticator_any;
pub use wire::{encode_group_vk, verify_group_signature, FROST_SIG_LEN};
pub use direct::{canonical_json, exec_contract_as, AminoMsg};
pub use grant::{GrantScope, LiveContract};
pub use terminal::listen_sign_doc;
