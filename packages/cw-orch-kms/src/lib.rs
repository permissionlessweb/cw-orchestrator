//! cw-orch sender for a terp-frost smart account.
//!
//! The quorum signs `SIGN_MODE_DIRECT` bytes. The chain selects the contract
//! through `TxExtension.selected_authenticators`.

mod allowlist;
mod grant;
mod sender;
mod session;
mod tx_extension;
mod wire;

pub use allowlist::{
    Authorization, AuthorizationError, Authorizer, Principal, RunAllowlist, SignDocDigest,
    SigningRequest, MSG_EXECUTE, MSG_INSTANTIATE, MSG_STORE_CODE,
};
pub use grant::{build_session_grants, SessionGrants};
pub use sender::{FrostKmsOptions, FrostKmsSender};
pub use session::{ApprovalFactor, Clock, FrostSession, ScriptSession, SessionGrant};
pub use tx_extension::add_authenticator_any;
pub use wire::{encode_group_vk, verify_group_signature, FROST_SIG_LEN};
