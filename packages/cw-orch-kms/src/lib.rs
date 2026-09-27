//! cw-orch sender for a terp-frost smart account.
//!
//! The quorum signs `SIGN_MODE_DIRECT` bytes. The chain selects the contract
//! through `TxExtension.selected_authenticators`.

mod sender;
mod session;
mod tx_extension;
mod wire;

pub use sender::{FrostKmsOptions, FrostKmsSender};
pub use session::FrostSession;
pub use tx_extension::add_authenticator_any;
pub use wire::{encode_group_vk, verify_group_signature, FROST_SIG_LEN};
