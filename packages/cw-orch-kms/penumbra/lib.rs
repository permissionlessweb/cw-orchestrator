//! Build root for cw-orch-kms's Penumbra custody. The code is cw-orch-kms's:
//! `../src/penumbra/` (the module) and `../src/ui_shared.rs` (the page layout,
//! scanner, zxing, QR frames and tokens the Cosmos pages use). This root only
//! exists because Penumbra v2.1 needs crates.io prost 0.13 / tendermint 0.40,
//! which the cw-orchestrator workspace [patch]es to prost-0.14 forks.

#[path = "../src/ui_shared.rs"]
#[allow(dead_code)]
pub(crate) mod ui_shared;

#[path = "../src/penumbra/mod.rs"]
pub mod penumbra;

pub use ui_shared::{raptor_frames, zigner_frames, ZIGNER_FRAME_BYTES};
