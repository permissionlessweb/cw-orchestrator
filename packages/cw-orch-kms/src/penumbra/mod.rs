//! Zigner custody for Penumbra (`penumbra` feature).
//!
//! Penumbra has no authz: every spend in a [`TransactionPlan`] is authorized
//! by a spend-auth signature over the transaction's effect hash, made with the
//! spend key randomized by that spend's randomizer. This crate drives that
//! signature through Zigner (air-gapped phone) with the same page, frames and
//! scanner cw-orch-kms uses for Cosmos sign docs:
//!
//! 1. [`policy::Policy::check`] — refuse plans that are not ICS20-out / LP
//!    open/close/withdraw (plus their spends/outputs) or that send value to
//!    unpinned destinations.
//! 2. [`qr::ZignerRequest`] — the `53 03 10` request Zigner scans.
//! 3. [`summary::summarize`] — the human-readable plan shown next to the QR.
//! 4. [`auth::verify_response`] — Zigner's response, checked against the
//!    effect hash we computed with the *pinned* FVK, giving
//!    [`AuthorizationData`].
//! 5. [`page`] — the run's page, built on the shared [`crate::ui_shared`]
//!    layout, frames and zxing scanner; [`custody::ZignerCustody`] —
//!    `penumbra.custody.v1.CustodyService` wrapping all of the above.
//! 6. [`session`] — FVK import/pinning and the wiped-on-exit pcli view home.

pub mod auth;
pub mod custody;
pub mod page;
pub mod policy;
pub mod qr;
pub mod session;
pub mod summary;

pub use penumbra_sdk_transaction::{AuthorizationData, TransactionPlan};

use anyhow::{bail, Result};
use penumbra_sdk_keys::FullViewingKey;
use std::str::FromStr;

/// The account Zigner signs with: it always derives the spend key from its
/// first seed, account 0. Pinning the FVK (and wallet id) means a phone holding
/// a different seed produces signatures that fail verification here.
#[derive(Clone, Debug)]
pub struct PinnedAccount {
    pub fvk: FullViewingKey,
}

impl PinnedAccount {
    /// `fvk` is the bech32m `penumbrafullviewingkey1…` string (public data, but
    /// it reveals all balances — treat as confidential). Optionally require
    /// that a given address belongs to it.
    pub fn new(fvk: &str, expect_address: Option<&str>) -> Result<Self> {
        let fvk = FullViewingKey::from_str(fvk.trim())?;
        if let Some(addr) = expect_address {
            let addr = penumbra_sdk_keys::Address::from_str(addr.trim())?;
            if fvk.address_index(&addr).is_none() {
                bail!("pinned address does not belong to the pinned full viewing key");
            }
        }
        Ok(Self { fvk })
    }

    pub fn wallet_id(&self) -> String {
        self.fvk.wallet_id().to_string()
    }
}
