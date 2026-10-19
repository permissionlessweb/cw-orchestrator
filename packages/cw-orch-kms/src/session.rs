//! In-process FROST quorum, and the ephemeral secp256k1 key for a script run.
//!
//! The FROST signature bytes match `terp-frost` Authenticate. The script
//! session key is a single secp256k1 key. It is not a FROST share.

use cosmrs::crypto::secp256k1::SigningKey;
use osst::curve::{OsstPoint, OsstScalar};
use osst::frost::SigningPackage;
use osst::SecretShare;
use rand::rngs::OsRng;

use crate::allowlist::RunAllowlist;

use crate::wire::{encode_group_vk, verify_group_signature, Point, Scalar, FROST_SIG_LEN};

pub struct FrostSession {
    group_vk: String,
    group: Point,
    shares: Vec<SecretShare<Scalar>>,
    threshold: u16,
}

impl core::fmt::Debug for FrostSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrostSession")
            .field("group_vk", &self.group_vk)
            .field("threshold", &self.threshold)
            .field("share_count", &self.shares.len())
            .field("shares", &"[REDACTED]")
            .finish()
    }
}

impl Clone for FrostSession {
    fn clone(&self) -> Self {
        Self {
            group_vk: self.group_vk.clone(),
            group: self.group,
            shares: self.shares.clone(),
            threshold: self.threshold,
        }
    }
}

impl FrostSession {
    pub fn deal(threshold: u16, parties: u16) -> Result<Self, String> {
        if threshold == 0 || parties == 0 || threshold > parties {
            return Err(format!(
                "frost quorum refused: threshold {threshold} of {parties}"
            ));
        }
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let mut coefficients = Vec::new();
        for _ in 1..threshold {
            coefficients.push(Scalar::random(&mut rng));
        }
        let shares = (1..=parties)
            .map(|index| {
                let x = Scalar::from_u32(index as u32);
                let mut y = secret.clone();
                let mut power = x.clone();
                for coefficient in &coefficients {
                    y = y.add(&coefficient.mul(&power));
                    power = power.mul(&x);
                }
                SecretShare::new(index as u32, y)
            })
            .collect();
        let group = <Point as OsstPoint>::generator().mul_scalar(&secret);
        Ok(Self {
            group_vk: encode_group_vk(&group),
            group,
            shares,
            threshold,
        })
    }

    pub fn group_vk(&self) -> &str {
        &self.group_vk
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; FROST_SIG_LEN], String> {
        let indexes: Vec<u32> = self
            .shares
            .iter()
            .take(self.threshold as usize)
            .map(|share| share.index)
            .collect();
        self.sign_indexes(message, &indexes)
    }

    pub fn sign_indexes(
        &self,
        message: &[u8],
        indexes: &[u32],
    ) -> Result<[u8; FROST_SIG_LEN], String> {
        if message.is_empty() {
            return Err("frost sign refused: empty sign doc".into());
        }
        if indexes.len() < self.threshold as usize {
            return Err(format!(
                "frost quorum not met: {} of {} shares",
                indexes.len(),
                self.threshold
            ));
        }
        let mut selected = Vec::with_capacity(indexes.len());
        for index in indexes {
            let share = self
                .shares
                .iter()
                .find(|share| share.index == *index)
                .ok_or_else(|| format!("frost sign refused: missing share index {index}"))?;
            selected.push(share.clone());
        }
        let mut rng = OsRng;
        let mut nonces = Vec::with_capacity(selected.len());
        let mut commits = Vec::with_capacity(selected.len());
        for share in &selected {
            let (nonce, commit) = osst::frost::commit::<Point, _>(share.index, &mut rng);
            nonces.push(nonce);
            commits.push(commit);
        }
        let package = SigningPackage::new(message.to_vec(), commits)
            .map_err(|err| format!("frost signing package refused: {err:?}"))?;
        let parts = selected
            .iter()
            .zip(nonces)
            .map(|(share, nonce)| {
                osst::frost::sign(&package, nonce, share, &self.group)
                    .map_err(|err| format!("frost signature share refused: {err:?}"))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let signature = osst::frost::aggregate(&package, &parts, &self.group, None)
            .map_err(|err| format!("frost aggregate refused: {err:?}"))?;
        let encoded = crate::wire::encode_signature(&signature);
        verify_group_signature(&self.group_vk, message, &encoded)
            .map_err(|err| format!("frost signature failed local verification: {err}"))?;
        Ok(encoded)
    }
}

/// Who approved the digest. The factor is not the broadcasting key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalFactor {
    Keplr,
    Zafu,
    Passkey,
    /// Injected approver for tests. Not a browser wallet.
    Test,
}

/// Time source for expiry. Callers pass a chain clock or a test clock.
pub trait Clock {
    fn unix_secs(&self) -> u64;
}

/// Immutable record of one script session. Authz and feegrant bytes are
/// phase 3. This record owns the scope those grants will carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionGrant {
    pub grantee: String,
    pub expiration_unix: u64,
    pub session_id: String,
    pub allowlist: RunAllowlist,
    pub factor: ApprovalFactor,
    pub nonce: [u8; 32],
}

impl SessionGrant {
    pub fn allowlist_type_urls(&self) -> Vec<String> {
        self.allowlist.type_urls()
    }
}

/// Ephemeral secp256k1 broadcaster for one run. The secret is not a share.
pub struct ScriptSession {
    grant: SessionGrant,
    key: SigningKey,
    revoked: bool,
    nonce_used: bool,
}

impl core::fmt::Debug for ScriptSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ScriptSession")
            .field("session_id", &self.grant.session_id)
            .field("grantee", &self.grant.grantee)
            .field("factor", &self.grant.factor)
            .field("expiration_unix", &self.grant.expiration_unix)
            .field("revoked", &self.revoked)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ScriptSession {
    pub fn open(
        allowlist: RunAllowlist,
        factor: ApprovalFactor,
        ttl_secs: u64,
        clock: &impl Clock,
        session_id: impl Into<String>,
    ) -> Result<Self, String> {
        let session_id = session_id.into();
        if session_id.is_empty() {
            return Err("session refused: empty session id".into());
        }
        if ttl_secs == 0 {
            return Err("session refused: ttl is 0".into());
        }
        let key = SigningKey::random();
        let grantee = key
            .public_key()
            .account_id("terp")
            .map_err(|err| format!("session grantee refused: {err}"))?
            .to_string();
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce);
        Ok(Self {
            grant: SessionGrant {
                grantee,
                expiration_unix: clock.unix_secs().saturating_add(ttl_secs),
                session_id,
                allowlist,
                factor,
                nonce,
            },
            key,
            revoked: false,
            nonce_used: false,
        })
    }

    pub fn grantee(&self) -> &str {
        &self.grant.grantee
    }

    pub fn grant(&self) -> &SessionGrant {
        &self.grant
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// One use of the approval nonce. Does not produce a chain signature.
    pub fn authorize_use(&mut self, clock: &impl Clock) -> Result<(), String> {
        let id = &self.grant.session_id;
        if self.revoked {
            return Err(format!("session revoked: {id}"));
        }
        if clock.unix_secs() >= self.grant.expiration_unix {
            return Err(format!("session expired: {id}"));
        }
        if self.nonce_used {
            return Err(format!("nonce already used: {id}"));
        }
        self.key
            .sign(&self.grant.nonce)
            .map_err(|err| format!("session sign refused: {id} {err}"))?;
        self.nonce_used = true;
        Ok(())
    }
}

#[cfg(test)]
struct FixedClock {
    now: u64,
}

#[cfg(test)]
impl Clock for FixedClock {
    fn unix_secs(&self) -> u64 {
        self.now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_of_one_and_two_of_three_verify_and_a_short_quorum_does_not_sign() {
        let one = FrostSession::deal(1, 1).unwrap();
        let message = b"sign-doc-bytes";
        let signature = one.sign(message).unwrap();
        verify_group_signature(one.group_vk(), message, &signature).unwrap();
        let debug = format!("{:?}", one);
        assert!(debug.contains("[REDACTED]"));

        let many = FrostSession::deal(2, 3).unwrap();
        let signature = many.sign(message).unwrap();
        verify_group_signature(many.group_vk(), message, &signature).unwrap();
        let err = many.sign_indexes(message, &[1]).unwrap_err();
        assert_eq!(err, "frost quorum not met: 1 of 2 shares");
        assert!(FrostSession::deal(0, 3)
            .unwrap_err()
            .contains("threshold 0 of 3"));
    }

    #[test]
    fn expired_revoked_and_reused_nonce_cannot_sign() {
        let allow = RunAllowlist::default();
        let mut clock = FixedClock { now: 1_000 };
        let mut session =
            ScriptSession::open(allow, ApprovalFactor::Test, 60, &clock, "run-1").unwrap();
        let debug = format!("{:?}", session);
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("run-1"));
        assert!(session.grantee().starts_with("terp1"));
        session.authorize_use(&clock).unwrap();
        let again = session.authorize_use(&clock).unwrap_err();
        assert!(again.contains("nonce already used"));
        assert!(again.contains("run-1"));

        clock.now = 1_000;
        let mut session = ScriptSession::open(
            RunAllowlist::default(),
            ApprovalFactor::Passkey,
            60,
            &clock,
            "run-2",
        )
        .unwrap();
        session.revoke();
        let err = session.authorize_use(&clock).unwrap_err();
        assert!(err.contains("session revoked"));
        assert!(err.contains("run-2"));

        clock.now = 1_060;
        let mut session = ScriptSession::open(
            RunAllowlist::default(),
            ApprovalFactor::Keplr,
            60,
            &FixedClock { now: 1_000 },
            "run-3",
        )
        .unwrap();
        let err = session.authorize_use(&clock).unwrap_err();
        assert!(err.contains("session expired"));
        assert!(err.contains("run-3"));
    }
}
