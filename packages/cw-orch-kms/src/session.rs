//! In-process FROST quorum. Signature bytes match `terp-frost` Authenticate.

use osst::curve::{OsstPoint, OsstScalar};
use osst::frost::SigningPackage;
use osst::SecretShare;
use rand::rngs::OsRng;

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
}
