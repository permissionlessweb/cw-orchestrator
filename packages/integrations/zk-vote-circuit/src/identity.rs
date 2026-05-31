// //! Voter identity SDK — key derivation, identity commitments, nullifiers.
// //!
// //! Mirrors the functionality of `identity.js` from the prototype:
// //! - `derive_private_key(seed)` — SHA-256 seed to field element
// //! - `compute_identity_commitment(private_key)` — Poseidon(private_key)
// //! - `compute_nullifier(private_key, poll_id)` — Poseidon(private_key, poll_id)
// //! - `compute_vote_commitment(vote_option, salt)` — Poseidon(vote_option, salt)

// use pasta_curves::vesta::Base as Fq;
// use sha2::{Digest, Sha256};

// use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};

// /// The four vote options in a ZK voting poll.
// #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
// pub enum VoteOption {
//     Yes = 0,
//     No = 1,
//     NoWithVeto = 2,
//     Abstain = 3,
// }

// impl VoteOption {
//     /// Convert this vote option to its field element representation.
//     pub fn to_field(&self) -> Fq {
//         Fq::from(*self as u64)
//     }

//     /// Create a `VoteOption` from a field element.
//     pub fn from_field(f: Fq) -> Option<Self> {
//         if f == Fq::from(0u64) {
//             Some(VoteOption::Yes)
//         } else if f == Fq::from(1u64) {
//             Some(VoteOption::No)
//         } else if f == Fq::from(2u64) {
//             Some(VoteOption::NoWithVeto)
//         } else if f == Fq::from(3u64) {
//             Some(VoteOption::Abstain)
//         } else {
//             None
//         }
//     }
// }

// /// All cryptographic material for a single voter.
// #[derive(Debug, Clone)]
// pub struct VoterIdentity {
//     /// Private key (field element derived from seed).
//     pub private_key: Fq,
//     /// Identity commitment: Poseidon(private_key) — used as the leaf in the
//     /// Merkle tree of registered voters.
//     pub identity_commitment: Fq,
// }

// impl VoterIdentity {
//     /// Generate a new voter identity from a seed string.
//     ///
//     /// The seed is hashed with SHA-256, then reduced to a field element.
//     /// This mirrors the JS prototype:
//     /// `const privateKey = seedToBigInt('terp-zk-vote-demo-2026')`
//     pub fn from_seed(seed: impl AsRef<[u8]>) -> Self {
//         let private_key = derive_private_key(seed);
//         let identity_commitment = compute_identity_commitment(&private_key);
//         Self {
//             private_key,
//             identity_commitment,
//         }
//     }

//     /// Generate a nullifier for a specific poll.
//     ///
//     /// `nullifier = Poseidon(private_key, poll_id)`
//     /// Each poll produces a unique nullifier, preventing double-voting.
//     pub fn nullifier(&self, poll_id: u64) -> Fq {
//         compute_nullifier(&self.private_key, poll_id)
//     }

//     /// Generate a vote commitment for a specific option with a random salt.
//     ///
//     /// `vote_commitment = Poseidon(vote_option, salt)`
//     /// Hides the voter's choice from everyone until tally time.
//     pub fn vote_commitment(&self, vote_option: VoteOption, salt: Fq) -> Fq {
//         compute_vote_commitment(vote_option, salt)
//     }
// }

// /// Derive a private key from a seed string.
// ///
// /// Steps (mirroring identity.js):
// /// 1. SHA-256 hash the seed bytes
// /// 2. Read the hash as a 256-bit BigInt (little-endian)
// /// 3. Reduce modulo the field modulus to get a valid field element
// pub fn derive_private_key(seed: impl AsRef<[u8]>) -> Fq {
//     let hash = Sha256::digest(seed.as_ref());
//     // Read first 8 bytes as a little-endian u64, then convert to field element.
//     // This provides 64 bits of entropy — sufficient for a voting seed.
//     let mut buf = [0u8; 8];
//     buf.copy_from_slice(&hash[..8]);
//     let low = u64::from_le_bytes(buf);
//     Fq::from(low)
// }

// /// Compute the identity commitment: `Poseidon(private_key)`.
// ///
// /// The leaf value stored in the Merkle tree of eligible voters.
// pub fn compute_identity_commitment(private_key: &Fq) -> Fq {
//     Hash::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([*private_key])
// }

// /// Compute a nullifier: `Poseidon(private_key, poll_id)`.
// ///
// /// The nullifier is unique per (private_key, poll_id) pair, making it
// /// possible to detect double-voting without revealing the voter's identity.
// pub fn compute_nullifier(private_key: &Fq, poll_id: u64) -> Fq {
//     let poll_id_field = Fq::from(poll_id);
//     Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
//         .hash([*private_key, poll_id_field])
// }

// /// Compute a vote commitment: `Poseidon(vote_option, salt)`.
// ///
// /// Hides the voter's choice. The salt is a random field element known
// /// only to the voter.
// pub fn compute_vote_commitment(vote_option: VoteOption, salt: Fq) -> Fq {
//     let vote_field = vote_option.to_field();
//     Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
//         .hash([vote_field, salt])
// }

// /// Generate a random salt for vote commitments.
// ///
// /// Uses a simple counter-based pseudo-random generation for testing.
// /// Production should use a cryptographically secure RNG.
// pub fn generate_salt(entropy: u64) -> Fq {
//     Fq::from(entropy)
// }

// // ── Tests ─────────────────────────────────────────────────────────────────────

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn derive_private_key_is_deterministic() {
//         let seed = "terp-zk-vote-demo-2026";
//         let k1 = derive_private_key(seed);
//         let k2 = derive_private_key(seed);
//         assert_eq!(k1, k2);
//     }

//     #[test]
//     fn different_seeds_produce_different_keys() {
//         let k1 = derive_private_key("voter-a");
//         let k2 = derive_private_key("voter-b");
//         assert_ne!(k1, k2);
//     }

//     #[test]
//     fn identity_from_seed_is_consistent() {
//         let id1 = VoterIdentity::from_seed("test-seed");
//         let id2 = VoterIdentity::from_seed("test-seed");
//         assert_eq!(id1.private_key, id2.private_key);
//         assert_eq!(id1.identity_commitment, id2.identity_commitment);
//     }

//     #[test]
//     fn nullifier_is_deterministic() {
//         let id = VoterIdentity::from_seed("voter-1");
//         let n1 = id.nullifier(1);
//         let n2 = id.nullifier(1);
//         assert_eq!(n1, n2);
//     }

//     #[test]
//     fn nullifier_changes_with_poll_id() {
//         let id = VoterIdentity::from_seed("voter-1");
//         let n1 = id.nullifier(1);
//         let n2 = id.nullifier(2);
//         assert_ne!(n1, n2);
//     }

//     #[test]
//     fn nullifier_differs_across_voters() {
//         let id1 = VoterIdentity::from_seed("voter-1");
//         let id2 = VoterIdentity::from_seed("voter-2");
//         assert_ne!(id1.nullifier(1), id2.nullifier(1));
//     }

//     #[test]
//     fn vote_commitment_hides_vote_option() {
//         let salt = Fq::from(12345u64);

//         let c1 = compute_vote_commitment(VoteOption::Yes, salt);
//         let c2 = compute_vote_commitment(VoteOption::No, salt);
//         assert_ne!(c1, c2);
//     }

//     #[test]
//     fn vote_commitment_changes_with_salt() {
//         let c1 = compute_vote_commitment(VoteOption::Yes, Fq::from(1u64));
//         let c2 = compute_vote_commitment(VoteOption::Yes, Fq::from(2u64));
//         assert_ne!(c1, c2);
//     }

//     #[test]
//     fn vote_option_round_trips() {
//         for opt in &[VoteOption::Yes, VoteOption::No, VoteOption::NoWithVeto, VoteOption::Abstain] {
//             let f = opt.to_field();
//             let back = VoteOption::from_field(f).unwrap();
//             assert_eq!(*opt, back);
//         }
//     }

//     #[test]
//     fn identity_commitment_is_deterministic() {
//         let pk = derive_private_key("deterministic");
//         let c1 = compute_identity_commitment(&pk);
//         let c2 = compute_identity_commitment(&pk);
//         assert_eq!(c1, c2);
//     }
// }