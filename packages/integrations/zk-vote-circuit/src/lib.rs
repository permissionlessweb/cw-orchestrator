// //! # ZK Vote Circuit
// //!
// //! Rust port of the MACI-style ZK voting prototype (t_9c0aa090).
// //!
// //! Provides a [`CircuitInstance`] + [`CircuitUploadable`] + [`CircuitFooterSpec`]
// //! implementation for the ZK voting circuit, along with off-chain voter
// //! identity management, Poseidon Merkle tree, and proof generation utilities.
// //!
// //! ## Architecture
// //!
// //! | Module | Replaces | Purpose |
// //! |--------|----------|---------|
// //! | [`types`] | — | `ZkVoteCircuit<Chain>`, `CircuitInstance` + `CircuitUploadable` impls |
// //! | [`identity`] | `identity.js` | Key derivation, identity commitment, nullifier, vote commitment |
// //! | [`merkle`] | `merkle.js` | Poseidon-based binary Merkle tree (depth=5) |
// //!
// //! The circuit binary itself is compiled externally via the Halo2/zk-wasmvm
// //! pipeline and placed at `circuit_keys/zk_vote/zk_vote_plonkish.bin`.

// pub mod circuit;
// pub mod identity;
// pub mod merkle;
// pub mod types;

// pub use identity::{
//     compute_identity_commitment, compute_nullifier, compute_vote_commitment,
//     derive_private_key, generate_salt, VoteOption, VoterIdentity,
// };
// pub use merkle::{MerkleProof, PoseidonMerkleTree, DEFAULT_MERKLE_DEPTH, MAX_LEAVES};
// pub use types::ZkVoteCircuit;