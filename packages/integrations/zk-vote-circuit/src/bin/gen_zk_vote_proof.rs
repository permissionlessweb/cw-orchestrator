// //! Proof generation binary for ZK voting circuit.
// //!
// //! Generates circuit artifacts:
// //! - `circuit_keys/zk_vote/zk_vote_plonkish.bin` — combined v2 VK
// //! - `circuit_keys/zk_vote/vk_combined.bin` — same bytes, convenience copy
// //! - `circuit_keys/zk_vote/zk_vote_summary.json` — metadata
// //!
// //! Also generates a test proof in-memory, verifies it, and
// //! reports pass/fail. The proof bytes are NOT written to disk
// //! (Proof has no public `as_bytes()` accessor in zk-cosmwasm yet).
// //!
// //! Usage: `cargo run --bin gen_zk_vote_proof`

// use std::path::PathBuf;

use anyhow::{Context, Result};
// use group::ff::{Field, PrimeField};
// use pasta_curves::vesta::{Base as Fq, Scalar};
// use serde::Serialize;
// use zk_cosmwasm::{CosmwasmCircuit, Instance, Proof, ProvingKey, VerifyingKey};
// // use zk_vote_circuit::circuit::{ZkVoteCircuit, MERKLE_DEPTH, NUM_INSTANCES};

// /// Log2 of the domain size (rows = 2^k). k=10 -> 1024 rows.
// const K: u32 = 10;

// /// Output directory (relative to CWD).
// const OUTPUT_DIR: &str = "circuit_keys/zk_vote";

// #[derive(Serialize)]
// struct Summary {
//     circuit: String,
//     k: u32,
//     num_instances: usize,
//     merkle_depth: usize,
//     plonkish_file: String,
//     plonkish_size_bytes: u64,
//     vk_hash_prefix: String,
// }

// /// Convert a vest::Base (Fq) to vest::Scalar (Fp) via repr.
// fn fq2scalar(v: Fq) -> Scalar {
//     Scalar::from_repr(v.to_repr()).unwrap_or(Scalar::ZERO)
// }

fn main() -> Result<()> {
    //     println!("=== ZK Vote Proof Generator ===");
    //     println!("k={K}, instances={NUM_INSTANCES}, merkle_depth={MERKLE_DEPTH}");

    //     let out_dir = PathBuf::from(OUTPUT_DIR);
    //     std::fs::create_dir_all(&out_dir).context("mkdir")?;

    //     // ── 1. Build circuit (no witness = keygen-only) ─────────────────
    //     let circuit = ZkVoteCircuit::without_witnesses();
    //     let cosmwasm_circuit = CosmwasmCircuit::new(circuit);

    //     // ── 2. Build proving key + v2 VK bytes ─────────────────────────
    //     println!("Building proving key + v2 VK...");
    //     let (pk, vk_v2_bytes) = ProvingKey::build_with_vk_v2(K, cosmwasm_circuit, NUM_INSTANCES)
    //         .context("ProvingKey::build_with_vk_v2")?;
    //     println!("VK v2 bytes: {}", vk_v2_bytes.len());

    //     // ── 3. Write artifacts ─────────────────────────────────────────
    //     let plonkish_path = out_dir.join("zk_vote_plonkish.bin");
    //     std::fs::write(&plonkish_path, &vk_v2_bytes).context("write zk_vote_plonkish.bin")?;

    //     let vk_combined_path = out_dir.join("vk_combined.bin");
    //     std::fs::write(&vk_combined_path, &vk_v2_bytes).context("write vk_combined.bin")?;

    //     let prefix: String = vk_v2_bytes[..8.min(vk_v2_bytes.len())]
    //         .iter()
    //         .map(|b| format!("{b:02x}"))
    //         .collect();

    //     let summary = Summary {
    //         circuit: "ZkVoteCircuit".into(),
    //         k: K,
    //         num_instances: NUM_INSTANCES,
    //         merkle_depth: MERKLE_DEPTH,
    //         plonkish_file: plonkish_path.to_string_lossy().into(),
    //         plonkish_size_bytes: vk_v2_bytes.len() as u64,
    //         vk_hash_prefix: prefix,
    //     };
    //     let summary_json = serde_json::to_string_pretty(&summary)?;
    //     std::fs::write(out_dir.join("zk_vote_summary.json"), &summary_json)?;
    //     println!("\n=== Summary ===\n{summary_json}");

    //     // ── 4. Generate + verify test proof ────────────────────────────
    //     println!("\n=== Generating test proof ===");
    //     generate_and_verify_test_proof(&pk, &vk_v2_bytes)?;

    //     println!("\nDone. All artifacts in: {}", out_dir.display());
    //     Ok(())
    // }

    // /// Generate a test proof and verify it in-memory.
    // fn generate_and_verify_test_proof(pk: &ProvingKey, vk_v2_bytes: &[u8]) -> Result<()> {
    //     use zk_vote_circuit::identity::{
    //         compute_identity_commitment, compute_nullifier, compute_vote_commitment, generate_salt,
    //         VoteOption, VoterIdentity,
    //     };
    //     use zk_vote_circuit::merkle::PoseidonMerkleTree;

    //     // Build real witnesses using the off-chain hashing code
    //     let identity = VoterIdentity::from_seed("test_voter_zk");
    //     let salt = generate_salt(42);
    //     let id_comm = compute_identity_commitment(&identity.private_key);
    //     let nullifier_val = compute_nullifier(&identity.private_key, 1);
    //     let vc_val = compute_vote_commitment(VoteOption::Yes, salt);

    //     // Build a Merkle tree containing only this voter
    //     let mut tree = PoseidonMerkleTree::new();
    //     tree.insert(id_comm);
    //     let merkle_proof = tree.get_proof(0).unwrap();
    //     let root = tree.root();

    //     // Convert Fq -> Fp for the circuit
    //     let private_key = fq2scalar(identity.private_key);
    //     let vote_option = fq2scalar(VoteOption::Yes.to_field());
    //     let salt = fq2scalar(salt);

    //     let mut path_elements = [Scalar::ZERO; MERKLE_DEPTH];
    //     let mut path_bits = [false; MERKLE_DEPTH];
    //     for i in 0..MERKLE_DEPTH {
    //         path_elements[i] = fq2scalar(merkle_proof.path_elements[i]);
    //         path_bits[i] = merkle_proof.path_bits[i];
    //     }

    //     let poll_id = fq2scalar(Fq::from(1u64));
    //     let merkle_root = fq2scalar(root);
    //     let nullifier = fq2scalar(nullifier_val);
    //     let vote_commitment = fq2scalar(vc_val);

    //     let witness = zk_vote_circuit::circuit::ZkVoteWitness {
    //         private_key,
    //         vote_option,
    //         salt,
    //         path_elements,
    //         path_bits,
    //         poll_id,
    //         merkle_root,
    //         nullifier,
    //         vote_commitment,
    //     };

    //     // Build circuit with witnesses
    //     let circuit = ZkVoteCircuit::with_witness(witness.clone());
    //     let cosmwasm_circuit = CosmwasmCircuit::new(circuit);

    //     let instances = Instance::new(vec![
    //         witness.poll_id,
    //         witness.merkle_root,
    //         witness.nullifier,
    //         witness.vote_commitment,
    //     ]);

    //     println!("Creating proof...");
    //     let mut rng = rand::thread_rng();
    //     let proof = Proof::create(pk, &[cosmwasm_circuit], &[instances.clone()], &mut rng)
    //         .context("Proof::create")?;
    //     println!("Proof created successfully.");

    //     // Verify using the v2 VK bytes
    //     println!("Verifying proof...");
    //     let verify_vk = VerifyingKey::from_bytes(vk_v2_bytes).context("VerifyingKey::from_bytes")?;
    //     let verify_result = proof.verify(&verify_vk, &[instances]);
    //     match verify_result {
    //         Ok(()) => println!("Proof verification: PASSED"),
    //         Err(e) => println!("Proof verification: FAILED -- {e:?}"),
    //     }

    Ok(())
}
