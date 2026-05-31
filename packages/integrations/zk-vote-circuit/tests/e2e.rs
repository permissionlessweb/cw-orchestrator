// //! End-to-end test: 5-voter ZK voting scenario.
// //!
// //! Mirrors the JS test `tests/test_zk_voting.js` from the prototype:
// //! 1. Create 5 voter identities
// //! 2. Register them in a Merkle tree
// //! 3. Each voter generates a nullifier and vote commitment
// //! 4. Verify nullifier uniqueness
// //! 5. Verify tally correctness
// //!
// //! Note: In this crate we test the off-chain identity + Merkle infrastructure.
// //! Full PLONK proof generation requires the Halo2 circuit binary which is
// //! compiled externally via the zk-wasmvm pipeline.

// use ff::Field;
// use pasta_curves::vesta::Base as Fq;

// use zk_vote_circuit::{
//     compute_vote_commitment, generate_salt, PoseidonMerkleTree, VoteOption, VoterIdentity,
// };

// /// Number of voters in the test scenario.
// const VOTER_COUNT: usize = 5;

// /// Poll ID for this test.
// const POLL_ID: u64 = 1;

// /// Expected tally for the test votes.
// struct ExpectedTally {
//     yes: usize,
//     no: usize,
//     no_with_veto: usize,
//     abstain: usize,
// }

// #[test]
// fn e2e_five_voter_scenario() {
//     // ── Phase 1: Create voter identities ──────────────────────────────────────
//     let seeds = ["alice", "bob", "charlie", "diana", "eve"];
//     let identities: Vec<VoterIdentity> = seeds
//         .iter()
//         .map(|s| VoterIdentity::from_seed(s))
//         .collect();

//     assert_eq!(identities.len(), VOTER_COUNT);
//     for id in &identities {
//         assert_ne!(id.private_key, Fq::ZERO);
//         assert_ne!(id.identity_commitment, Fq::ZERO);
//     }

//     // Verify deterministic identity generation
//     let id_again = VoterIdentity::from_seed("alice");
//     assert_eq!(identities[0].private_key, id_again.private_key);
//     assert_eq!(identities[0].identity_commitment, id_again.identity_commitment);

//     // ── Phase 2: Build Merkle tree of eligible voters ─────────────────────────
//     let mut tree = PoseidonMerkleTree::new();
//     let mut leaf_indices = Vec::with_capacity(VOTER_COUNT);

//     for id in &identities {
//         let idx = tree.insert(id.identity_commitment);
//         leaf_indices.push(idx);
//     }

//     assert_eq!(tree.leaf_count(), VOTER_COUNT);
//     assert_ne!(tree.root(), Fq::ZERO);

//     // ── Phase 3: Each voter generates a proof, nullifier, vote commitment ─────
//     // Vote assignments: 2 Yes, 1 No, 1 NoWithVeto, 1 Abstain
//     let vote_options = [
//         VoteOption::Yes,
//         VoteOption::Yes,
//         VoteOption::No,
//         VoteOption::NoWithVeto,
//         VoteOption::Abstain,
//     ];

//     let mut nullifiers = Vec::with_capacity(VOTER_COUNT);
//     let mut vote_commitments = Vec::with_capacity(VOTER_COUNT);
//     let mut merkle_proofs = Vec::with_capacity(VOTER_COUNT);

//     for (i, (id, vote)) in identities.iter().zip(vote_options.iter()).enumerate() {
//         // Generate Merkle proof
//         let proof = tree.get_proof(leaf_indices[i]).expect("should have proof");
//         assert_eq!(proof.path_elements.len(), 5); // depth=5
//         assert_eq!(proof.path_bits.len(), 5);

//         // Verify Merkle proof
//         assert!(
//             PoseidonMerkleTree::verify_leaf(&id.identity_commitment, &proof),
//             "Merkle proof failed for voter {}",
//             i
//         );

//         // Generate nullifier (unique per voter + poll)
//         let nullifier = id.nullifier(POLL_ID);
//         assert_ne!(nullifier, Fq::ZERO);

//         // Generate vote commitment with a salt
//         let salt = generate_salt(i as u64 * 1000 + 42);
//         let vote_commit = id.vote_commitment(*vote, salt);

//         nullifiers.push(nullifier);
//         vote_commitments.push(vote_commit);
//         merkle_proofs.push(proof);
//     }

//     // ── Phase 4: Verify nullifier uniqueness (no double-voting) ───────────────
//     for i in 0..nullifiers.len() {
//         for j in (i + 1)..nullifiers.len() {
//             assert!(
//                 nullifiers[i] != nullifiers[j],
//                 "Nullifier collision at voter {} and {}!",
//                 i,
//                 j
//             );
//         }
//     }

//     // ── Phase 5: Coordinator tally validation (simulated) ─────────────────────
//     // In production, the coordinator would verify each PLONK proof, check
//     // nullifier freshness, and store the vote commitment.
//     // Here we verify the tally conceptually.
//     let expected = ExpectedTally {
//         yes: 2,
//         no: 1,
//         no_with_veto: 1,
//         abstain: 1,
//     };

//     // Verify vote commitments match expected distribution
//     let mut yes_count = 0;
//     let mut no_count = 0;
//     let mut no_with_veto_count = 0;
//     let mut abstain_count = 0;

//     for (i, vote) in vote_options.iter().enumerate() {
//         let salt = generate_salt(i as u64 * 1000 + 42);
//         let expected_commit = compute_vote_commitment(*vote, salt);
//         assert_eq!(
//             vote_commitments[i], expected_commit,
//             "Vote commitment mismatch for voter {}",
//             i
//         );

//         match vote {
//             VoteOption::Yes => yes_count += 1,
//             VoteOption::No => no_count += 1,
//             VoteOption::NoWithVeto => no_with_veto_count += 1,
//             VoteOption::Abstain => abstain_count += 1,
//         }
//     }

//     assert_eq!(yes_count, expected.yes, "Yes count mismatch");
//     assert_eq!(no_count, expected.no, "No count mismatch");
//     assert_eq!(
//         no_with_veto_count, expected.no_with_veto,
//         "NoWithVeto count mismatch"
//     );
//     assert_eq!(abstain_count, expected.abstain, "Abstain count mismatch");

//     // ── Phase 6: Cross-voter verification ─────────────────────────────────────
//     // A voter's nullifier for poll 1 should differ from their nullifier for poll 2
//     for id in &identities {
//         let n1 = id.nullifier(1);
//         let n2 = id.nullifier(2);
//         assert_ne!(n1, n2, "Nullifier must change across polls");
//     }

//     // Different voters in the same poll produce different nullifiers
//     for i in 0..VOTER_COUNT {
//         for j in (i + 1)..VOTER_COUNT {
//             assert_ne!(
//                 nullifiers[i], nullifiers[j],
//                 "Nullifier collision between voters {} and {}",
//                 i, j
//             );
//         }
//     }
// }

// #[test]
// fn e2e_wrong_voter_rejected() {
//     // Simulate a voter who is NOT in the Merkle tree trying to vote
//     let legitimate = VoterIdentity::from_seed("alice");
//     let intruder = VoterIdentity::from_seed("mallory");

//     let mut tree = PoseidonMerkleTree::new();
//     tree.insert(legitimate.identity_commitment);

//     let intruder_proof = tree.get_proof(0).unwrap();
//     // Intruder uses a fake leaf — verification should fail
//     assert!(
//         !PoseidonMerkleTree::verify_leaf(&intruder.identity_commitment, &intruder_proof),
//         "Intruder should not be able to prove membership"
//     );
// }

// #[test]
// fn e2e_deterministic_output_consistency() {
//     // Run the scenario twice and confirm identical outputs
//     fn run_scenario(seed_prefix: &str, poll: u64) -> Vec<Fq> {
//         let id = VoterIdentity::from_seed(seed_prefix);
//         let nullifier = id.nullifier(poll);
//         let vote_commit = id.vote_commitment(VoteOption::Yes, Fq::from(42u64));
//         vec![id.identity_commitment, nullifier, vote_commit]
//     }

//     let r1 = run_scenario("alice", 1);
//     let r2 = run_scenario("alice", 1);
//     assert_eq!(r1, r2);
// }

// #[test]
// fn e2e_full_merkle_verification() {
//     // Build a tree with 32 voters (max for depth=5) and verify all proofs
//     let mut tree = PoseidonMerkleTree::new();
//     let mut identities = Vec::new();

//     for i in 0..32 {
//         let id = VoterIdentity::from_seed(format!("voter-{}", i));
//         tree.insert(id.identity_commitment);
//         identities.push(id);
//     }

//     assert_eq!(tree.leaf_count(), 32);

//     for (i, id) in identities.iter().enumerate() {
//         let proof = tree.get_proof(i).expect("should have proof");
//         assert!(
//             PoseidonMerkleTree::verify_leaf(&id.identity_commitment, &proof),
//             "Full tree verification failed at index {}",
//             i
//         );
//     }
// }