// //! Halo2 PLONK circuit for ZK voting.
// //!
// //! Constrains:
// //! 1. identity_commitment = Poseidon(private_key)
// //! 2. nullifier = Poseidon(private_key, poll_id)
// //! 3. vote_commitment = Poseidon(vote_option, salt)
// //! 4. Merkle membership: leaf (identity_commitment) ∈ tree with root = merkle_root
// //!
// //! Public instances (instance column row order):
// //!   [0] = poll_id, [1] = merkle_root, [2] = nullifier, [3] = vote_commitment

// use group::ff::Field;
// use halo2_gadgets::poseidon::{
//     primitives::{ConstantLength, P128Pow5T3},
//     Hash as PoseidonHash, Pow5Chip, Pow5Config,
// };
// use halo2_proofs::{
//         circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
//         plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Instance, Selector},
//         poly::Rotation,
//     };
//     use pasta_curves::vesta::Scalar;

// pub const NUM_INSTANCES: usize = 4;
// pub const MERKLE_DEPTH: usize = 5;

// // ── Witness ──────────────────────────────────────────────────────────────

// #[derive(Debug, Clone)]
// pub struct ZkVoteWitness {
//     pub private_key: Scalar,
//     pub vote_option: Scalar,
//     pub salt: Scalar,
//     pub path_elements: [Scalar; MERKLE_DEPTH],
//     pub path_bits: [bool; MERKLE_DEPTH],
//     pub poll_id: Scalar,
//     pub merkle_root: Scalar,
//     pub nullifier: Scalar,
//     pub vote_commitment: Scalar,
// }

// // ── Config ──────────────────────────────────────────────────────────────

// #[derive(Clone, Debug)]
// pub struct ZkVoteConfig {
//     pub pow5_config: Pow5Config<Scalar, 3, 2>,
//     pub instance: Column<Instance>,
//     /// Gate columns: [col_a, col_b, col_bit, col_selected]
//     pub gate_cols: [Column<Advice>; 4],
//     /// Bool gate: bit * (1 - bit) = 0
//     pub s_bool: Selector,
//     /// Select gate: selected = (1-bit)*a + bit*b
//     pub s_select: Selector,
// }

// // ── Circuit ─────────────────────────────────────────────────────────────

// #[derive(Clone, Debug)]
// pub struct ZkVoteCircuit {
//     witness: Option<ZkVoteWitness>,
// }

// impl ZkVoteCircuit {
//     pub fn without_witnesses() -> Self {
//         Self { witness: None }
//     }
//     pub fn with_witness(witness: ZkVoteWitness) -> Self {
//         Self {
//             witness: Some(witness),
//         }
//     }
// }

// impl halo2_proofs::plonk::Circuit<Scalar> for ZkVoteCircuit {
//     type Config = ZkVoteConfig;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn without_witnesses(&self) -> Self {
//         Self::without_witnesses()
//     }

//     fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
//         let instance = meta.instance_column();
//         meta.enable_equality(instance);

//         let gate_cols = [
//             meta.advice_column(),
//             meta.advice_column(),
//             meta.advice_column(),
//             meta.advice_column(),
//         ];
//         for col in &gate_cols {
//             meta.enable_equality(*col);
//         }

//         // Poseidon chip columns
//         let state = [
//             meta.advice_column(),
//             meta.advice_column(),
//             meta.advice_column(),
//         ];
//         for col in &state {
//             meta.enable_equality(*col);
//         }
//         let partial_sbox = meta.advice_column();
//         meta.enable_equality(partial_sbox);

//         let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
//         let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
//         let constants = meta.fixed_column();
//         meta.enable_constant(constants);

//         let pow5_config = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

//         // Bool gate: bit * (1 - bit) == 0
//         let s_bool = meta.selector();
//         meta.create_gate("bool", |meta| {
//             let s = meta.query_selector(s_bool);
//             let bit = meta.query_advice(gate_cols[2], Rotation::cur());
//             let one = Expression::Constant(Scalar::ONE);
//             Constraints::with_selector(s, std::iter::once(bit.clone() * (one - bit)))
//         });

//         // Select gate: selected == (1-bit)*a + bit*b
//         //   ⇔  selected - (1-bit)*a - bit*b == 0
//         let s_select = meta.selector();
//         meta.create_gate("merkle_select", |meta| {
//             let s = meta.query_selector(s_select);
//             let a = meta.query_advice(gate_cols[0], Rotation::cur());
//             let b = meta.query_advice(gate_cols[1], Rotation::cur());
//             let bit = meta.query_advice(gate_cols[2], Rotation::cur());
//             let sel = meta.query_advice(gate_cols[3], Rotation::cur());
//             let one = Expression::Constant(Scalar::ONE);
//             Constraints::with_selector(s, std::iter::once(sel - (one - bit.clone()) * a - bit * b))
//         });

//         ZkVoteConfig {
//             pow5_config,
//             instance,
//             gate_cols,
//             s_bool,
//             s_select,
//         }
//     }

//     fn synthesize(
//         &self,
//         config: Self::Config,
//         mut layouter: impl Layouter<Scalar>,
//     ) -> Result<(), Error> {
//         let witness = match self.witness.as_ref() {
//             Some(w) => w,
//             None => return Ok(()),
//         };

//         let [ca, cb, cbit, csel] = config.gate_cols;

//         // ── 1. Load private witnesses ─────────────────────────────────
//         let pk = assign_advice(&mut layouter, ca, "private_key", witness.private_key)?;
//         let vote = assign_advice(&mut layouter, ca, "vote_option", witness.vote_option)?;
//         let salt = assign_advice(&mut layouter, ca, "salt", witness.salt)?;

//         let mut path_elements: Vec<AssignedCell<Scalar, Scalar>> = Vec::new();
//         let mut path_bit_cells: Vec<AssignedCell<Scalar, Scalar>> = Vec::new();

//         for i in 0..MERKLE_DEPTH {
//             let el = assign_advice(
//                 &mut layouter, ca, &format!("path_elem_{i}"), witness.path_elements[i],
//             )?;
//             path_elements.push(el);

//             let bval = if witness.path_bits[i] { Scalar::ONE } else { Scalar::ZERO };
//             let bit_cell = assign_advice(&mut layouter, ca, &format!("path_bit_{i}"), bval)?;

//             // Bool constraint via Region
//             layouter.assign_region(
//                 || format!("bool_{i}"),
//                 |mut region: Region<'_, Scalar>| {
//                     config.s_bool.enable(&mut region, 0)?;
//                     let assigned = region.assign_advice(
//                         || "bit_copy", cbit, 0,
//                         || bit_cell.value().cloned(),
//                     )?;
//                     region.constrain_equal(assigned.cell(), bit_cell.cell())?;
//                     Ok(())
//                 },
//             )?;

//             path_bit_cells.push(bit_cell);
//         }

//         // ── 2. Load instance values into advice cells ─────────────────
//         let poll_id_inst = copy_from_instance(
//             &mut layouter, config.instance, 0, ca, "poll_id_inst",
//         )?;

//         // ── 3. Identity commitment = Hash(private_key) ────────────────
//         let ident_commit = {
//             let chip = Pow5Chip::construct(config.pow5_config.clone());
//             let mut hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<1>, 3, 2>::init(
//                 chip, layouter.namespace(|| "id_commit_init"),
//             )?;
//             hasher.hash(layouter.namespace(|| "id_commit"), [pk.clone()])?
//         };

//         // ── 4. Nullifier = Hash(private_key, poll_id) ────────────────
//         let nullifier = {
//             let chip = Pow5Chip::construct(config.pow5_config.clone());
//             let mut hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
//                 chip, layouter.namespace(|| "nullifier_init"),
//             )?;
//             hasher.hash(
//                 layouter.namespace(|| "nullifier"),
//                 [pk.clone(), poll_id_inst.clone()],
//             )?
//         };

//         // ── 5. Vote commitment = Hash(vote, salt) ────────────────────
//         let vote_commit = {
//             let chip = Pow5Chip::construct(config.pow5_config.clone());
//             let mut hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
//                 chip, layouter.namespace(|| "vc_init"),
//             )?;
//             hasher.hash(layouter.namespace(|| "vc"), [vote.clone(), salt.clone()])?
//         };

//         // ── 6. Merkle path ───────────────────────────────────────────
//         let mut current = ident_commit;

//         for i in 0..MERKLE_DEPTH {
//             let sibling = &path_elements[i];
//             let bit = &path_bit_cells[i];

//             // Compute both orderings
//             let h_ab = {
//                 let chip = Pow5Chip::construct(config.pow5_config.clone());
//                 let mut hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
//                     chip, layouter.namespace(|| format!("hash_ab_{i}_init")),
//                 )?;
//                 hasher.hash(
//                     layouter.namespace(|| format!("hash_ab_{i}")),
//                     [current.clone(), sibling.clone()],
//                 )?
//             };

//             let h_ba = {
//                 let chip = Pow5Chip::construct(config.pow5_config.clone());
//                 let mut hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
//                     chip, layouter.namespace(|| format!("hash_ba_{i}_init")),
//                 )?;
//                 hasher.hash(
//                     layouter.namespace(|| format!("hash_ba_{i}")),
//                     [sibling.clone(), current.clone()],
//                 )?
//             };

//             // Select gate region: constrain selected = (1-bit)*h_ab + bit*h_ba
//             current = layouter.assign_region(
//                 || format!("merkle_select_{i}"),
//                 |mut region: Region<'_, Scalar>| {
//                     config.s_select.enable(&mut region, 0)?;

//                     // Copy hash_ab → ca
//                     let a_cell = region.assign_advice(
//                         || "a", ca, 0, || h_ab.value().cloned(),
//                     )?;
//                     region.constrain_equal(a_cell.cell(), h_ab.cell())?;

//                     // Copy hash_ba → cb
//                     let b_cell = region.assign_advice(
//                         || "b", cb, 0, || h_ba.value().cloned(),
//                     )?;
//                     region.constrain_equal(b_cell.cell(), h_ba.cell())?;

//                     // Copy bit → cbit
//                     let bit_c = region.assign_advice(
//                         || "bit", cbit, 0, || bit.value().cloned(),
//                     )?;
//                     region.constrain_equal(bit_c.cell(), bit.cell())?;

//                     // Compute selected = (1-bit)*a + bit*b using Value arithmetic
//                     let selected: Value<Scalar> = {
//                         let a_val = h_ab.value().cloned();
//                         let b_val = h_ba.value().cloned();
//                         let bv = bit.value().cloned();
//                         a_val.zip(bv).zip(b_val).map(|((a, bv), b)| {
//                             let one = Scalar::ONE;
//                             (one - bv) * a + bv * b
//                         })
//                     };

//                     let sel = region.assign_advice(
//                         || "selected", csel, 0, || selected,
//                     )?;

//                     Ok(sel)
//                 },
//             )?;
//         }

//         // ── 7. Constrain outputs ─────────────────────────────────────
//         // Final Merkle current == merkle_root instance
//         let merkle_root_inst = copy_from_instance(
//             &mut layouter, config.instance, 1, ca, "mk_root_inst",
//         )?;

//         layouter.assign_region(
//             || "constrain_merkle_root",
//             |mut region: Region<'_, Scalar>| {
//                 region.constrain_equal(current.cell(), merkle_root_inst.cell())?;
//                 Ok(())
//             },
//         )?;

//         // nullifier == instance[2]
//         let nullifier_inst = copy_from_instance(
//             &mut layouter, config.instance, 2, ca, "nullifier_inst",
//         )?;

//         layouter.assign_region(
//             || "constrain_nullifier",
//             |mut region: Region<'_, Scalar>| {
//                 region.constrain_equal(nullifier.cell(), nullifier_inst.cell())?;
//                 Ok(())
//             },
//         )?;

//         // vote_commitment == instance[3]
//         let vc_inst = copy_from_instance(
//             &mut layouter, config.instance, 3, ca, "vc_inst",
//         )?;

//         layouter.assign_region(
//             || "constrain_vc",
//             |mut region: Region<'_, Scalar>| {
//                 region.constrain_equal(vote_commit.cell(), vc_inst.cell())?;
//                 Ok(())
//             },
//         )?;

//         Ok(())
//     }
// }

// // ── Helpers ─────────────────────────────────────────────────────────────

// fn assign_advice(
//     layouter: &mut impl Layouter<Scalar>,
//     col: Column<Advice>,
//     label: &str,
//     value: Scalar,
// ) -> Result<AssignedCell<Scalar, Scalar>, Error> {
//     layouter.assign_region(
//         || label,
//         |mut region: Region<'_, Scalar>| {
//             region.assign_advice(|| label, col, 0, || Value::known(value))
//         },
//     )
// }

// fn copy_from_instance(
//     layouter: &mut impl Layouter<Scalar>,
//     instance: Column<Instance>,
//     row: usize,
//     dest: Column<Advice>,
//     label: &str,
// ) -> Result<AssignedCell<Scalar, Scalar>, Error> {
//     layouter.assign_region(
//         || label,
//         |mut region: Region<'_, Scalar>| {
//             region.assign_advice_from_instance(|| label, instance, row, dest, 0)
//         },
//     )
// }

// // ── Tests ───────────────────────────────────────────────────────────────

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::identity::{
//         compute_identity_commitment, compute_nullifier, compute_vote_commitment,
//         generate_salt, VoteOption, VoterIdentity,
//     };
//     use crate::merkle::PoseidonMerkleTree;
//     use group::ff::PrimeField;
//     use halo2_proofs::dev::MockProver;
//     use pasta_curves::vesta::Base as Fq;

//     fn fq2scalar(v: Fq) -> Scalar {
//         Scalar::from_repr(v.to_repr()).unwrap_or(Scalar::ZERO)
//     }

//     fn build_witness(seed: &str, vote: VoteOption, poll_id: u64) -> ZkVoteWitness {
//         let identity = VoterIdentity::from_seed(seed);
//         let salt = generate_salt(42);
//         let id_comm = compute_identity_commitment(&identity.private_key);
//         let nullifier_val = compute_nullifier(&identity.private_key, poll_id);
//         let vc_val = compute_vote_commitment(vote, salt);

//         let mut tree = PoseidonMerkleTree::new();
//         tree.insert(id_comm);
//         let proof = tree.get_proof(0).unwrap();
//         let root = tree.root();

//         let mut path_elements = [Fq::ZERO; MERKLE_DEPTH];
//         let mut path_bits = [false; MERKLE_DEPTH];
//         for i in 0..MERKLE_DEPTH {
//             path_elements[i] = proof.path_elements[i];
//             path_bits[i] = proof.path_bits[i];
//         }

//         ZkVoteWitness {
//             private_key: identity.private_key,
//             vote_option: vote.to_field(),
//             salt,
//             path_elements: path_elements.map(fq2scalar),
//             path_bits,
//             poll_id: fq2scalar(Fq::from(poll_id)),
//             merkle_root: fq2scalar(root),
//             nullifier: fq2scalar(nullifier_val),
//             vote_commitment: fq2scalar(vc_val),
//         }
//     }

//     fn run_mock(w: ZkVoteWitness) -> Result<(), Vec<halo2_proofs::dev::VerifyFailure>> {
//         let circuit = ZkVoteCircuit::with_witness(w.clone());
//         let pub_inst = vec![vec![
//             w.poll_id,
//             w.merkle_root,
//             w.nullifier,
//             w.vote_commitment,
//         ]];
//         let prover = MockProver::run(10, &circuit, pub_inst)?;
//         prover.verify()
//     }

//     #[test]
//     fn test_correct_vote() {
//         let w = build_witness("alice", VoteOption::Yes, 1);
//         assert_eq!(run_mock(w), Ok(()));
//     }

//     #[test]
//     fn test_different_voter() {
//         let w = build_witness("bob", VoteOption::No, 1);
//         assert_eq!(run_mock(w), Ok(()));
//     }

//     #[test]
//     fn test_abstain_vote() {
//         let w = build_witness("charlie", VoteOption::Abstain, 42);
//         assert_eq!(run_mock(w), Ok(()));
//     }

//     #[test]
//     fn test_wrong_nullifier_rejected() {
//         let w = build_witness("diana", VoteOption::Yes, 1);
//         let circuit = ZkVoteCircuit::with_witness(w.clone());
//         let pub_inst = vec![vec![
//             w.poll_id,
//             w.merkle_root,
//             fq2scalar(Fq::from(999)),
//             w.vote_commitment,
//         ]];
//         let prover = MockProver::run(10, &circuit, pub_inst).unwrap();
//         assert!(prover.verify().is_err());
//     }

//     #[test]
//     fn test_wrong_root_rejected() {
//         let w = build_witness("eve", VoteOption::Yes, 1);
//         let circuit = ZkVoteCircuit::with_witness(w.clone());
//         let pub_inst = vec![vec![
//             w.poll_id,
//             fq2scalar(Fq::from(12345)),
//             w.nullifier,
//             w.vote_commitment,
//         ]];
//         let prover = MockProver::run(10, &circuit, pub_inst).unwrap();
//         assert!(prover.verify().is_err());
//     }
// }