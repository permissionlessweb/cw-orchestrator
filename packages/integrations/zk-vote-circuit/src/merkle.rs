//! Poseidon-based binary Merkle tree (depth=5) for ZK voting.
//!
//! Mirrors the functionality of `merkle.js` from the prototype:
//! - Incremental insertion of identity commitments
//! - Proof generation (path elements + path bits)
//! - Root calculation from leaf + path
//! - Supports up to 2^depth voters

use pasta_curves::vesta::Base as Fq;
use ff::Field;

use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};

/// Default Merkle tree depth for the ZK voting circuit.
pub const DEFAULT_MERKLE_DEPTH: usize = 5;

/// Maximum number of leaves: 2^depth.
pub const MAX_LEAVES: usize = 1 << DEFAULT_MERKLE_DEPTH; // 32

/// A Merkle membership proof for a ZK vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// Sibling hashes along the path from leaf to root.
    pub path_elements: Vec<Fq>,
    /// Binary indicators: 0 = leaf is the left child, 1 = leaf is the right child.
    pub path_bits: Vec<bool>,
    /// The leaf's index in the tree.
    pub index: usize,
    /// The computed Merkle root.
    pub root: Fq,
}

/// Poseidon-based binary Merkle tree with fixed depth.
///
/// # Examples
///
/// ```
/// use zk_vote_circuit::merkle::PoseidonMerkleTree;
/// use pasta_curves::vesta::Base as Fq;
///
/// let mut tree = PoseidonMerkleTree::new();
/// let leaf_a = Fq::from(42u64);
/// let leaf_b = Fq::from(99u64);
///
/// let idx_a = tree.insert(leaf_a);
/// let idx_b = tree.insert(leaf_b);
///
/// let proof_a = tree.get_proof(idx_a).unwrap();
/// assert!(PoseidonMerkleTree::verify_leaf(&leaf_a, &proof_a));
/// ```
#[derive(Debug, Clone)]
pub struct PoseidonMerkleTree {
    depth: usize,
    /// Level-by-level storage: `levels[0]` is leaves, `levels[depth]` is root.
    levels: Vec<Vec<Fq>>,
    /// Current number of leaves inserted.
    leaf_count: usize,
}

impl PoseidonMerkleTree {
    /// Create a new empty Merkle tree with [`DEFAULT_MERKLE_DEPTH`].
    pub fn new() -> Self {
        Self::with_depth(DEFAULT_MERKLE_DEPTH)
    }

    /// Create a new empty Merkle tree with a custom depth.
    pub fn with_depth(depth: usize) -> Self {
        let mut levels = Vec::with_capacity(depth + 1);
        for _ in 0..=depth {
            levels.push(Vec::new());
        }
        Self {
            depth,
            levels,
            leaf_count: 0,
        }
    }

    /// Insert a leaf value and return its index.
    pub fn insert(&mut self, leaf: Fq) -> usize {
        let idx = self.leaf_count;
        self.leaf_count += 1;

        // Place leaf at the correct position in level 0
        if idx >= self.levels[0].len() {
            self.levels[0].resize(idx + 1, Fq::ZERO);
        }
        self.levels[0][idx] = leaf;

        // Recompute ancestors up to the root
        let mut current = leaf;
        let mut pos = idx;
        for level in 1..=self.depth {
            let sibling = if pos % 2 == 0 {
                // current is left child
                let right = if pos + 1 < self.levels[level - 1].len() {
                    self.levels[level - 1][pos + 1]
                } else {
                    Fq::ZERO // zero-fill for empty right siblings
                };
                self.ensure_level(level - 1, pos + 1);
                self.levels[level - 1][pos] = current;
                self.levels[level - 1][pos + 1] = right;
                right
            } else {
                // current is right child
                let left = self.levels[level - 1][pos - 1];
                left
            };

            current = if pos % 2 == 0 {
                // current is left child: hash(left, right)
                hash_pair(&current, &sibling)
            } else {
                // current is right child: hash(left, right)
                hash_pair(&sibling, &current)
            };

            self.ensure_level(level, pos / 2);
            self.levels[level][pos / 2] = current;

            pos /= 2;
        }

        idx
    }

    /// Generate a Merkle proof for a leaf at the given index.
    ///
    /// Returns `None` if the index is out of range.
    pub fn get_proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaf_count {
            return None;
        }

        let mut path_elements = Vec::with_capacity(self.depth);
        let mut path_bits = Vec::with_capacity(self.depth);
        let mut pos = index;

        for level in 0..self.depth {
            if pos % 2 == 0 {
                // Current is left child -> sibling is right
                let sibling = if pos + 1 < self.levels[level].len() {
                    self.levels[level][pos + 1]
                } else {
                    Fq::ZERO
                };
                path_elements.push(sibling);
                path_bits.push(false);
            } else {
                // Current is right child -> sibling is left
                let sibling = if pos > 0 && pos - 1 < self.levels[level].len() {
                    self.levels[level][pos - 1]
                } else {
                    Fq::ZERO
                };
                path_elements.push(sibling);
                path_bits.push(true);
            }
            pos /= 2;
        }

        let root = self
            .levels
            .get(self.depth)
            .and_then(|l| l.first().copied())
            .unwrap_or(Fq::ZERO);

        Some(MerkleProof {
            path_elements,
            path_bits,
            index,
            root,
        })
    }

    /// Verify a Merkle proof given the leaf value explicitly.
    pub fn verify_leaf(leaf: &Fq, proof: &MerkleProof) -> bool {
        if proof.path_elements.len() != proof.path_bits.len() {
            return false;
        }
        if proof.path_elements.is_empty() {
            return *leaf == proof.root;
        }
        let mut current = *leaf;
        for (sibling, bit) in proof.path_elements.iter().zip(proof.path_bits.iter()) {
            current = if *bit {
                // Current is right child: [sibling, current]
                hash_pair(sibling, &current)
            } else {
                // Current is left child: [current, sibling]
                hash_pair(&current, sibling)
            };
        }
        current == proof.root
    }

    /// Get the current Merkle root.
    pub fn root(&self) -> Fq {
        if self.leaf_count == 0 {
            return Fq::ZERO;
        }
        self.levels[self.depth]
            .first()
            .copied()
            .unwrap_or(Fq::ZERO)
    }

    /// The depth of this tree.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Current number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    fn ensure_level(&mut self, level: usize, min_len: usize) {
        if self.levels[level].len() <= min_len {
            self.levels[level].resize(min_len + 1, Fq::ZERO);
        }
    }
}

impl Default for PoseidonMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash two field elements with Poseidon(t=3, rate=2, ConstantLength<2>).
pub fn hash_pair(left: &Fq, right: &Fq) -> Fq {
    Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([*left, *right])
}

/// Hash a single field element with Poseidon (ConstantLength<1>).
pub fn hash_single(value: &Fq) -> Fq {
    Hash::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([*value])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_is_zero() {
        let tree = PoseidonMerkleTree::new();
        assert_eq!(tree.root(), Fq::ZERO);
    }

    #[test]
    fn single_insert_produces_non_zero_root() {
        let mut tree = PoseidonMerkleTree::new();
        let leaf = Fq::from(42u64);
        tree.insert(leaf);
        assert_ne!(tree.root(), Fq::ZERO);
    }

    #[test]
    fn proof_verifies_for_single_leaf() {
        let mut tree = PoseidonMerkleTree::new();
        let leaf = Fq::from(42u64);
        tree.insert(leaf);
        let proof = tree.get_proof(0).unwrap();
        assert!(PoseidonMerkleTree::verify_leaf(&leaf, &proof));
    }

    #[test]
    fn proof_verifies_for_multiple_leaves() {
        let mut tree = PoseidonMerkleTree::new();
        let leaves: Vec<Fq> = (0u64..5).map(Fq::from).collect();

        for &leaf in &leaves {
            tree.insert(leaf);
        }

        for (i, &leaf) in leaves.iter().enumerate() {
            let proof = tree.get_proof(i).unwrap();
            assert!(
                PoseidonMerkleTree::verify_leaf(&leaf, &proof),
                "proof failed for index {}",
                i
            );
        }
    }

    #[test]
    fn proof_fails_for_wrong_leaf() {
        let mut tree = PoseidonMerkleTree::new();
        tree.insert(Fq::from(42u64));
        let proof = tree.get_proof(0).unwrap();
        assert!(!PoseidonMerkleTree::verify_leaf(&Fq::from(99u64), &proof));
    }

    #[test]
    fn tree_fills_inserts_correctly() {
        let mut tree = PoseidonMerkleTree::with_depth(2);
        for i in 0u64..3 {
            tree.insert(Fq::from(i));
        }
        assert_eq!(tree.leaf_count(), 3);
        for i in 0u64..3 {
            let proof = tree.get_proof(i as usize).unwrap();
            assert!(PoseidonMerkleTree::verify_leaf(&Fq::from(i), &proof));
        }
    }

    #[test]
    fn insert_returns_correct_index() {
        let mut tree = PoseidonMerkleTree::new();
        for i in 0u64..5 {
            let idx = tree.insert(Fq::from(i));
            assert_eq!(idx, i as usize);
        }
    }

    #[test]
    fn get_proof_returns_none_for_out_of_range() {
        let tree = PoseidonMerkleTree::new();
        assert!(tree.get_proof(0).is_none());
        assert!(tree.get_proof(100).is_none());
    }

    #[test]
    fn proof_has_correct_depth() {
        let mut tree = PoseidonMerkleTree::new();
        tree.insert(Fq::from(42u64));
        let proof = tree.get_proof(0).unwrap();
        assert_eq!(proof.path_elements.len(), DEFAULT_MERKLE_DEPTH);
        assert_eq!(proof.path_bits.len(), DEFAULT_MERKLE_DEPTH);
    }

    #[test]
    fn hash_pair_is_deterministic() {
        let a = Fq::from(1u64);
        let b = Fq::from(2u64);
        let h1 = hash_pair(&a, &b);
        let h2 = hash_pair(&a, &b);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_pair_is_not_commutative() {
        let a = Fq::from(1u64);
        let b = Fq::from(2u64);
        let h_ab = hash_pair(&a, &b);
        let h_ba = hash_pair(&b, &a);
        assert_ne!(h_ab, h_ba);
    }
}