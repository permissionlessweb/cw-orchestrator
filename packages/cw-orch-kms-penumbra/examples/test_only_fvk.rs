//! Prints the FVK + address of the TEST-ONLY seed used by tests/offline.rs
//! (SeedPhrase::from_randomness(&[7; 32])). Holds nothing; for local pcli checks.
use penumbra_sdk_keys::keys::{Bip44Path, SeedPhrase, SpendKey};
fn main() {
    let sk = SpendKey::from_seed_phrase_bip44(SeedPhrase::from_randomness(&[7; 32]), &Bip44Path::new(0));
    let fvk = sk.full_viewing_key();
    println!("{}", fvk);
    println!("{}", fvk.payment_address(0u32.into()).0);
}
