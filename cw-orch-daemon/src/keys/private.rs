use super::public::PublicKey;
use crate::proto::injective::{InjectivePubKey, ETHEREUM_COIN_TYPE};
use crate::DaemonError;
#[cfg(feature = "eth")]
use ::ethers_core::k256::ecdsa::SigningKey;
use base64::Engine;
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::{
    bip32::{IntoDerivationPath, Xpriv},
    Network,
};
use cosmrs::tx::SignerPublicKey;
use cw_orch_core::log::local_target;
use prost_types::Any;
use rand_core::{OsRng, RngCore};

pub const DEFAULT_MNEMONIC_WORD_COUNT: usize = 24;

/// The Private key structure that is used to generate signatures and public keys
/// WARNING: No Security Audit has been performed
#[derive(Clone)]
pub struct PrivateKey {
    #[allow(missing_docs)]
    pub account: u32,
    #[allow(missing_docs)]
    pub index: u32,
    #[allow(missing_docs)]
    pub coin_type: u32,
    /// The mnemonic (12, 15, 18, 21 or 24 words) used to generate this private key
    mnemonic: Option<bip39::Mnemonic>,
    #[allow(dead_code)]
    /// This is used for testing
    root_private_key: Xpriv,
    /// The private key
    private_key: Xpriv,
}
impl PrivateKey {
    /// Generate a new private key
    pub fn new<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        coin_type: u32,
    ) -> Result<PrivateKey, DaemonError> {
        Self::new_seed(secp, "", coin_type)
    }
    /// generate a new private key with a seed phrase
    pub fn new_seed<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        passphrase: &str,
        coin_type: u32,
    ) -> Result<PrivateKey, DaemonError> {
        match bip39::Mnemonic::generate(DEFAULT_MNEMONIC_WORD_COUNT) {
            Ok(mnemonic) => {
                PrivateKey::gen_private_key_phrase(secp, mnemonic, 0, 0, coin_type, passphrase)
            }
            Err(_) => Err(DaemonError::Phrasing),
        }
    }
    /// for private key recovery. This is also used by wallet routines to re-hydrate the structure
    pub fn from_words<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        words: &str,
        account: u32,
        index: u32,
        coin_type: u32,
    ) -> Result<PrivateKey, DaemonError> {
        match bip39::Mnemonic::parse_in_normalized(bip39::Language::English, words) {
            Ok(mnemonic) => {
                PrivateKey::gen_private_key_phrase(secp, mnemonic, account, index, coin_type, "")
            }
            Err(_) => Err(DaemonError::Phrasing),
        }
    }

    /// for private key recovery with passphrase
    pub fn from_words_with_passphrase<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        words: &str,
        passphrase: &str,
        coin_type: u32,
    ) -> Result<PrivateKey, DaemonError> {
        match bip39::Mnemonic::parse_in_normalized(bip39::Language::English, words) {
            Ok(phrase) => {
                PrivateKey::gen_private_key_phrase(secp, phrase, 0, 0, coin_type, passphrase)
            }
            Err(_) => Err(DaemonError::Phrasing),
        }
    }

    pub fn from_raw_key<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        raw_key: &[u8],
        account: u32,
        index: u32,
        coin_type: u32,
    ) -> Result<PrivateKey, DaemonError> {
        Self::gen_private_key_raw(secp, raw_key, account, index, coin_type)
    }

    /// generate the public key for this private key
    pub fn public_key<C: secp256k1::Signing + secp256k1::Context>(
        &self,
        secp: &Secp256k1<C>,
    ) -> PublicKey {
        if self.coin_type == ETHEREUM_COIN_TYPE {
            #[cfg(feature = "eth")]
            return PublicKey::from_ethers_address_bytes(
                ethers_core::utils::secret_key_to_address(
                    &SigningKey::from_slice(self.raw_key().as_slice()).unwrap(),
                ),
            );
            panic!(
                "Coin Type {} not supported without eth feature",
                ETHEREUM_COIN_TYPE
            );
        }

        let x = self.private_key.private_key.public_key(secp);
        PublicKey::from_bitcoin_public_key(&bitcoin::PublicKey::new(x))
    }

    pub fn get_injective_public_key<C: secp256k1::Signing + secp256k1::Context>(
        &self,
        secp: &Secp256k1<C>,
    ) -> SignerPublicKey {
        use base64::engine::general_purpose;
        use cosmrs::tx::MessageExt;
        use secp256k1::SecretKey;

        let secret_key = SecretKey::from_slice(self.raw_key().as_slice()).unwrap();
        let public_key = secp256k1::PublicKey::from_secret_key(secp, &secret_key);

        let vec_pk = public_key.serialize();

        log::debug!(target: &local_target(), "{:?}, public key", general_purpose::STANDARD.encode(vec_pk));

        let inj_key = InjectivePubKey { key: vec_pk.into() };

        cosmrs::Any::from_msg(&inj_key).unwrap().try_into().unwrap()
    }

    pub fn get_signer_public_key<C: secp256k1::Signing + secp256k1::Context>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Option<SignerPublicKey> {
        if self.coin_type == ETHEREUM_COIN_TYPE {
            #[cfg(feature = "eth")]
            return Some(self.get_injective_public_key(secp));
            panic!(
                "Coin Type {} not supported without eth feature",
                ETHEREUM_COIN_TYPE
            );
        }

        Some(
            cosmrs::crypto::secp256k1::SigningKey::from_slice(self.raw_key().as_slice())
                .unwrap()
                .public_key()
                .into(),
        )
    }

    pub fn raw_key(&self) -> [u8; secp256k1::constants::SECRET_KEY_SIZE] {
        self.private_key.private_key.secret_bytes()
    }

    // Generate private key from Phrase
    fn gen_private_key_phrase<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        phrase: bip39::Mnemonic,
        account: u32,
        index: u32,
        coin_type: u32,
        passphrase: &str,
    ) -> Result<PrivateKey, DaemonError> {
        let seed = phrase.to_seed(passphrase);
        let mut private_key = Self::gen_private_key_raw(secp, &seed, account, index, coin_type)?;
        private_key.mnemonic = Some(phrase);
        Ok(private_key)
    }

    // Generate private key from private key bytes
    fn gen_private_key_raw<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        raw_key: &[u8],
        account: u32,
        index: u32,
        coin_type: u32,
    ) -> Result<PrivateKey, DaemonError> {
        let root_private_key = Xpriv::new_master(Network::Bitcoin, raw_key).unwrap();
        // For injective: https://docs.injective.network/learn/basic-concepts/accounts#injective-accounts
        let path = format!("m/44'/{coin_type}'/{account}'/0/{index}");
        let derivation_path = path.into_derivation_path()?;

        let private_key = root_private_key.derive_priv(secp, &derivation_path)?;
        Ok(PrivateKey {
            account,
            index,
            coin_type,
            mnemonic: None,
            root_private_key,
            private_key,
        })
    }

    /// the words used to generate this private key
    pub fn words(&self) -> Option<String> {
        self.mnemonic.as_ref().map(|phrase| phrase.to_string())
    }

    /// used for testing
    /// could potentially be used to recreate the private key instead of words
    #[allow(dead_code)]
    pub(crate) fn seed(&self, passwd: &str) -> Option<[u8; 64]> {
        self.mnemonic.as_ref().map(|phrase| phrase.to_seed(passwd))
    }
}

#[cfg(test)]
mod tst {
    use base64::{engine::general_purpose, Engine};
    use cosmwasm_std::StdResult;
    use ethers_core::k256::ecdsa::SigningKey;
    use ethers_signers::{coins_bip39::English, MnemonicBuilder, Signer};

    use super::*;

    #[test]
    pub fn tst_gen_mnemonic() -> Result<(), DaemonError> {
        // this test just makes sure the default will call it.
        let s = Secp256k1::new();
        let coin_type: u32 = 330;
        PrivateKey::new(&s, coin_type).map(|_| ())
    }

    #[test]
    pub fn tst_words_len() {
        let coin_type: u32 = 330;
        let str_1 = "notice oak worry limit wrap speak medal online prefer cluster roof addict wrist behave treat actual wasp year salad speed social layer crew";
        let seed_1 = "a2ae8846397b55d266af35acdbb18ba1d005f7ddbdd4ca7a804df83352eaf373f274ba0dc8ac1b2b25f19dfcb7fa8b30a240d2c6039d88963defc2f626003b2f";
        let s = Secp256k1::new();
        let res = PrivateKey::from_words(&s, str_1, 0, 0, coin_type);
        assert!(res.is_err())
    }

    #[test]
    pub fn tst_words() -> StdResult<()> {
        let coin_type: u32 = 330;
        let str_1 = "notice oak worry limit wrap speak medal online prefer cluster roof addict wrist behave treat actual wasp year salad speed social layer crew genius";
        let seed_1 = "a2ae8846397b55d266af35acdbb18ba1d005f7ddbdd4ca7a804df83352eaf373f274ba0dc8ac1b2b25f19dfcb7fa8b30a240d2c6039d88963defc2f626003b2f";
        let s = Secp256k1::new();
        let pk = PrivateKey::from_words(&s, str_1, 0, 0, coin_type)?;
        assert_eq!(hex::encode(pk.seed("").unwrap()), seed_1);
        match pk.words() {
            Some(words) => {
                assert_eq!(words, str_1);
                Ok(())
            }
            None => Err(DaemonError::MissingPhrase.into()),
        }
    }
    #[test]
    pub fn tst_root_priv_key() -> StdResult<()> {
        let coin_type: u32 = 330;
        let str_1 = "wonder caution square unveil april art add hover spend smile proud admit modify old copper throw crew happy nature luggage reopen exhibit ordinary napkin";
        let secp = Secp256k1::new();
        let pk = PrivateKey::from_words(&secp, str_1, 0, 0, coin_type)?;
        let root_key = "xprv9s21ZrQH143K2ep3BpYRRMjSqjLHZAPAzxfVVS3NBuGKBVtCrK3C8mE8TcmTjYnLm7SJxdLigDFWGAMnctKxc3p5QKNWXdprcFSQzGzQqTW";
        assert_eq!(pk.root_private_key.to_string(), root_key);

        let derived_key = "4804e2bdce36d413206ccf47cc4c64db2eff924e7cc9e90339fa7579d2bd9d5b";
        assert_eq!(
            pk.private_key.private_key.display_secret().to_string(),
            derived_key
        );

        Ok(())
    }
    #[test]
    pub fn tst_words_to_pub() -> StdResult<()> {
        let str_1 = "wonder caution square unveil april art add hover spend smile proud admit modify old copper throw crew happy nature luggage reopen exhibit ordinary napkin";
        let coin_type: u32 = 330;
        let prefix = "terra";
        let secp = Secp256k1::new();
        let pk = PrivateKey::from_words(&secp, str_1, 0, 0, coin_type)?;
        let pub_k = pk.public_key(&secp);

        let account = pub_k.account(prefix)?;
        assert_eq!(&account, "terra1jnzv225hwl3uxc5wtnlgr8mwy6nlt0vztv3qqm");
        assert_eq!(
            &pub_k.operator_address_public_key(prefix)?,
            "terravaloperpub1addwnpepqt8ha594svjn3nvfk4ggfn5n8xd3sm3cz6ztxyugwcuqzsuuhhfq5y7accr"
        );
        assert_eq!(
            &pub_k.application_public_key(prefix)?,
            "terrapub1addwnpepqt8ha594svjn3nvfk4ggfn5n8xd3sm3cz6ztxyugwcuqzsuuhhfq5nwzrf9"
        );

        Ok(())
    }

    #[cfg(feature = "eth")]
    #[test]
    pub fn inj() -> StdResult<()> {
        let str_1: &str = "across left ignore gold echo argue track joy hire release captain enforce hotel wide flash hotel brisk joke midnight duck spare drop chronic stool";
        let coin_type: u32 = 118;
        let prefix = "juno";
        let secp = Secp256k1::new();
        let pk = PrivateKey::from_words(&secp, str_1, 0, 0, coin_type)?;
        let pub_k = pk.public_key(&secp);

        let account = pub_k.account(prefix)?;
        assert_eq!(&account, "juno1jdpunqljj5xypxk6f7dnpga6cjfatwu6vfuyrq");
        // juno1jdpunqljj5xypxk6f7dnpga6cjfatwu6vfuyrq

        // Coin type 60 is a bit peculiar, because of how injective derives addresses : https://docs.injective.network/learn/basic-concepts/accounts/
        let coin_type: u32 = 60;
        let prefix = "inj";
        let pk = PrivateKey::from_words(&secp, str_1, 0, 0, coin_type)?;
        let pub_k = pk.public_key(&secp);

        let account = pub_k.account(prefix)?;
        assert_eq!(&account, "inj1u4f9tvhkltksfr5ezz5cfe8fcsl9k5t5ycjhat");
        // inj1u4f9tvhkltksfr5ezz5cfe8fcsl9k5t5ycjhat

        Ok(())
    }

    // #[test]
    // pub fn test_sign() -> StdResult<()> {
    //     // This test is using message from python SDK.. so these keys generate same sigs as they do.
    //     let str_1 =  "island relax shop such yellow opinion find know caught erode blue dolphin behind coach tattoo light focus snake common size analyst imitate employ walnut";
    //     let coin_type: u32 = 330;
    //     let secp = Secp256k1::new();
    //     let pk = PrivateKey::from_words(&secp, str_1, 0, 0, coin_type)?;
    //     let _pub_k = pk.public_key(&secp);
    //     let to_sign = r#"{"account_number":"45","chain_id":"columbus-3-testnet","fee":{"amount":[{"amount":"698","denom":"uluna"}],"gas":"46467"},"memo":"","msgs":[{"type":"bank/MsgSend","value":{"amount":[{"amount":"100000000","denom":"uluna"}],"from_address":"terra1n3g37dsdlv7ryqftlkef8mhgqj4ny7p8v78lg7","to_address":"terra1wg2mlrxdmnnkkykgqg4znky86nyrtc45q336yv"}}],"sequence":"0"}"#;

    //     let sig = pk.sign(&secp, to_sign)?;

    //     assert_eq!(
    //         sig.pub_key.value,
    //         "AiMzHaA2bvnDXfHzkjMM+vkSE/p0ymBtAFKUnUtQAeXe"
    //     );
    //     assert_eq!(sig.signature, "FJKAXRxNB5ruqukhVqZf3S/muZEUmZD10fVmWycdVIxVWiCXXFsUy2VY2jINEOUGNwfrqEZsT2dUfAvWj8obLg==");

    //     Ok(())
    // }
}
