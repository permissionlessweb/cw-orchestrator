use std::{str::FromStr, sync::Arc};

use cosmrs::AccountId;
use cosmwasm_std::Addr;
use cw_orch_core::environment::ChainInfoOwned;

use crate::{DaemonError, Wallet};

use super::{builder::SenderBuilder, CosmosSender};

/// Options for how txs should be constructed for this sender.
#[derive(Default, Clone)]
#[non_exhaustive]
pub struct CosmosOptions {
    pub authz_granter: Option<Addr>,
    pub fee_granter: Option<Addr>,
    pub hd_index: Option<u32>,
    /// Used to derive the private key
    pub(crate) key: CosmosWalletKey,
}

#[derive(Default, Clone)]
pub enum CosmosWalletKey {
    Mnemonic(String),
    /// BIP32 seed. Derived at `m/44'/coin_type'/0'/0/index`. Not a keyring export.
    RawKey(Vec<u8>),
    /// Already-derived 32-byte secp256k1 secret, as returned by a keyring hex export.
    Secp256k1(Vec<u8>),
    #[default]
    Env,
}

impl CosmosOptions {
    pub fn check(&self) -> Result<(), DaemonError> {
        if let Some(addr) = &self.authz_granter {
            AccountId::from_str(addr.as_str())?;
        }

        if let Some(addr) = &self.fee_granter {
            AccountId::from_str(addr.as_str())?;
        }

        Ok(())
    }

    pub fn authz_granter(mut self, granter: &Addr) -> Self {
        self.authz_granter = Some(granter.clone());
        self
    }

    pub fn fee_granter(mut self, granter: &Addr) -> Self {
        self.fee_granter = Some(granter.clone());
        self
    }

    pub fn hd_index(mut self, index: u32) -> Self {
        self.hd_index = Some(index);
        self
    }

    pub fn mnemonic(mut self, mnemonic: impl Into<String>) -> Self {
        self.key = CosmosWalletKey::Mnemonic(mnemonic.into());
        self
    }

    /// Sign with an already-derived secp256k1 secret. Does not HD-derive it.
    pub fn secp256k1_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.key = CosmosWalletKey::Secp256k1(secret.into());
        self
    }

    pub fn set_authz_granter(&mut self, granter: &Addr) {
        self.authz_granter = Some(granter.clone());
    }

    pub fn set_fee_granter(&mut self, granter: &Addr) {
        self.fee_granter = Some(granter.clone());
    }

    pub fn set_hd_index(&mut self, index: u32) {
        self.hd_index = Some(index);
    }

    pub fn set_mnemonic(&mut self, mnemonic: impl Into<String>) {
        self.key = CosmosWalletKey::Mnemonic(mnemonic.into());
    }
}

impl SenderBuilder for CosmosOptions {
    type Error = DaemonError;
    type Sender = Wallet;

    async fn build(&self, chain_info: &Arc<ChainInfoOwned>) -> Result<Self::Sender, Self::Error> {
        CosmosSender::new(chain_info, self.clone()).await
    }
}
