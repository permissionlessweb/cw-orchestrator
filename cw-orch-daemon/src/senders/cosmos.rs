use super::{
    cosmos_options::CosmosWalletKey,
    query::QuerySender,
    sign::{Signer, SigningAccount},
    tx::TxSender,
};
use crate::{
    cosmos_modules::{self, auth::BaseAccount},
    env::{DaemonEnvVars, LOCAL_MNEMONIC_ENV_NAME, MAIN_MNEMONIC_ENV_NAME, TEST_MNEMONIC_ENV_NAME},
    error::DaemonError,
    keys::private::PrivateKey,
    proto::injective::{InjectiveEthAccount, ETHEREUM_COIN_TYPE},
    queriers::{Bank, Node},
    tx_builder::TxBuilder,
    tx_resp::CosmTxResponse,
    upload_wasm, CosmosOptions, GrpcChannel,
};
use bitcoin::secp256k1::{All, Secp256k1, Signing};
use cosmos_modules::vesting::PeriodicVestingAccount;
use cosmrs::{
    crypto::secp256k1::SigningKey,
    proto::traits::Message,
    tendermint::chain::Id,
    tx::{self, Fee, ModeInfo, Msg, Raw, SignDoc, SignMode, SignerInfo, SignerPublicKey},
    AccountId, Any,
};
use cosmwasm_std::{coin, Addr, Coin};
use cw_orch_core::{
    contract::WasmPath,
    environment::{AccessConfig, ChainInfoOwned, ChainKind},
    CoreEnvVars, CwEnvError,
};
use prost::Message as _;
use std::sync::Arc;
use tonic::transport::Channel;

#[cfg(feature = "eth")]
use crate::proto::injective::InjectiveSigner;

const GAS_BUFFER: f64 = 1.3;
const BUFFER_THRESHOLD: u64 = 200_000;
const SMALL_GAS_BUFFER: f64 = 1.4;

/// A wallet is a sender of transactions, can be safely cloned and shared within the same thread.
pub type Wallet = CosmosSender<All>;

/// Signer of the transactions and helper for address derivation
/// This is the main interface for simulating and signing transactions
#[derive(Clone)]
pub struct CosmosSender<C: Signing + Clone> {
    pub private_key: PrivateKey,
    /// gRPC channel
    pub grpc_channel: Channel,
    /// Information about the chain
    pub chain_info: Arc<ChainInfoOwned>,
    pub(crate) options: CosmosOptions,
    pub secp: Secp256k1<C>,
}

impl Wallet {
    pub async fn new(
        chain_info: &Arc<ChainInfoOwned>,
        options: CosmosOptions,
    ) -> Result<Wallet, DaemonError> {
        let secp = Secp256k1::new();

        let pk_from_mnemonic = |mnemonic: &str| -> Result<PrivateKey, DaemonError> {
            PrivateKey::from_words(
                &secp,
                mnemonic,
                0,
                options.hd_index.unwrap_or(0),
                chain_info.network_info.coin_type,
            )
        };

        let pk: PrivateKey = match &options.key {
            CosmosWalletKey::Mnemonic(mnemonic) => pk_from_mnemonic(mnemonic)?,
            CosmosWalletKey::Env => {
                let mnemonic = get_mnemonic_env(&chain_info.kind)?;
                pk_from_mnemonic(&mnemonic)?
            }
            CosmosWalletKey::RawKey(bytes) => PrivateKey::from_raw_key(
                &secp,
                bytes,
                0,
                options.hd_index.unwrap_or(0),
                chain_info.network_info.coin_type,
            )?,
        };

        // ensure address is valid
        AccountId::new(
            &chain_info.network_info.pub_address_prefix,
            &pk.public_key(&secp).raw_address.unwrap(),
        )?;

        Ok(Self {
            chain_info: chain_info.clone(),
            grpc_channel: GrpcChannel::from_chain_info(chain_info.as_ref()).await?,
            private_key: pk,
            secp,
            options,
        })
    }

    /// Construct a new Sender from a mnemonic
    pub async fn from_mnemonic(
        chain_info: &Arc<ChainInfoOwned>,
        mnemonic: &str,
    ) -> Result<Wallet, DaemonError> {
        let options = CosmosOptions {
            key: CosmosWalletKey::Mnemonic(mnemonic.to_string()),
            ..Default::default()
        };
        Self::new(chain_info, options).await
    }

    pub fn channel(&self) -> Channel {
        self.grpc_channel.clone()
    }

    pub fn options(&self) -> CosmosOptions {
        self.options.clone()
    }

    pub fn public_key(&self) -> Option<SignerPublicKey> {
        self.private_key.get_signer_public_key(&self.secp)
    }

    /// Replaces the private key that the [CosmosSender] is using with key derived from the provided 24-word mnemonic.
    /// If you want more control over the derived private key, use [Self::set_private_key]
    pub fn set_mnemonic(&mut self, mnemonic: impl Into<String>) -> Result<(), DaemonError> {
        let secp = Secp256k1::new();

        let pk = PrivateKey::from_words(
            &secp,
            &mnemonic.into(),
            0,
            self.options.hd_index.unwrap_or(0),
            self.chain_info.network_info.coin_type,
        )?;
        self.set_private_key(pk);
        Ok(())
    }

    /// Replaces the private key the sender is using
    /// You can use a mnemonic to overwrite the key using [Self::set_mnemonic]
    pub fn set_private_key(&mut self, private_key: PrivateKey) {
        self.private_key = private_key
    }

    pub fn set_authz_granter(&mut self, granter: &Addr) {
        self.options.authz_granter = Some(granter.to_owned());
    }

    pub fn set_fee_granter(&mut self, granter: &Addr) {
        self.options.fee_granter = Some(granter.to_owned());
    }

    pub fn pub_addr_str(&self) -> String {
        Signer::account_id(self).to_string()
    }

    /// Computes the gas needed for submitting a transaction
    pub async fn calculate_gas(
        &self,
        tx_body: &tx::Body,
        sequence: u64,
        account_number: u64,
    ) -> Result<u64, DaemonError> {
        let fee = TxBuilder::build_fee(
            0u8,
            &self.chain_info.gas_denom,
            0,
            self.options.fee_granter.clone(),
        )?;

        let auth_info = SignerInfo {
            public_key: self.private_key.get_signer_public_key(&self.secp),
            mode_info: ModeInfo::single(SignMode::Direct),
            sequence,
        }
        .auth_info(fee);

        let sign_doc = SignDoc::new(
            tx_body,
            &auth_info,
            &Id::try_from(self.chain_info.chain_id.to_string())?,
            account_number,
        )?;

        let tx_raw = self.sign(sign_doc)?;

        Node::new_async(self.channel())
            ._simulate_tx(tx_raw.to_bytes()?)
            .await
    }

    /// Simulates the transaction against an actual node
    /// Returns the gas needed as well as the fee needed for submitting a transaction
    pub async fn simulate(
        &self,
        msgs: Vec<Any>,
        memo: Option<&str>,
    ) -> Result<(u64, Coin), DaemonError> {
        let timeout_height = Node::new_async(self.channel())._block_height().await? + 10u64;

        let tx_body = TxBuilder::build_body(msgs, memo, timeout_height);

        let tx_builder = TxBuilder::new(tx_body);

        let gas_needed = tx_builder.simulate(self).await?;

        let (gas_for_submission, fee_amount) = self.get_fee_from_gas(gas_needed)?;
        let expected_fee = coin(fee_amount, self.get_fee_token());
        // During simulation, we also make sure the account has enough balance to submit the transaction
        // This is disabled by an env variable
        if DaemonEnvVars::wallet_balance_assertion() {
            self.assert_wallet_balance(&expected_fee).await?;
        }

        Ok((gas_for_submission, expected_fee))
    }

    pub async fn commit_tx<T: Msg>(
        &self,
        msgs: Vec<T>,
        memo: Option<&str>,
    ) -> Result<CosmTxResponse, DaemonError> {
        let msgs = msgs
            .into_iter()
            .map(Msg::into_any)
            .collect::<Result<Vec<Any>, _>>()
            .unwrap();

        self.commit_tx_any(msgs, memo).await
    }

    pub async fn base_account(&self) -> Result<BaseAccount, DaemonError> {
        let addr = self.address().to_string();

        let mut client = cosmos_modules::auth::query_client::QueryClient::new(self.channel());

        let resp = client
            .account(cosmos_modules::auth::QueryAccountRequest { address: addr })
            .await?
            .into_inner();

        let account = resp.account.unwrap().value;

        let acc = if let Ok(acc) = BaseAccount::decode(account.as_ref()) {
            acc
        } else if let Ok(acc) = PeriodicVestingAccount::decode(account.as_ref()) {
            // try vesting account, (used by Terra2)
            acc.base_vesting_account.unwrap().base_account.unwrap()
        } else if let Ok(acc) = InjectiveEthAccount::decode(account.as_ref()) {
            acc.base_account.unwrap()
        } else {
            return Err(DaemonError::StdErr(
                "Unknown account type returned from QueryAccountRequest".into(),
            ));
        };

        Ok(acc)
    }

    /// Allows for checking wether the sender is able to broadcast a transaction that necessitates the provided `gas`
    pub async fn has_enough_balance_for_gas(&self, gas: u64) -> Result<(), DaemonError> {
        let (_gas_expected, fee_amount) = self.get_fee_from_gas(gas)?;
        let fee_denom = self.get_fee_token();

        self.assert_wallet_balance(&coin(fee_amount, fee_denom))
            .await
    }

    /// Allows checking wether the sender has more funds than the provided `fee` argument
    #[async_recursion::async_recursion(?Send)]
    async fn assert_wallet_balance(&self, fee: &Coin) -> Result<(), DaemonError> {
        let chain_info = self.chain_info.clone();

        let bank = Bank::new_async(self.channel());
        let balance = bank
            ._balance(&self.address(), Some(fee.denom.clone()))
            .await?[0]
            .clone();

        log::debug!(
            "Checking balance {} on chain {}, address {}. Expecting {}{}",
            balance.amount,
            chain_info.chain_id,
            self.address(),
            fee,
            fee.denom
        );

        if balance.amount >= fee.amount {
            log::debug!("The wallet has enough balance to deploy");
            return Ok(());
        }

        // If there is not enough asset balance, we need to warn the user
        log::info!(
            "Not enough funds on chain {} at address {} to deploy the contract. 
                Needed: {}{} but only have: {}.
                Press 'y' when the wallet balance has been increased to resume deployment",
            chain_info.chain_id,
            self.address(),
            fee,
            fee.denom,
            balance
        );

        if CoreEnvVars::manual_interaction() {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.to_lowercase().contains('y') {
                // We retry asserting the balance
                self.assert_wallet_balance(fee).await
            } else {
                Err(DaemonError::NotEnoughBalance {
                    expected: fee.clone(),
                    current: balance,
                })
            }
        } else {
            log::info!("No Manual Interactions, defaulting to 'no'");
            return Err(DaemonError::NotEnoughBalance {
                expected: fee.clone(),
                current: balance,
            });
        }
    }

    pub(crate) fn get_fee_token(&self) -> String {
        self.chain_info.gas_denom.to_string()
    }

    fn cosmos_private_key(&self) -> SigningKey {
        SigningKey::from_slice(&self.private_key.raw_key()).unwrap()
    }

    /// Compute the gas fee from the expected gas in the transaction
    /// Applies a Gas Buffer for including signature verification
    pub(crate) fn get_fee_from_gas(&self, gas: u64) -> Result<(u64, u128), DaemonError> {
        let mut gas_expected = if let Some(gas_buffer) = DaemonEnvVars::gas_buffer() {
            gas as f64 * gas_buffer
        } else if gas < BUFFER_THRESHOLD {
            gas as f64 * SMALL_GAS_BUFFER
        } else {
            gas as f64 * GAS_BUFFER
        };

        let min_gas = DaemonEnvVars::min_gas();
        gas_expected = (min_gas as f64).max(gas_expected);

        let fee_amount = gas_expected * (self.chain_info.gas_price + 0.00001);

        Ok((gas_expected as u64, fee_amount as u128))
    }
}

// Helpers to facilitate some rare operations
impl Wallet {
    /// Uploads the `WasmPath` path specifier on chain.
    /// The resulting code_id can be extracted from the Transaction result using [cw_orch_core::environment::IndexResponse::uploaded_code_id] and returns the resulting code_id
    pub async fn upload_wasm(&self, wasm_path: WasmPath) -> Result<CosmTxResponse, DaemonError> {
        self.upload_with_access_config(wasm_path, None).await
    }

    pub async fn upload_with_access_config(
        &self,
        wasm_path: WasmPath,
        access: Option<AccessConfig>,
    ) -> Result<CosmTxResponse, DaemonError> {
        upload_wasm(self, wasm_path, access).await
    }
}

impl QuerySender for Wallet {
    type Error = DaemonError;
    type Options = CosmosOptions;

    fn channel(&self) -> Channel {
        self.channel()
    }
}

fn get_mnemonic_env(chain_kind: &ChainKind) -> Result<String, CwEnvError> {
    match chain_kind {
        ChainKind::Local => DaemonEnvVars::local_mnemonic(),
        ChainKind::Testnet => DaemonEnvVars::test_mnemonic(),
        ChainKind::Mainnet => DaemonEnvVars::main_mnemonic(),
        _ => None,
    }
    .ok_or(CwEnvError::EnvVarNotPresentNamed(
        get_mnemonic_env_name(chain_kind).to_string(),
    ))
}

fn get_mnemonic_env_name(chain_kind: &ChainKind) -> &str {
    match chain_kind {
        ChainKind::Local => LOCAL_MNEMONIC_ENV_NAME,
        ChainKind::Testnet => TEST_MNEMONIC_ENV_NAME,
        ChainKind::Mainnet => MAIN_MNEMONIC_ENV_NAME,
        _ => panic!("Can't set mnemonic for unspecified chainkind"),
    }
}

impl Signer for Wallet {
    fn sign(&self, sign_doc: SignDoc) -> Result<Raw, DaemonError> {
        let tx_raw = if self.private_key.coin_type == ETHEREUM_COIN_TYPE {
            #[cfg(not(feature = "eth"))]
            panic!(
                "Coin Type {} not supported without eth feature",
                ETHEREUM_COIN_TYPE
            );
            #[cfg(feature = "eth")]
            self.private_key.sign_injective(sign_doc)?
        } else {
            sign_doc.sign(&self.cosmos_private_key())?
        };
        Ok(tx_raw)
    }

    fn chain_id(&self) -> String {
        self.chain_info.chain_id.clone()
    }

    fn signer_info(&self, sequence: u64) -> SignerInfo {
        SignerInfo {
            public_key: self.private_key.get_signer_public_key(&self.secp),
            mode_info: ModeInfo::single(SignMode::Direct),
            sequence,
        }
    }

    fn build_fee(&self, amount: impl Into<u128>, gas_limit: u64) -> Result<Fee, DaemonError> {
        TxBuilder::build_fee(
            amount,
            &self.get_fee_token(),
            gas_limit,
            self.options.fee_granter.clone(),
        )
    }

    async fn signing_account(&self) -> Result<super::sign::SigningAccount, DaemonError> {
        let BaseAccount {
            account_number,
            sequence,
            ..
        } = self.base_account().await?;

        Ok(SigningAccount {
            account_number,
            sequence,
        })
    }

    fn gas_price(&self) -> Result<f64, DaemonError> {
        Ok(self.chain_info.gas_price)
    }

    fn account_id(&self) -> AccountId {
        AccountId::new(
            &self.chain_info.network_info.pub_address_prefix,
            &self.private_key.public_key(&self.secp).raw_address.unwrap(),
        )
        // unwrap as address is validated on construction
        .unwrap()
    }

    fn authz_granter(&self) -> Option<&Addr> {
        self.options.authz_granter.as_ref()
    }
}
