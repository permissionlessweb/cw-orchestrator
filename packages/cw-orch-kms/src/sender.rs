//! Account pubkey identifies the smart account. Signature bytes are the
//! terp-frost quorum over the SIGN_MODE_DIRECT sign doc.

use std::sync::Arc;

use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountRequest};
use cosmrs::proto::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmrs::proto::cosmos::tx::v1beta1::{BroadcastMode, BroadcastTxRequest};
use cosmrs::proto::traits::Message;
use cosmrs::tendermint::chain::Id;
use cosmrs::proto::cosmos::tx::v1beta1::TxRaw;
use cosmrs::tx::{Body, ModeInfo, Raw, SignDoc, SignMode, SignerInfo, SignerPublicKey};
use cosmrs::AccountId;
use cosmrs::Any;
use cw_orch_core::environment::ChainInfoOwned;
use cw_orch_daemon::queriers::Node;
use cw_orch_daemon::senders::builder::SenderBuilder;
use cw_orch_daemon::senders::query::QuerySender;
use cw_orch_daemon::senders::sign::Signer;
use cw_orch_daemon::senders::tx::TxSender;
use cw_orch_daemon::{CosmTxResponse, DaemonError, GrpcChannel, TxBuilder, Wallet};
use tonic::transport::Channel;

use crate::session::FrostSession;
use crate::tx_extension;

const SUBMISSION_GAS_BUFFER: f64 = 1.4;

#[derive(Clone)]
pub struct FrostKmsOptions {
    pub account_id: AccountId,
    pub public_key: SignerPublicKey,
    pub authenticator_id: u64,
    pub session: FrostSession,
}

impl FrostKmsOptions {
    pub fn from_wallet(
        wallet: &Wallet,
        authenticator_id: u64,
        session: FrostSession,
    ) -> Result<Self, DaemonError> {
        let public_key = wallet.public_key().ok_or_else(|| {
            DaemonError::StdErr(format!(
                "frost kms account {} has no secp256k1 public key",
                wallet.address()
            ))
        })?;
        Ok(Self {
            account_id: Signer::account_id(wallet),
            public_key,
            authenticator_id,
            session,
        })
    }
}

#[derive(Clone)]
pub struct FrostKmsSender {
    account_id: AccountId,
    public_key: SignerPublicKey,
    authenticator_id: u64,
    session: FrostSession,
    chain_info: Arc<ChainInfoOwned>,
    grpc_channel: Channel,
}

impl SenderBuilder for FrostKmsOptions {
    type Error = DaemonError;
    type Sender = FrostKmsSender;

    async fn build(&self, chain_info: &Arc<ChainInfoOwned>) -> Result<Self::Sender, Self::Error> {
        let grpc_channel = GrpcChannel::from_chain_info(chain_info.as_ref()).await?;
        Ok(FrostKmsSender {
            account_id: self.account_id.clone(),
            public_key: self.public_key.clone(),
            authenticator_id: self.authenticator_id,
            session: self.session.clone(),
            chain_info: chain_info.clone(),
            grpc_channel,
        })
    }
}

impl QuerySender for FrostKmsSender {
    type Error = DaemonError;
    type Options = FrostKmsOptions;

    fn channel(&self) -> Channel {
        self.grpc_channel.clone()
    }
}

impl FrostKmsSender {
    pub fn group_vk(&self) -> &str {
        self.session.group_vk()
    }

    async fn account(&self) -> Result<BaseAccount, DaemonError> {
        let mut client =
            cosmrs::proto::cosmos::auth::v1beta1::query_client::QueryClient::new(self.channel());
        let resp = client
            .account(QueryAccountRequest {
                address: self.account_id.to_string(),
            })
            .await
            .map_err(|err| {
                DaemonError::StdErr(format!(
                    "frost kms account query failed for {}: {err}",
                    self.account_id
                ))
            })?
            .into_inner();
        let any = resp.account.ok_or_else(|| {
            DaemonError::StdErr(format!(
                "frost kms account {} is not on chain",
                self.account_id
            ))
        })?;
        BaseAccount::decode(any.value.as_slice()).map_err(|err| {
            DaemonError::StdErr(format!(
                "frost kms account {} is not a BaseAccount: {err}",
                self.account_id
            ))
        })
    }

    fn raw_tx(
        &self,
        body: &Body,
        sequence: u64,
        account_number: u64,
        gas_limit: u64,
        fee_amount: u128,
        signature: Vec<u8>,
    ) -> Result<(Raw, Vec<u8>), DaemonError> {
        let fee = TxBuilder::build_fee(
            fee_amount,
            &self.chain_info.gas_denom,
            gas_limit,
            None,
        )?;
        let auth_info = SignerInfo {
            public_key: Some(self.public_key.clone()),
            mode_info: ModeInfo::single(SignMode::Direct),
            sequence,
        }
        .auth_info(fee);
        let sign_doc = SignDoc::new(
            body,
            &auth_info,
            &Id::try_from(self.chain_info.chain_id.clone())?,
            account_number,
        )?;
        let sign_doc_bytes = sign_doc.clone().into_bytes()?;
        Ok((
            Raw::from(TxRaw {
                body_bytes: sign_doc.body_bytes,
                auth_info_bytes: sign_doc.auth_info_bytes,
                signatures: vec![signature],
            }),
            sign_doc_bytes,
        ))
    }
}

impl TxSender for FrostKmsSender {
    fn account_id(&self) -> AccountId {
        self.account_id.clone()
    }

    async fn commit_tx_any(
        &self,
        msgs: Vec<Any>,
        memo: Option<&str>,
    ) -> Result<CosmTxResponse, DaemonError> {
        let node = Node::new_async(self.channel());
        let timeout_height = node._block_height().await? + 10;
        let mut body = Body::new(msgs, memo.unwrap_or("frost kms"), timeout_height as u32);
        body.non_critical_extension_options
            .push(tx_extension::extension_any(self.authenticator_id));

        let account = self.account().await?;
        let (simulated, _) = self.raw_tx(
            &body,
            account.sequence,
            account.account_number,
            0,
            0,
            Vec::new(),
        )?;
        let gas_used = node._simulate_tx(simulated.to_bytes()?).await.map_err(|err| {
            DaemonError::StdErr(format!(
                "frost kms simulate failed for {} authenticator {}: {err}",
                self.account_id, self.authenticator_id
            ))
        })?;
        let gas_limit = ((gas_used as f64) * SUBMISSION_GAS_BUFFER).ceil() as u64;
        let fee_amount = ((gas_limit as f64) * self.chain_info.gas_price).ceil() as u128;
        let (_, sign_doc_bytes) = self.raw_tx(
            &body,
            account.sequence,
            account.account_number,
            gas_limit,
            fee_amount,
            Vec::new(),
        )?;
        let signature = self
            .session
            .sign(&sign_doc_bytes)
            .map_err(DaemonError::StdErr)?;
        let (raw, _) = self.raw_tx(
            &body,
            account.sequence,
            account.account_number,
            gas_limit,
            fee_amount,
            signature.to_vec(),
        )?;
        let mut client = ServiceClient::new(self.channel());
        let broadcast = client
            .broadcast_tx(BroadcastTxRequest {
                tx_bytes: raw.to_bytes()?,
                mode: BroadcastMode::Sync.into(),
            })
            .await
            .map_err(|err| {
                DaemonError::StdErr(format!(
                    "frost kms broadcast failed for {}: {err}",
                    self.account_id
                ))
            })?
            .into_inner()
            .tx_response
            .ok_or_else(|| {
                DaemonError::StdErr("frost kms broadcast returned no tx response".into())
            })?;
        if broadcast.code != 0 {
            return Err(DaemonError::TxFailed {
                code: broadcast.code as usize,
                reason: format!(
                    "frost kms broadcast code {} for {}: {}",
                    broadcast.code, self.account_id, broadcast.raw_log
                ),
            });
        }
        let found = node._find_tx(broadcast.txhash).await?;
        if found.code != 0 {
            return Err(DaemonError::TxFailed {
                code: found.code,
                reason: format!(
                    "frost kms tx code {} for {}: {}",
                    found.code, self.account_id, found.raw_log
                ),
            });
        }
        Ok(found)
    }

    async fn bank_send(
        &self,
        recipient: &cosmwasm_std::Addr,
        coins: &[cosmwasm_std::Coin],
    ) -> Result<CosmTxResponse, DaemonError> {
        let amount = cw_orch_daemon::parse_cw_coins(coins)?;
        let msg = cosmrs::bank::MsgSend {
            from_address: self.account_id.clone(),
            to_address: recipient.as_str().parse()?,
            amount,
        };
        self.commit_tx(vec![msg], Some("frost kms bank send")).await
    }
}
