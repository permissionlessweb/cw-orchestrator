use std::{cmp::min, time::Duration};

use crate::{
    cosmos_modules, env::DaemonEnvVars, error::DaemonError, senders::query::QuerySender,
    tx_resp::CosmTxResponse, DaemonBase,
};

use cosmrs::proto::tendermint::types::Block;

use cosmrs::{
    proto::cosmos::{
        base::query::v1beta1::PageRequest,
        tx::v1beta1::{OrderBy, SimulateResponse},
    },
    tendermint::Time,
};
use cosmwasm_std::BlockInfo;
use cw_orch_core::{
    environment::{NodeQuerier, Querier, QuerierGetter},
    log::query_target,
};
use tokio::runtime::Handle;
use tonic::transport::Channel;

/// Querier for the Tendermint node.
/// Supports queries for block and tx information
/// All the async function are prefixed with `_`
pub struct Node {
    pub channel: Channel,
    pub rt_handle: Option<Handle>,
}

impl Node {
    pub fn new<Sender: QuerySender>(daemon: &DaemonBase<Sender>) -> Self {
        Self {
            channel: daemon.channel(),
            rt_handle: Some(daemon.rt_handle.clone()),
        }
    }
    pub fn new_async(channel: Channel) -> Self {
        Self {
            channel,
            rt_handle: None,
        }
    }
}

impl<Sender: QuerySender> QuerierGetter<Node> for DaemonBase<Sender> {
    fn querier(&self) -> Node {
        Node::new(self)
    }
}

impl Querier for Node {
    type Error = DaemonError;
}

impl Node {
    /// Returns node info
    pub async fn _info(
        &self,
    ) -> Result<cosmos_modules::tendermint::GetNodeInfoResponse, DaemonError> {
        let mut client =
            cosmos_modules::tendermint::service_client::ServiceClient::new(self.channel.clone());

        let resp = client
            .get_node_info(cosmos_modules::tendermint::GetNodeInfoRequest {})
            .await?
            .into_inner();

        Ok(resp)
    }

    /// Queries node syncing
    pub async fn _syncing(&self) -> Result<bool, DaemonError> {
        let mut client =
            cosmos_modules::tendermint::service_client::ServiceClient::new(self.channel.clone());

        let resp = client
            .get_syncing(cosmos_modules::tendermint::GetSyncingRequest {})
            .await?
            .into_inner();

        Ok(resp.syncing)
    }

    /// Returns latests block information
    pub async fn _latest_block(&self) -> Result<Block, DaemonError> {
        let mut client =
            cosmos_modules::tendermint::service_client::ServiceClient::new(self.channel.clone());

        let resp = client
            .get_latest_block(cosmos_modules::tendermint::GetLatestBlockRequest {})
            .await?
            .into_inner();

        resp.block
            .ok_or_else(|| DaemonError::StdErr("Block not found in response".to_string()))
    }

    /// Returns block information fetched by height
    pub async fn _block_by_height(&self, height: u64) -> Result<Block, DaemonError> {
        let mut client =
            cosmos_modules::tendermint::service_client::ServiceClient::new(self.channel.clone());

        let resp = client
            .get_block_by_height(cosmos_modules::tendermint::GetBlockByHeightRequest {
                height: height as i64,
            })
            .await?
            .into_inner();

        resp.block
            .ok_or_else(|| DaemonError::StdErr("Block not found in response".to_string()))
    }

    /// Return the average block time for the last 50 blocks or since inception
    /// This is used to estimate the time when a tx will be included in a block
    pub async fn _average_block_speed(
        &self,
        multiplier: Option<f32>,
    ) -> Result<Duration, DaemonError> {
        // get latest block time and height
        let mut latest_block = self._latest_block().await?;
        let header = latest_block.header.ok_or_else(|| DaemonError::StdErr("Block header not found".to_string()))?;
        let proto_time = header.time.ok_or_else(|| DaemonError::StdErr("Block time not found".to_string()))?;
        let latest_block_time = Time::from_unix_timestamp(proto_time.seconds, proto_time.nanos as u32)?;
        let mut latest_block_height = header.height;

        while latest_block_height <= 1 {
            // wait to get some blocks
            tokio::time::sleep(Duration::from_secs(1)).await;
            latest_block = self._latest_block().await?;
            latest_block_height = latest_block.header.ok_or_else(|| DaemonError::StdErr("Block header not found".to_string()))?.height;
        }

        // let avg period
        let avg_period = min(latest_block_height - 1, 50);

        // get block time for block avg_period blocks ago
        let block_avg_period_ago = self
            ._block_by_height((latest_block_height - avg_period) as u64)
            .await?;
        let proto_time_ago = block_avg_period_ago.header.ok_or_else(|| DaemonError::StdErr("Block header not found".to_string()))?.time.ok_or_else(|| DaemonError::StdErr("Block time not found".to_string()))?;
        let block_avg_period_ago_time = Time::from_unix_timestamp(proto_time_ago.seconds, proto_time_ago.nanos as u32)?;

        // calculate average block time
        let average_block_time = latest_block_time.duration_since(block_avg_period_ago_time)?;
        let average_block_time = average_block_time.div_f64(avg_period as f64);

        // multiply by multiplier if provided
        let average_block_time = match multiplier {
            Some(multiplier) => average_block_time.mul_f32(multiplier),
            None => average_block_time,
        };

        Ok(average_block_time)
    }

    /// Returns latests validator set
    pub async fn _latest_validator_set(
        &self,
        pagination: Option<PageRequest>,
    ) -> Result<cosmos_modules::tendermint::GetLatestValidatorSetResponse, DaemonError> {
        let mut client =
            cosmos_modules::tendermint::service_client::ServiceClient::new(self.channel.clone());

        let resp = client
            .get_latest_validator_set(cosmos_modules::tendermint::GetLatestValidatorSetRequest {
                pagination,
            })
            .await?
            .into_inner();

        Ok(resp)
    }

    /// Returns latests validator set fetched by height
    pub async fn _validator_set_by_height(
        &self,
        height: i64,
        pagination: Option<PageRequest>,
    ) -> Result<cosmos_modules::tendermint::GetValidatorSetByHeightResponse, DaemonError> {
        let mut client =
            cosmos_modules::tendermint::service_client::ServiceClient::new(self.channel.clone());

        let resp = client
            .get_validator_set_by_height(
                cosmos_modules::tendermint::GetValidatorSetByHeightRequest { height, pagination },
            )
            .await?
            .into_inner();

        Ok(resp)
    }

    /// Returns current block height
    pub async fn _block_height(&self) -> Result<u64, DaemonError> {
        let block = self._latest_block().await?;
        let header = block.header.ok_or_else(|| DaemonError::StdErr("Block header not found".to_string()))?;
        Ok(header.height as u64)
    }

    /// Returns the block timestamp (since unix epoch) in nanos
    pub async fn _block_time(&self) -> Result<u128, DaemonError> {
        let block = self._latest_block().await?;
        let header = block.header.ok_or_else(|| DaemonError::StdErr("Block header not found".to_string()))?;
        let proto_time = header.time.ok_or_else(|| DaemonError::StdErr("Block time not found".to_string()))?;
        let time = Time::from_unix_timestamp(proto_time.seconds, proto_time.nanos as u32)?;
        Ok(time.duration_since(Time::unix_epoch())?.as_nanos())
    }

    /// Simulate TX
    pub async fn _simulate_tx(&self, tx_bytes: Vec<u8>) -> Result<u64, DaemonError> {
        let mut client =
            cosmos_modules::tx::service_client::ServiceClient::new(self.channel.clone());
        #[allow(deprecated)]
        let resp: SimulateResponse = client
            .simulate(cosmos_modules::tx::SimulateRequest { tx: None, tx_bytes })
            .await?
            .into_inner();
        let gas_used = resp.gas_info.unwrap().gas_used;
        Ok(gas_used)
    }

    /// Returns all the block info
    pub async fn _block_info(&self) -> Result<cosmwasm_std::BlockInfo, DaemonError> {
        let block = self._latest_block().await?;

        block_to_block_info(block)
    }

    /// Find TX by hash
    pub async fn _find_tx(&self, hash: String) -> Result<CosmTxResponse, DaemonError> {
        self._find_tx_with_retries(hash, DaemonEnvVars::max_tx_query_retries())
            .await
    }

    /// Find TX by hash with a given amount of retries
    pub async fn _find_tx_with_retries(
        &self,
        hash: String,
        retries: usize,
    ) -> Result<CosmTxResponse, DaemonError> {
        let mut client =
            cosmos_modules::tx::service_client::ServiceClient::new(self.channel.clone());

        let request = cosmos_modules::tx::GetTxRequest { hash: hash.clone() };
        let mut block_speed = self._average_block_speed(Some(0.7)).await?;
        let max_block_time = DaemonEnvVars::max_block_time();
        if let Some(max_time) = max_block_time {
            block_speed = block_speed.min(max_time);
        } else {
            let min_block_time = DaemonEnvVars::min_block_time();
            block_speed = block_speed.max(min_block_time);
        }

        for _ in 0..retries {
            match client.get_tx(request.clone()).await {
                Ok(tx) => {
                    let resp = tx.into_inner().tx_response.unwrap().into();
                    log::debug!(target: &query_target(), "TX found: {:?}", resp);
                    return Ok(resp);
                }
                Err(err) => {
                    // increase wait time
                    block_speed = block_speed.mul_f64(1.6);
                    if let Some(max_time) = max_block_time {
                        block_speed = block_speed.min(max_time)
                    }
                    log::debug!(target: &query_target(), "TX not found with error: {:?}", err);
                    log::debug!(target: &query_target(), "Waiting {} milli-seconds", block_speed.as_millis());
                    tokio::time::sleep(block_speed).await;
                }
            }
        }

        // return error if tx not found by now
        Err(DaemonError::TXNotFound(hash, retries))
    }

    /// Find TX by events
    pub async fn _find_tx_by_events(
        &self,
        events: Vec<String>,
        page: Option<u64>,
        order_by: Option<OrderBy>,
    ) -> Result<Vec<CosmTxResponse>, DaemonError> {
        self._find_tx_by_events_with_retries(
            events,
            page,
            order_by,
            false,
            DaemonEnvVars::max_tx_query_retries(),
        )
        .await
    }

    /// Find Tx by events
    /// This function will consider that no transactions found is an error
    /// This either returns a non empty vector or errors
    pub async fn _find_some_tx_by_events(
        &self,
        events: Vec<String>,
        page: Option<u64>,
        order_by: Option<OrderBy>,
    ) -> Result<Vec<CosmTxResponse>, DaemonError> {
        self._find_tx_by_events_with_retries(
            events,
            page,
            order_by,
            true,
            DaemonEnvVars::max_tx_query_retries(),
        )
        .await
    }

    /// Find TX by events with  :
    /// 1. Specify if an empty tx object is a valid response
    /// 2. Specify a given amount of retries
    pub async fn _find_tx_by_events_with_retries(
        &self,
        events: Vec<String>,
        page: Option<u64>,
        order_by: Option<OrderBy>,
        retry_on_empty: bool,
        retries: usize,
    ) -> Result<Vec<CosmTxResponse>, DaemonError> {
        let mut client = cosmrs::proto::cosmos::tx::v1beta1::service_client::ServiceClient::new(
            self.channel.clone(),
        );

        #[allow(deprecated)]
        let request = cosmrs::proto::cosmos::tx::v1beta1::GetTxsEventRequest {
            events: events.clone(),
            pagination: None,
            order_by: order_by.unwrap_or(OrderBy::Desc).into(),
            page: page.unwrap_or(0),
            limit: 100,
            query: events.join(" AND "),
        };

        for _ in 0..retries {
            match client.get_txs_event(request.clone()).await {
                Ok(tx) => {
                    let resp = tx.into_inner().tx_responses;
                    if retry_on_empty && resp.is_empty() {
                        log::debug!(target: &query_target(), "No TX found with events {:?}", events);
                        log::debug!(target: &query_target(), "Waiting 10s");
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    } else {
                        log::debug!(
                            target: &query_target(),
                            "TX found by events: {:?}",
                            resp.iter().map(|t| t.txhash.clone())
                        );
                        return Ok(resp.iter().map(|r| r.clone().into()).collect());
                    }
                }
                Err(err) => {
                    log::debug!(target: &query_target(), "TX not found with error: {:?}", err);
                    log::debug!(target: &query_target(), "Waiting 10s");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        }
        // return error if tx not found by now
        Err(DaemonError::TXNotFound(
            format!("with events {:?}", events),
            DaemonEnvVars::max_tx_query_retries(),
        ))
    }
}

// Now we define traits

impl NodeQuerier for Node {
    type Response = CosmTxResponse;

    fn latest_block(&self) -> Result<cosmwasm_std::BlockInfo, Self::Error> {
        self.rt_handle
            .as_ref()
            .ok_or(DaemonError::QuerierNeedRuntime)?
            .block_on(self._block_info())
    }

    fn block_by_height(&self, height: u64) -> Result<cosmwasm_std::BlockInfo, Self::Error> {
        let block = self
            .rt_handle
            .as_ref()
            .ok_or(DaemonError::QuerierNeedRuntime)?
            .block_on(self._block_by_height(height))?;

        block_to_block_info(block)
    }

    fn block_height(&self) -> Result<u64, Self::Error> {
        self.rt_handle
            .as_ref()
            .ok_or(DaemonError::QuerierNeedRuntime)?
            .block_on(self._block_height())
    }

    fn block_time(&self) -> Result<u128, Self::Error> {
        self.rt_handle
            .as_ref()
            .ok_or(DaemonError::QuerierNeedRuntime)?
            .block_on(self._block_time())
    }

    fn simulate_tx(&self, tx_bytes: Vec<u8>) -> Result<u64, Self::Error> {
        self.rt_handle
            .as_ref()
            .ok_or(DaemonError::QuerierNeedRuntime)?
            .block_on(self._simulate_tx(tx_bytes))
    }

    fn find_tx(&self, hash: String) -> Result<Self::Response, Self::Error> {
        self.rt_handle
            .as_ref()
            .ok_or(DaemonError::QuerierNeedRuntime)?
            .block_on(self._find_tx(hash))
    }
}

fn block_to_block_info(block: Block) -> Result<BlockInfo, DaemonError> {
    let header = block.header.ok_or_else(|| DaemonError::StdErr("Block header not found".to_string()))?;
    let proto_time = header.time.ok_or_else(|| DaemonError::StdErr("Block time not found".to_string()))?;
    let time_timestamp = Time::from_unix_timestamp(proto_time.seconds, proto_time.nanos as u32)?;
    let since_epoch = time_timestamp.duration_since(Time::unix_epoch())?;
    let time = cosmwasm_std::Timestamp::from_nanos(since_epoch.as_nanos() as u64);
    Ok(cosmwasm_std::BlockInfo {
        height: header.height as u64,
        time,
        chain_id: header.chain_id,
    })
}
