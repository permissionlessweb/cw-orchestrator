use crate::networks::{ChainInfo, ChainKind, NetworkInfo};

pub const TERP_LOCAL_CHAIN_ID: &str = "240u-1";

pub const AKASH_NETWORK: NetworkInfo = NetworkInfo {
    chain_name: "akash",
    pub_address_prefix: "akash",
    coin_type: 118u32,
};

 

pub const AKASH_1: ChainInfo = ChainInfo {
    kind: ChainKind::Mainnet,
    chain_id: "akash-1",
    gas_denom: "uakt",
    gas_price: 0.05,
    grpc_urls: &["http://grpc.akash.network:9090"],
    network_info: TERP_NETWORK,
    lcd_url: None,
    fcd_url: None,
};

 