use crate::networks::{ChainInfo, ChainKind, NetworkInfo};

// ANCHOR: akash
pub const AKASH_NETWORK: NetworkInfo = NetworkInfo {
    chain_name: "akash",
    pub_address_prefix: "akash",
    coin_type: 118u32,
};

pub const AKASH_MAINNET: ChainInfo = ChainInfo {
    kind: ChainKind::Mainnet,
    chain_id: "akash-1",
    gas_denom: "uakt",
    gas_price: 0.025,
    grpc_urls: &["https://akash-grpc.publicnode.com:443"],
    network_info: AKASH_NETWORK,
    lcd_url: None,
    fcd_url: None,
};