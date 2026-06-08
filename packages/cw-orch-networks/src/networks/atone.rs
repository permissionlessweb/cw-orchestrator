use crate::networks::{ChainInfo, ChainKind, NetworkInfo};
// ANCHOR: atomone
pub const ATOMEONE_NETWORK: NetworkInfo = NetworkInfo {
    chain_name: "akash",
    pub_address_prefix: "akash",
    coin_type: 118u32,
};

pub const ATOMEONE_MAINNET: ChainInfo = ChainInfo {
    kind: ChainKind::Mainnet,
    chain_id: "akash-1",
    gas_denom: "uakt",
    gas_price: 0.025,
    grpc_urls: &["https://grpc-akash.ecostake.com:443"],
    network_info: ATOMEONE_NETWORK,
    lcd_url: None,
    fcd_url: None,
};
