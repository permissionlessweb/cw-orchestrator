use crate::networks::{ChainInfo, ChainKind, NetworkInfo};
// ANCHOR: atomone
pub const ATOMEONE_NETWORK: NetworkInfo = NetworkInfo {
    chain_name: "akash",
    pub_address_prefix: "akash",
    coin_type: 118u32,
};

pub const ATOMEONE_MAINNET: ChainInfo = ChainInfo {
    kind: ChainKind::Mainnet,
    chain_id: "atomone-1",
    gas_denom: "uatone",
    gas_price: 0.025,
    grpc_urls: &["http://mainnet-atomone.konsortech.xyz:12090"],
    network_info: ATOMEONE_NETWORK,
    lcd_url: None,
    fcd_url: None,
};

pub const ATOMEONE_TESTNET: ChainInfo = ChainInfo {
    kind: ChainKind::Testnet,
    chain_id: "atomone-1",
    gas_denom: "uakt",
    gas_price: 0.025,
    grpc_urls: &["http://testnet-atomone.konsortech.xyz:12090"],
    network_info: ATOMEONE_NETWORK,
    lcd_url: None,
    fcd_url: None,
};
