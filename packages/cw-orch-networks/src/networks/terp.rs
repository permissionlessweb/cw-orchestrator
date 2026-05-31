use crate::networks::{ChainInfo, ChainKind, NetworkInfo};

pub const TERP_LOCAL_CHAIN_ID: &str = "240u-1";

pub const TERP_NETWORK: NetworkInfo = NetworkInfo {
    chain_name: "Terp",
    pub_address_prefix: "terp",
    coin_type: 118u32,
};

pub const TERP_TESTNET: ChainInfo = ChainInfo {
    kind: ChainKind::Testnet,
    chain_id: "120u-1",
    gas_denom: "uthiol",
    gas_price: 0.05,
    grpc_urls: &["http://testnet-grpc.terp.network:9390"],
    network_info: TERP_NETWORK,
    lcd_url: None,
    fcd_url: None,
};

pub const TERP_MAINNET: ChainInfo = ChainInfo {
    kind: ChainKind::Mainnet,
    chain_id: "morocco-1",
    gas_denom: "uthiol",
    gas_price: 0.05,
    grpc_urls: &["http://grpc.terp.network:9090"],
    network_info: TERP_NETWORK,
    lcd_url: None,
    fcd_url: None,
};

pub const TERP_LOCALNET: ChainInfo = ChainInfo {
    kind: ChainKind::Local,
    chain_id: TERP_LOCAL_CHAIN_ID,
    gas_denom: "uterp",
    gas_price: 0.025,
    grpc_urls: &[],
    network_info: NetworkInfo {
        chain_name: "terp",
        pub_address_prefix: "terp",
        coin_type: 118,
    },
    lcd_url: None,
    fcd_url: None,
};
