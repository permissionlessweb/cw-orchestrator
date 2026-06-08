#![allow(missing_docs)]
//! # Cosmos blockchain networks
//! Contains information and helpers for different blockchain networks
//! See [parse_network] to easily retrieve this static network information
pub mod akash;
pub mod archway;
pub mod atone;
pub mod cosmos;
pub mod doravota;
pub mod injective;
pub mod juno;
pub mod kujira;
pub mod landslide;
pub mod neutron;
pub mod nibiru;
pub mod osmosis;
pub mod rollkit;
pub mod sei;
pub mod terp;
pub mod terra;
pub mod union;
pub mod xion;

#[allow(deprecated)]
use crate::networks::union::UNION_TESTNET_8;
pub use akash::{AKASH_MAINNET, AKASH_NETWORK};
pub use archway::{ARCHWAY_1, CONSTANTINE_3};
pub use atone::{ATOMEONE_MAINNET, ATOMEONE_NETWORK};
pub use cosmos::COSMOS_HUB_TESTNET;
pub use cw_orch_core::environment::{ChainInfo, ChainKind, NetworkInfo};
pub use doravota::{VOTA_ASH, VOTA_TESTNET};
pub use injective::{INJECTIVE_1, INJECTIVE_888};
pub use juno::{JUNO_1, LOCAL_JUNO, UNI_6};
pub use kujira::HARPOON_4;
pub use landslide::LOCAL_LANDSLIDE;
pub use neutron::{LOCAL_NEUTRON, NEUTRON_1, PION_1};
pub use nibiru::NIBIRU_ITN_2;
pub use osmosis::{LOCAL_OSMO, OSMOSIS_1, OSMO_5};
pub use rollkit::{LOCAL_ROLLKIT, ROLLKIT_TESTNET};
pub use sei::{ATLANTIC_2, LOCAL_SEI, PACIFIC_1, SEI_DEVNET_3};
pub use terp::{TERP_LOCALNET, TERP_MAINNET, TERP_TESTNET};
pub use terra::{LOCAL_TERRA, PHOENIX_1, PISCO_1};
pub use xion::{XION_MAINNET_1, XION_TESTNET_1};

/// A helper function to retrieve a [`ChainInfo`] struct for a given chain-id.
///
/// ## Example
/// ```rust,no_run
/// use cw_orch_networks::networks::{parse_network, ChainInfo};
/// let juno_mainnet: ChainInfo = parse_network("juno-1").unwrap();
/// ```
/// ---
/// supported chains are defined by the `SUPPORT_NETWORKS` variable
pub fn parse_network(net_id: &str) -> Result<ChainInfo, String> {
    SUPPORTED_NETWORKS
        .iter()
        .find(|net| net.chain_id == net_id)
        .cloned()
        .ok_or(format!("Network not found: {}", net_id))
}

pub const SUPPORTED_NETWORKS: &[ChainInfo] = &[
    UNI_6,
    JUNO_1,
    LOCAL_JUNO,
    PISCO_1,
    PHOENIX_1,
    LOCAL_TERRA,
    INJECTIVE_888,
    CONSTANTINE_3,
    ARCHWAY_1,
    PION_1,
    NEUTRON_1,
    INJECTIVE_1,
    HARPOON_4,
    OSMOSIS_1,
    OSMO_5,
    LOCAL_OSMO,
    LOCAL_NEUTRON,
    LOCAL_SEI,
    SEI_DEVNET_3,
    ATLANTIC_2,
    PACIFIC_1,
    XION_TESTNET_1,
    TERP_LOCALNET,
    TERP_MAINNET,
    TERP_TESTNET,
    XION_MAINNET_1,
    ROLLKIT_TESTNET,
    LOCAL_LANDSLIDE,
    #[allow(deprecated)]
    UNION_TESTNET_8,
    COSMOS_HUB_TESTNET,
];

/// Mapping from chain_id to chain_name for known chains
pub fn chain_name_from_id(chain_id: &str) -> String {
    let name: &str = match chain_id {
        "morocco-1" => "terp",
        "cosmoshub-4" => "cosmoshub",
        "osmosis-1" => "osmosis",
        "juno-1" => "juno",
        "akashnet-2" => "akash",
        "stargaze-1" => "stargaze",
        "injective-1" => "injective",
        "neutron-1" => "neutron",
        "atomone-1" => "atomone",
        "regen-1" => "regen",
        "sei-1" => "sei",
        "omniflixhub-1" => "omniflix",
        "passage-2" => "passage3d",
        "evmos_9001-2" => "evmos",
        "core-1" => "persistence",
        "axelar-dojo-1" => "axelar",
        "noble-1" => "noble",
        "terra2-1" => "terra2",
        "kava_2222-10" => "kava",
        "gitopia" => "gitopia",
        "secret-4" => "secret",
        _ => "UNKNOWN",
    };
    name.to_string()
}
