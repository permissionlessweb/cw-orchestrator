use cosmwasm_schema::{
    cw_serde,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
};
use cosmwasm_std::{from_json, Binary};
use prost::Message;
// TODO: when polytone updates to cosmwasm v2 use polytone::ack::Callback;
use crate::{packet::success::IbcAppResult, InterchainError};
use cosmwasm_schema::schemars;

use polytone_callback::Callback;

use self::acknowledgement::{Acknowledgement, Response};

/// Struct used to centralize all the pre-defined ack types
pub enum IbcAckParser {}

impl IbcAckParser {
    /// Verifies if the given ack is an Polytone type and returns the parsed acknowledgement if it is
    ///
    /// Returns an error if there was an error in the process
    pub fn polytone_ack(ack: &Binary) -> Result<Callback, InterchainError> {
        // We try decoding the ack with Polytone
        let decoded_polytone_packet: Result<Callback, _> = from_json(ack);
        if let Ok(decoded_polytone_packet) = decoded_polytone_packet {
            match &decoded_polytone_packet {
                Callback::Query(query_result) => match query_result {
                    polytone_callback::QueryResult::Success(_) => {
                        return Ok(decoded_polytone_packet)
                    }
                    polytone_callback::QueryResult::Error(e) => {
                        return Err(InterchainError::FailedAckReceived(format!(
                            "Error during query on remote chain : {:?}",
                            e
                        )))
                    }
                },
                Callback::Execute(execute_response) => match execute_response {
                    polytone_callback::ExecutionResult::Success(_) => {
                        return Ok(decoded_polytone_packet)
                    }
                    polytone_callback::ExecutionResult::Error(e) => {
                        return Err(InterchainError::FailedAckReceived(format!(
                            "Error during execution on remote chain : {}",
                            e
                        )))
                    }
                },
                Callback::FatalError(e) => {
                    return Err(InterchainError::FailedAckReceived(e.to_string()))
                }
            }
        }

        Err(decode_ack_error(ack))
    }

    /// Verifies if the given ack is an IBC20 type
    ///
    /// Returns an error if there was an error in the parsing process
    pub fn ics20_ack(ack: &Binary) -> Result<(), InterchainError> {
        let successful_ics20_packet = Binary::new(vec![0x01]);

        if ack == &successful_ics20_packet {
            return Ok(());
        }

        Err(decode_ack_error(ack))
    }

    /// Verifies if the given ack is an ICS004 type and returns the ack result if it is
    ///
    /// Returns an error if there was an error in the parsing process
    pub fn ics004_ack(ack: &Binary) -> Result<Vec<u8>, InterchainError> {
        if let Ok(decoded_ics_004) = Acknowledgement::decode(ack.as_slice()) {
            if let Some(response) = decoded_ics_004.response {
                log::debug!("Decoded ack using ICS-004 : {:x?}", response);
                match response {
                    Response::Result(result) => return Ok(result),
                    Response::Error(e) => return Err(InterchainError::FailedAckReceived(e)),
                }
            }
        }
        Err(decode_ack_error(ack))
    }

    /// Verifies if the given ack is an ibc-hooks type and returns the ack result if it is
    ///
    /// Returns an error if there was an error in the parsing process
    ///
    /// The structure can be found here : https://github.com/cosmos/ibc-apps/blob/8cb681e31589bc90b47e0ab58173a579825fd56d/modules/ibc-hooks/wasm_hook.go#L119C1-L119C86
    pub fn ibc_hooks_ack(ack: &Binary) -> Result<IbcHooksAck, InterchainError> {
        if let Ok(decoded_ics_ack) = from_json::<IbcHooksAck>(ack) {
            return Ok(decoded_ics_ack);
        }

        Err(decode_ack_error(ack))
    }

    /// Verifies if the given ack is an ICS004 type with json parsing and returns the ack result if it is
    ///
    /// Returns an error if there was an error in the parsing process
    pub fn ics004_json_ack(ack: &Binary) -> Result<Vec<u8>, InterchainError> {
        if let Ok(decoded_ics_004) = from_json::<StdAck>(ack) {
            log::debug!(
                "Decoded ack using ICS-004 with json format : {:x?}",
                decoded_ics_004
            );
            match decoded_ics_004 {
                StdAck::Result(result) => return Ok(result.into()),
                StdAck::Error(e) => return Err(InterchainError::FailedAckReceived(e)),
            }
        }
        Err(decode_ack_error(ack))
    }

    /// Verifies if the given ack is a standard acknowledgement type
    ///
    /// Returns an error if there was an error in the parsing process
    pub fn any_standard_app_result(ack: &Binary) -> Result<IbcAppResult, InterchainError> {
        if let Ok(ack) = IbcAckParser::polytone_ack(ack) {
            Ok(IbcAppResult::Polytone(ack))
        } else if IbcAckParser::ics20_ack(ack).is_ok() {
            Ok(IbcAppResult::Ics20)
        } else if let Ok(ack) = IbcAckParser::ics004_ack(ack) {
            Ok(IbcAppResult::Ics004(ack))
        } else if let Ok(ack) = IbcAckParser::ics004_json_ack(ack) {
            Ok(IbcAppResult::Ics004(ack))
        } else if let Ok(ack) = IbcAckParser::ibc_hooks_ack(ack) {
            Ok(IbcAppResult::IbcHooks(ack))
        } else {
            Err(InterchainError::AckDecodingFailed(
                ack.clone(),
                String::from_utf8_lossy(ack.as_slice()).to_string(),
            ))
        }
    }

    /// Verifies if the given ack custom acknowledgement type.
    /// If it fails, tries to parse into standard ack types
    ///
    /// Returns an error if there was an error in the parsing process
    pub fn any_standard_app_result_with_custom<CustomResult>(
        ack: &Binary,
        parsing_func: fn(&Binary) -> Result<CustomResult, InterchainError>,
    ) -> Result<IbcAppResult<CustomResult>, InterchainError> {
        parsing_func(ack)
            .map(IbcAppResult::Custom)
            .or_else(|_| Self::any_standard_app_result(ack).map(|ack| ack.into_custom()))
    }
}

pub(crate) fn decode_ack_error(ack: &Binary) -> InterchainError {
    InterchainError::AckDecodingFailed(
        ack.clone(),
        String::from_utf8_lossy(ack.as_slice()).to_string(),
    )
}

/// This is copied from https://github.com/cosmos/cosmos-rust/blob/4f2e3bbf9c67c8ffef44ef1e485a327fd66f060a/cosmos-sdk-proto/src/prost/ibc-go/ibc.core.channel.v1.rs#L164
/// This is the ICS-004 standard proposal
pub mod acknowledgement {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Acknowledgement {
        /// response contains either a result or an error and must be non-empty
        #[prost(oneof = "Response", tags = "21, 22")]
        pub response: ::core::option::Option<Response>,
    }
    /// response contains either a result or an error and must be non-empty
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(bytes, tag = "21")]
        Result(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "22")]
        Error(::prost::alloc::string::String),
    }

    impl ::prost::Name for Acknowledgement {
        const NAME: &'static str = "Acknowledgement";
        const PACKAGE: &'static str = "ibc.core.channel.v1";
        fn full_name() -> ::prost::alloc::string::String {
            ::prost::alloc::format!("ibc.core.channel.v1.{}", Self::NAME)
        }
    }
}
/// This is a generic ICS acknowledgement format formated in json.
/// Proto defined here: https://github.com/cosmos/cosmos-sdk/blob/v0.42.0/proto/ibc/core/channel/v1/channel.proto#L141-L147
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StdAck {
    Result(Binary),
    Error(String),
}

/// This is the ibc-hooks acknowledgment formated in json
/// https://github.com/cosmos/ibc-apps/blob/8cb681e31589bc90b47e0ab58173a579825fd56d/modules/ibc-hooks/wasm_hook.go#L119C1-L119C86

#[cw_serde]
pub struct IbcHooksAck {
    contract_result: Option<Binary>,
    ibc_ack: Binary,
}

pub mod polytone_callback {
    use super::*;

    use cosmwasm_std::{SubMsgResponse, Uint64};

    #[cw_serde]
    pub struct ExecutionResponse {
        /// The address on the remote chain that executed the messages.
        pub executed_by: String,
        /// Index `i` corresponds to the result of executing the `i`th
        /// message.
        pub result: Vec<SubMsgResponse>,
    }

    #[cw_serde]
    pub struct ErrorResponse {
        /// The index of the first message who's execution failed.
        pub message_index: Uint64,
        /// The error that occured executing the message.
        pub error: String,
    }

    /// Wrapper for query results to work with cosmwasm-schema 3.0
    #[cw_serde]
    pub enum QueryResult {
        Success(Vec<Binary>),
        Error(ErrorResponse),
    }

    /// Wrapper for execution results to work with cosmwasm-schema 3.0
    #[cw_serde]
    pub enum ExecutionResult {
        Success(ExecutionResponse),
        Error(String),
    }

    /// Copy of the [polytone::ack::Callback](https://docs.rs/polytone/1.0.0/polytone/ack/index.html#reexport.Callback)
    /// But without cosmwasm v1 dependencies
    #[cw_serde]
    pub enum Callback {
        /// Result of executing the requested query, or an error.
        ///
        /// result[i] corresponds to the i'th query and contains the
        /// base64 encoded query response.
        Query(QueryResult),

        /// Result of executing the requested messages, or an error.
        ///
        /// 14/04/23: if a submessage errors the reply handler can see
        /// `codespace: wasm, code: 5`, but not the actual error. as a
        /// result, we can't return good errors for Execution and this
        /// error string will only tell you the error's codespace. for
        /// example, an out-of-gas error is code 11 and looks like
        /// `codespace: sdk, code: 11`.
        Execute(ExecutionResult),

        /// An error occured that could not be recovered from. The only
        /// known way that this can occur is message handling running out
        /// of gas, in which case the error will be `codespace: sdk, code:
        /// 11`.
        ///
        /// This error is not named becuase it could also occur due to a
        /// panic or unhandled error during message processing. We don't
        /// expect this to happen and have carefully written the code to
        /// avoid it.
        FatalError(String),
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::{Binary, StdResult};

    use super::IbcAckParser;

    #[test]
    fn ics20_ack_test() -> StdResult<()> {
        let success_ack = Binary::from_base64("AQ==")?;

        IbcAckParser::ics20_ack(&success_ack)?;
        Ok(())
    }
}
