//! Run allowlist checked before any signature. No network.

use std::collections::BTreeSet;
use std::fmt;

pub const MSG_STORE_CODE: &str = "/cosmwasm.wasm.v1.MsgStoreCode";
pub const MSG_INSTANTIATE: &str = "/cosmwasm.wasm.v1.MsgInstantiateContract";
pub const MSG_EXECUTE: &str = "/cosmwasm.wasm.v1.MsgExecuteContract";

/// SHA-256 of the sign-doc bytes, 64 lowercase hex characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignDocDigest(String);

impl SignDocDigest {
    pub fn new(hex_sha256: impl Into<String>) -> Result<Self, String> {
        let text = hex_sha256.into();
        if text.len() != 64 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("sign doc digest refused: want 64 hex characters".into());
        }
        Ok(Self(text.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Account or operator the audit line names. Not a signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal(String);

impl Principal {
    pub fn new(id: impl Into<String>) -> Result<Self, String> {
        let id = id.into();
        if id.is_empty() {
            return Err("principal refused: empty".into());
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What one script run may broadcast. Addresses created during the run
/// are recorded after instantiate. They are not known at approval time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunAllowlist {
    type_urls: BTreeSet<String>,
    code_ids: BTreeSet<u64>,
    created: BTreeSet<String>,
    explicit: BTreeSet<String>,
}

impl RunAllowlist {
    pub fn allow_type(mut self, type_url: impl Into<String>) -> Self {
        self.type_urls.insert(type_url.into());
        self
    }

    pub fn allow_code(mut self, code_id: u64) -> Self {
        self.code_ids.insert(code_id);
        self
    }

    /// Address that already exists and was named in the approval.
    pub fn allow_address(mut self, address: impl Into<String>) -> Self {
        self.explicit.insert(address.into());
        self
    }

    pub fn record_created(&mut self, address: impl Into<String>) {
        self.created.insert(address.into());
    }

    pub fn type_urls(&self) -> Vec<String> {
        self.type_urls.iter().cloned().collect()
    }
}

/// One message the sender is about to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningRequest {
    pub type_url: String,
    pub contract: Option<String>,
    pub code_id: Option<u64>,
}

impl SigningRequest {
    pub fn new(type_url: impl Into<String>) -> Self {
        Self {
            type_url: type_url.into(),
            contract: None,
            code_id: None,
        }
    }

    pub fn contract(mut self, address: impl Into<String>) -> Self {
        self.contract = Some(address.into());
        self
    }

    pub fn code_id(mut self, code_id: u64) -> Self {
        self.code_id = Some(code_id);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub digest: SignDocDigest,
    pub principal: Principal,
    pub type_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationError {
    pub reason: &'static str,
    pub digest: String,
    pub principal: String,
    pub offending: String,
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: digest {} principal {} offending {}",
            self.reason, self.digest, self.principal, self.offending
        )
    }
}

impl std::error::Error for AuthorizationError {}

/// Holds the run allowlist. `authorize` does not sign.
#[derive(Clone, Debug, Default)]
pub struct Authorizer {
    allowlist: RunAllowlist,
}

impl Authorizer {
    pub fn new(allowlist: RunAllowlist) -> Self {
        Self { allowlist }
    }

    pub fn record_created(&mut self, address: impl Into<String>) {
        self.allowlist.record_created(address);
    }

    pub fn authorize(
        &self,
        request: &SigningRequest,
        digest: SignDocDigest,
        principal: Principal,
    ) -> Result<Authorization, AuthorizationError> {
        let refuse = |reason: &'static str, offending: String| AuthorizationError {
            reason,
            digest: digest.as_str().to_string(),
            principal: principal.as_str().to_string(),
            offending,
        };
        if request.type_url.is_empty() || !self.allowlist.type_urls.contains(&request.type_url) {
            return Err(refuse(
                "type url not on the run allowlist",
                request.type_url.clone(),
            ));
        }
        if request.type_url == MSG_INSTANTIATE {
            match request.code_id {
                Some(code_id) if self.allowlist.code_ids.contains(&code_id) => {}
                Some(code_id) => {
                    return Err(refuse(
                        "code id not on the run allowlist",
                        code_id.to_string(),
                    ));
                }
                None => {
                    return Err(refuse(
                        "instantiate missing code id",
                        request.type_url.clone(),
                    ));
                }
            }
        }
        if request.type_url == MSG_EXECUTE {
            let contract = request.contract.as_deref().unwrap_or("");
            if contract.is_empty() {
                return Err(refuse("execute missing contract", request.type_url.clone()));
            }
            let known = self.allowlist.created.contains(contract)
                || self.allowlist.explicit.contains(contract);
            if !known {
                return Err(refuse(
                    "contract was not created by this run",
                    contract.to_string(),
                ));
            }
        }
        Ok(Authorization {
            digest,
            principal,
            type_url: request.type_url.clone(),
        })
    }
}

fn digest() -> SignDocDigest {
    SignDocDigest::new("ab".repeat(32)).expect("64 hex")
}

fn principal() -> Principal {
    Principal::new("treasury").expect("principal")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_rejects() {
        let err = Authorizer::new(RunAllowlist::default())
            .authorize(&SigningRequest::new(MSG_STORE_CODE), digest(), principal())
            .expect_err("empty");
        assert_eq!(err.reason, "type url not on the run allowlist");
        assert_eq!(err.offending, MSG_STORE_CODE);
        assert_eq!(err.digest, digest().as_str());
        assert_eq!(err.principal, "treasury");
    }

    #[test]
    fn undeclared_type_url_rejects() {
        let allow = RunAllowlist::default().allow_type(MSG_STORE_CODE);
        let err = Authorizer::new(allow)
            .authorize(&SigningRequest::new(MSG_EXECUTE), digest(), principal())
            .expect_err("undeclared");
        assert_eq!(err.reason, "type url not on the run allowlist");
        assert_eq!(err.offending, MSG_EXECUTE);
    }

    #[test]
    fn declared_type_url_allows_store() {
        let allow = RunAllowlist::default().allow_type(MSG_STORE_CODE);
        let ok = Authorizer::new(allow)
            .authorize(&SigningRequest::new(MSG_STORE_CODE), digest(), principal())
            .expect("store");
        assert_eq!(ok.type_url, MSG_STORE_CODE);
    }

    #[test]
    fn contract_outside_the_run_rejects() {
        let allow = RunAllowlist::default().allow_type(MSG_EXECUTE);
        let err = Authorizer::new(allow)
            .authorize(
                &SigningRequest::new(MSG_EXECUTE).contract("terp1other"),
                digest(),
                principal(),
            )
            .expect_err("foreign");
        assert_eq!(err.reason, "contract was not created by this run");
        assert_eq!(err.offending, "terp1other");
    }

    #[test]
    fn execute_of_a_contract_this_run_created_allows() {
        let allow = RunAllowlist::default().allow_type(MSG_EXECUTE);
        let mut auth = Authorizer::new(allow);
        auth.record_created("terp1made");
        auth.authorize(
            &SigningRequest::new(MSG_EXECUTE).contract("terp1made"),
            digest(),
            principal(),
        )
        .expect("created");
    }

    #[test]
    fn instantiate_requires_a_declared_code_id() {
        let allow = RunAllowlist::default()
            .allow_type(MSG_INSTANTIATE)
            .allow_code(7);
        Authorizer::new(allow.clone())
            .authorize(
                &SigningRequest::new(MSG_INSTANTIATE).code_id(7),
                digest(),
                principal(),
            )
            .expect("code 7");
        let err = Authorizer::new(allow)
            .authorize(
                &SigningRequest::new(MSG_INSTANTIATE).code_id(8),
                digest(),
                principal(),
            )
            .expect_err("code 8");
        assert_eq!(err.reason, "code id not on the run allowlist");
        assert_eq!(err.offending, "8");
    }

    #[test]
    fn explicit_address_is_an_extra_entry() {
        let allow = RunAllowlist::default()
            .allow_type(MSG_EXECUTE)
            .allow_address("terp1listed");
        Authorizer::new(allow)
            .authorize(
                &SigningRequest::new(MSG_EXECUTE).contract("terp1listed"),
                digest(),
                principal(),
            )
            .expect("listed");
    }

    #[test]
    fn digest_constructor_rejects_a_short_value() {
        assert!(SignDocDigest::new("abcd").is_err());
    }
}
