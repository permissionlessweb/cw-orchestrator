//! Run allowlist checked before any signature. No network.

use std::collections::BTreeSet;
use std::fmt;

pub const MSG_STORE_CODE: &str = "/cosmwasm.wasm.v1.MsgStoreCode";
pub const MSG_INSTANTIATE: &str = "/cosmwasm.wasm.v1.MsgInstantiateContract";
pub const MSG_INSTANTIATE2: &str = "/cosmwasm.wasm.v1.MsgInstantiateContract2";
pub const MSG_EXECUTE: &str = "/cosmwasm.wasm.v1.MsgExecuteContract";
pub const MSG_MIGRATE: &str = "/cosmwasm.wasm.v1.MsgMigrateContract";

/// One contract the session may call. `keys` empty means every execute key.
/// `funds` empty means the call attaches no coins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedCall {
    pub address: String,
    pub keys: Vec<String>,
    pub calls: u64,
    pub funds: Vec<(String, u128)>,
}

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

/// `MsgExec`, granted only through [`RunAllowlist::allow_nested_exec`].
pub const MSG_AUTHZ_EXEC: &str = "/cosmos.authz.v1beta1.MsgExec";

/// What one script run may broadcast. Addresses created during the run
/// are recorded after instantiate. They are not known at approval time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunAllowlist {
    type_urls: BTreeSet<String>,
    code_ids: BTreeSet<u64>,
    created: BTreeSet<String>,
    explicit: BTreeSet<String>,
    /// Lowercase hex SHA-256 of each Wasm module this session may store.
    stores: BTreeSet<String>,
    executes: Vec<ScopedCall>,
    migrates: Vec<ScopedCall>,
    /// The grantee may send `MsgExec` as the granter (nested authz). Opt-in only.
    nested_exec: bool,
}

impl RunAllowlist {
    /// Grant `MsgExec` itself (GenericAuthorization), so the grantee can relay
    /// the granter's own authz grants: `MsgExec{MsgExec{..}}`. The grantee can
    /// then use every grant the granter holds until this one expires or is
    /// revoked, so keep the TTL short and revoke at close.
    pub fn allow_nested_exec(mut self) -> Self {
        self.nested_exec = true;
        self.type_urls.insert(MSG_AUTHZ_EXEC.into());
        self
    }

    pub fn nested_exec(&self) -> bool {
        self.nested_exec
    }

    pub fn allow_type(mut self, type_url: impl Into<String>) -> Self {
        self.type_urls.insert(type_url.into());
        self
    }

    /// Store this Wasm and nothing else. The checksum is the SHA-256 the
    /// chain computes after gunzip.
    pub fn allow_store(mut self, wasm: &[u8]) -> Result<Self, String> {
        let sum = wasm_checksum(wasm)?;
        self.stores.insert(hex_encode(&sum));
        self.type_urls.insert(MSG_STORE_CODE.into());
        Ok(self)
    }

    pub fn allow_execute(mut self, call: ScopedCall) -> Result<Self, String> {
        if call.address.is_empty() {
            return Err("grant refused: execute needs a contract address".into());
        }
        if call.calls == 0 {
            return Err("grant refused: execute needs at least one call".into());
        }
        self.type_urls.insert(MSG_EXECUTE.into());
        self.explicit.insert(call.address.clone());
        self.executes.push(call);
        Ok(self)
    }

    pub fn allow_migrate(mut self, call: ScopedCall) -> Result<Self, String> {
        if call.address.is_empty() {
            return Err("grant refused: migrate needs a contract address".into());
        }
        if call.calls == 0 {
            return Err("grant refused: migrate needs at least one call".into());
        }
        self.type_urls.insert(MSG_MIGRATE.into());
        self.explicit.insert(call.address.clone());
        self.migrates.push(call);
        Ok(self)
    }

    pub fn allow_store_checksum(mut self, hex_checksum: impl Into<String>) -> Self {
        self.stores.insert(hex_checksum.into());
        self.type_urls.insert(MSG_STORE_CODE.into());
        self
    }

    pub fn allow_execute_unchecked(mut self, call: ScopedCall) -> Self {
        self.type_urls.insert(MSG_EXECUTE.into());
        self.explicit.insert(call.address.clone());
        self.executes.push(call);
        self
    }

    pub fn allow_migrate_unchecked(mut self, call: ScopedCall) -> Self {
        self.type_urls.insert(MSG_MIGRATE.into());
        self.explicit.insert(call.address.clone());
        self.migrates.push(call);
        self
    }

    pub fn stores(&self) -> Vec<String> {
        self.stores.iter().cloned().collect()
    }

    pub fn executes(&self) -> &[ScopedCall] {
        &self.executes
    }

    pub fn migrates(&self) -> &[ScopedCall] {
        &self.migrates
    }

    pub fn has_store_scope(&self) -> bool {
        !self.stores.is_empty()
    }

    pub fn has_execute_scope(&self) -> bool {
        !self.executes.is_empty()
    }

    pub fn has_migrate_scope(&self) -> bool {
        !self.migrates.is_empty()
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
    /// JSON text of the message body the cold key is signing. Empty when the
    /// run has only declared the type.
    pub body: Option<String>,
}

impl SigningRequest {
    pub fn new(type_url: impl Into<String>) -> Self {
        Self {
            type_url: type_url.into(),
            contract: None,
            code_id: None,
            body: None,
        }
    }

    pub fn body(mut self, json: impl Into<String>) -> Self {
        self.body = Some(json.into());
        self
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

/// Contract address `MsgInstantiateContract2` will use.
///
/// `creator` is the canonical account that sends the instantiate, the
/// ephemeral grantee. `msg` is empty, matching wasmd when `fix_msg` is unset.
/// The result is 32 bytes, this chain's contract address length.
pub fn instantiate2_bech32(
    prefix: &str,
    checksum: &[u8],
    creator: &[u8],
    salt: &[u8],
) -> Result<String, String> {
    let canonical = cosmwasm_std::CanonicalAddr::from(creator);
    let raw = cosmwasm_std::instantiate2_address(checksum, &canonical, salt)
        .map_err(|err| format!("instantiate2 address refused: {err}"))?;
    let hrp = bech32::Hrp::parse(prefix).map_err(|err| format!("instantiate2 address refused: {err}"))?;
    bech32::encode::<bech32::Bech32>(hrp, raw.as_slice())
        .map_err(|err| format!("instantiate2 address refused: {err}"))
}

/// SHA-256 of the Wasm module. A gzip wrapper is removed first, because
/// wasmd checksums the bytes after gunzip.
pub fn wasm_checksum(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let raw = if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        let mut decoder = flate2::read::GzDecoder::new(bytes);
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut out)
            .map_err(|err| format!("grant refused: wasm gzip: {err}"))?;
        out
    } else {
        bytes.to_vec()
    };
    use sha2::Digest;
    Ok(sha2::Sha256::digest(&raw).to_vec())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> SignDocDigest {
        SignDocDigest::new("ab".repeat(32)).expect("64 hex")
    }

    fn principal() -> Principal {
        Principal::new("treasury").expect("principal")
    }

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
