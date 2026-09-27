# Threshold KMS signer

Status: v5, 2026-09-27. This page is the engineering spec and the working-state
log for the cw-orch threshold KMS signer. Decisions live here, not in chat.

Two signature tracks. Threshold ECDSA is still blocked on a named crate.
FROST authorization lives on `terp-frost` and must keep pubkey rotation
working. See [Account model](#account-model).

## Decisions

Resolved 2026-09-25:

- **D1.** No Infisical signing exists, and none is added. The o-line Argus
  scripts, `zakura` `SNAPSHOT_HOST.md`, and the vendored tree at
  `terp-core/crates/infiscial/` are out of scope and must not be edited.
- **D2.** Threshold math is `osst` 0.1.1 on its `secp256k1` (`k256` 0.13)
  backend. osst is unaudited; that risk is accepted below. The intended
  Cosmos signature was a hand-written ECDSA finalizer over osst output.
  That finalizer is blocked. See [Blocker](#blocker).
- **D4.** The KMS is remote. The signer reaches it with Noise over TCP. The
  operator's browser talks only to `127.0.0.1`. The browser never talks to
  the KMS and never sees a share.

Resolved 2026-09-27 by the user:

- **D3.** Accounts are threshold-born. DKG is the operating rule. An existing
  non-threshold address is rotated with a coordinated on-chain handover.
  Trusted-dealer Shamir import remains a one-time migration tool, with the
  rollover warning: a key that was ever whole on one machine has already lost
  the property the threshold scheme exists to provide.
- **D5.** Keep `Signer::sign(&self, SignDoc) -> Result<Raw, DaemonError>`
  synchronous. The impl blocks on a dedicated tokio `Handle`. No version bump.
  Calling `sign` from inside a runtime worker thread is a programmer error and
  must fail with an error that says so, not a panic from a nested `block_on`.
  An async `sign` is a later, separately announced breaking change and is not
  part of this work.
- **D6.** The trusted-dealer split uses `osst::lagrange::compute_lagrange_coefficients`
  and the reshare primitives. No new secret-sharing crate.
- **D7.** Node-backed examples and tests target a local terp-core node that
  the user starts. They sit behind the existing `node-tests` feature. The
  agent does not start Docker.
- **D8.** Crate: workspace member `packages/cw-orch-kms`, feature `threshold`,
  re-exported from the `cw-orch` prelude. `Signer` is implemented, not forked,
  so the blanket `TxSender` impl is inherited. This file is both the spec and
  the progress log.
- **D9.** Loopback HTTP and WebSocket use `axum` 0.8.9 with its `ws` feature
  (that feature pulls `tokio-tungstenite` 0.29.0). MSRV of axum 0.8.9 is 1.80.
  The toolchain checked on 2026-09-27 is `rustc 1.98.0-nightly`. No other new
  dependency is approved. `snow` 0.10.0 is approved with exactly
  `default-features = false` and features
  `use-curve25519`, `use-chacha20poly1305`, `use-blake2`, `use-getrandom`.

Locked from D4, written down so they are not defaults discovered in code:

- Noise pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s`. Each side has a static
  X25519 keypair. A wrong pattern, a wrong static key, or a missing static key
  is a specific rejection. There is no PSK mode and no downgrade to plaintext.
- One handshake per TCP connection. Handshake timeout 30 seconds. Idle timeout
  60 seconds. A dropped connection does not reconnect into the same signing
  round.
- Frame: version byte `1`, then a `u32` big-endian length, then that many
  bytes. Unknown version is a specific rejection. Length above 65536 is
  rejected before the body is allocated.
- Retry policy for `Signer::sign` (requirement R1.5), both halves: a completed
  authorization is cached by `SignDocDigest`. A cache hit returns the exact
  signature bytes and is provable. A cache miss does not start a threshold
  round. It returns `ReauthorizationRequired` naming the digest, the account,
  the rejected sequence, and the block height. The only operator-visible
  re-auth entry point is one explicit call. Eviction or expiry of a cached
  authorization is a typed event.
- Share and config writes: write a temp file in the same directory, `fsync`
  the file, rename over the destination, `fsync` the directory. Readers reject
  torn, truncated, garbage, wrong-version, and wrong-length input by name.
  They do not repair it.

## Account model

Decided 2026-09-27 after the Schnorr/ECDSA contradiction. Two tracks. They
are not adapters of each other.

**Priority: threshold ECDSA, sharded keys.** A standard secp256k1 account
whose address is the group public key. Quorum signing produces a recoverable
ECDSA signature that `SIGN_MODE_DIRECT` accepts, without assembling the
secret in one process. osst FROST does not do this. A search of `terp-rs`
`*.rs` and `*.toml` for `cggmp`, `gg18`, `gg20`, and `threshold.ecdsa` on
2026-09-27 returned no hits. No protocol crate is approved yet. The signing
rounds are not implemented, and they will not be hand-rolled. The next step
is a named, audited crate and version from the user. §2.4 still applies:
adding that dependency requires that name.

**FROST track: `terp-frost` is the authenticator.** Decided 2026-09-27.
An account that signs with osst FROST is not a native secp256k1 account. It
is a Terp smart account, and `contracts/smart-accounts/terp-frost` is the
contract that both rotates the group verifying key and authorizes Schnorr
signatures. Authorization and rotation do not share an entry point.

- Rotation stays `ExecuteMsg::RotateFrostPubkey` and `AddRotateShare`. Those
  handlers still return Ok and write, including the fail reasons they already
  write. A pending proposal does not change the key used for authorization.
  The applied `group_vk` is the only key that authorizes. `old_vk` does not.
- `sudo` handles `AuthSudoMsg`. `Authenticate` reads `group_vk` and the
  signature. It does not write. `x/smart-account` discards writes made from
  Authenticate, so putting rotation there would drop a rotate. Track,
  confirm, add, and remove also do not write, and remove does not clear the
  group key.
- The signed preimage is `AuthenticationRequest.sign_mode_tx_data.sign_mode_direct`.
  An empty preimage is rejected. `simulate: true` accepts without a signature
  and still does not write, so gas estimation does not require a quorum.
- `group_vk` for authorization is 66 lowercase hex characters of the 33-byte
  SEC1 compressed osst secp256k1 point (`OsstPoint::compress_vec`). Any other
  string, including the opaque labels the rotate tests use, fails
  authorization with `group_vk is not a secp256k1 point` and leaves storage
  as it was. Rotation of those labels is unchanged.
- The signature is 65 bytes: 33-byte SEC1 `R` || 32-byte canonical scalar `z`.
  osst `Signature::to_bytes` is 64 bytes and drops the secp256k1 y parity
  (`compress` keeps x only; `decompress` assumes `0x02`). The contract does
  not use that encoding. It decompresses the 33-byte `R` and calls
  `osst::frost::verify_signature`. A failed check names the group key and the
  preimage length. It does not echo the signature.

Threshold ECDSA for a normal secp256k1 account is still not implemented. No
protocol crate has been named.

## Blocker

Verified 2026-09-27 in `crates/zeratul/crates/osst/src/frost.rs`. The
arithmetic fact stands. The user decision above replaces "stop the project"
with the two-track model. Threshold ECDSA stays blocked on a named crate.

`aggregate` (line 489) sums FROST responses into `Signature { r, z }` and the
comment calls it a standard Schnorr signature. `verify_signature` (line 554)
checks `g^z == R + H(R, Y, m) · Y`. `sign` (line 434) computes
`z_i = d_i + ρ_i·e_i + λ_i·c·s_i` and drops the nonces.

Cosmos `SIGN_MODE_DIRECT` on a secp256k1 account expects a recoverable ECDSA
signature. `cosmrs::tx::SignDoc::sign` (`cosmos-rust/cosmrs/src/tx/sign_doc.rs:60`)
hashes the sign-doc bytes and calls `SigningKey::sign`, which is ECDSA
(`k256` `try_sign`, RFC6979).

A Schnorr pair `(R, z)` does not determine an ECDSA pair `(r, s)`. ECDSA needs
`s = k^{-1}(h + r·x)`. The nonce scalar `k` was discarded inside `sign`, and
the secret `x` is shared. No arithmetic on osst's signature output produces
the ECDSA signature §6.4 requires to be byte-identical to
`SignDoc::sign(&full_private_key)`.

No crate code is written until this is resolved. Building a "finalizer" that
reconstructs `x` in one process would violate the rule that no single
participant holds the whole key. Inventing a threshold-ECDSA protocol is a new
cryptographic protocol and is not the exception D2 described.

## Risk acceptance — osst

`crates/zeratul/crates/osst` version 0.1.1. Its README says: "this crate has
not been audited. use at your own risk." Accepted 2026-09-25 (D2) and recorded
here 2026-09-27. osst sits inside the trust boundary of this signer. Its
unaccountable verification failure mode (a bad share cannot be blamed) is part
of that acceptance. Properties we rely on are tested in this repo; the
acceptance is not a substitute for those tests.

## Infisical sweep — 2026-09-27

`rg` is not installed on this machine (`command -v rg` empty, no binary under
Homebrew or `~/.cargo/bin`). The sweep used `grep -R -i -n` with
`--include` for `*.rs`, `*.toml`, `*.md`, `*.sh`, plus `git log -S`.

`grep` over `crates/cw-orchestrator`: no output. Zero hits.

```
git -C crates/cw-orchestrator log --all -S infisical --oneline
```

No output. Zero commits.

`cargo tree -p cw-orch-kms` was not run. The crate does not exist yet. Run it
when the crate is added, and again before calling the work complete.

Out of scope, present, not modified:

- `crates/o-line/tools/argus/with-infisical.sh`
- `crates/o-line/tools/argus/infisical-renew.sh`
- `crates/o-line/tools/argus/README.md`
- `crates/o-line/tools/argus/ARGG.md`
- `crates/zakura/deploy/release-state/SNAPSHOT_HOST.md` lines 49 and 124
- `crates/infiscial/`: 255 files matched. Vendored product clone.

## Requirements

The signer is a `SenderBuilder` consumed by `DaemonAsyncBuilder::build_sender`
and `DaemonBuilder::build_sender`. No parallel daemon type. `ThresholdSigner`
implements `QuerySender` and `Signer` and inherits the blanket `TxSender`.

`calculate_gas` is overridden. Simulation builds
`TxRaw { body_bytes, auth_info_bytes, signatures: vec![vec![]] }` and calls
`_simulate_tx`, the same shape as `cw-orch-daemon/examples/manual_sender.rs`.
The inherited `calculate_gas` signs, and a threshold round must not run for
gas estimation.

The signer has no local-key fallback. An unreachable KMS is a hard error.

Two threshold key sets share one type parameterized by a validated
`Threshold` (t-of-n). The treasury key uses a high quorum. The session key
uses a lower quorum. `SessionGrant` owns, immutably, the grantee, the authz
grant, the feegrant allowance, the `Expiration`, and the `SessionId`.
Expiry is checked locally through an injected `Clock` and on chain. After
expiry or revocation the session key cannot sign. Scope is enforced only in
`authorize`. The audit trail is append-only: mint, register, use, expire,
revoke, each with the `SignDocDigest`.

The operator surface is one `Terminal` implementation with two carriers: a
self-contained HTML file and a loopback WebSocket. The page renders the
decoded sign doc and the SHA-256 of the exact bytes that would be signed.
Approval requires an acknowledgement and a one-time nonce compared in
constant time. Refusal emits no share, nonce, or partial signature. The
listener binds `127.0.0.1` only, rejects traversal and NUL paths, and is
dropped with the run. axum is the HTTP and WebSocket stack (D9).

Shamir import is an offline migration binary with no network client and no
sender constructor in scope. It preserves the bech32 address. The
reconstructed secret lives in a `zeroize` buffer and is not written to disk.
Published Shamir vectors are the interoperability test. t = 0, n = 0, index 0,
duplicate indices, and a short quorum are rejections with the counts.

Domain newtypes, each with a validating constructor: `Threshold`,
`NumParties`, `ShareIndex`, `Expiration`, `SessionTtl`, `SignDocDigest`,
`SessionId`. k256 and `bitcoin::secp256k1` conversions live in one module.

One function decides whether a key set may sign a sign doc:

```rust
fn authorize(
    &self,
    request: &SigningRequest,
    digest: SignDocDigest,
    principal: Principal,
) -> Result<Authorization, AuthorizationError>
```

`AuthorizationError` names the reason, the digest, the principal, and the
offending value.

Wire format version is 1. Unknown versions are rejected. `decode(encode(x))`
equals `x` on generated valid inputs. Key material is redacted in `Debug`,
`Display`, errors, logs, and panics.

Public traits `Signer`, `TxSender`, `SenderBuilder`, `CosmosOptions`, and
`TxHandler` are not changed (D5).

## Work order

1. This page, the sweep, and the risk acceptance. Done in the commit that
   adds this file.
2. Crate skeleton and domain newtypes. Not started. Blocked.
3. Curve conversion module. Not started. Blocked.
4. ECDSA finalizer. Blocked on the contradiction above. Nothing after this
   milestone is started.
5. DKG, Noise, `Signer`, differential test, policy, operator surface, session
   grants, Shamir import, examples, the public docs pass on this page,
   `docs/src/cli/keys.md`, and `CHANGELOG.md`.

## Progress

- 2026-09-27. Read §0–§3. Confirmed cw-orchestrator branch `product/cw3` and
  the pre-existing dirty files (`Cargo.toml`, `cw-orch-daemon/Cargo.toml`,
  `cw-orch-daemon/src/channel.rs`, `cw-orch-daemon/src/queriers/cosmwasm.rs`,
  `packages/cw-orch-core/{Cargo.toml,src/lib.rs,src/circuits/circuit_interface_traits.rs}`,
  `packages/cw-orch-mock/Cargo.toml`,
  `packages/cw-orch-networks/src/networks/terp.rs`, and the two `.bak` files).
  Those files are not part of this work.
- 2026-09-27. User resolved D3, D5, D6, D7, D8, D9 as recorded above.
- 2026-09-27. Infisical sweep recorded. osst risk acceptance recorded.
- 2026-09-27. Stopped. `osst::frost::aggregate` is Schnorr. No ECDSA adapter
  was written. No crate was added.
- 2026-09-27. User decision: FROST accounts are smart accounts whose
  authenticator authorizes osst signatures. Priority remains threshold ECDSA
  for sharded secp256k1 keys. No threshold-ECDSA crate is in tree, so those
  rounds are not started. `terp-frost` was recorded here as rotate-only.
- 2026-09-27. User decision: `terp-frost` is the Schnorr authenticator, and
  pubkey rotation stays on the existing execute messages. Authenticate is
  read-only against the applied group key. Wire format is 33-byte SEC1 `R`
  plus 32-byte `z`, because osst's 64-byte encoding drops y parity.
