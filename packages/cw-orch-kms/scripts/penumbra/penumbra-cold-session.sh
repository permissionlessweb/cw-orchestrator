#!/bin/sh
# One command: the cold-wallet run page on 127.0.0.1:8743 (the shared
# cw-orch-kms page: FVK import from Zigner QR, then every approval) and custody
# gRPC on 127.0.0.1:8742. Ctrl-C or "End session" wipes the home.
# Build: (cd packages/cw-orch-kms/penumbra && cargo build --release)
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
if [ -z "${COLD_WALLET_CFG:-}" ]; then
  if [ -f "$here/config/penumbra/cold-wallet.env" ]; then
    COLD_WALLET_CFG=$here/config/penumbra/cold-wallet.env
  else
    COLD_WALLET_CFG=$here/config/penumbra/cold-wallet.env.example
  fi
fi
. "$COLD_WALLET_CFG"
case "$PENUMBRA_POLICY" in
  /*) policy=$PENUMBRA_POLICY ;;
  *) policy=$here/$PENUMBRA_POLICY
     [ -f "$policy" ] || policy=$here/config/penumbra/$(basename "$PENUMBRA_POLICY") ;;
esac
bin=${PZC_BIN:-$here/penumbra/target/release/penumbra-zigner-custody}
exec "$bin" --expect-address "$PENUMBRA_PINNED_ADDRESS" --policy "$policy" \
  --page 127.0.0.1:8743 --timeout-secs 900 \
  session --node "$PENUMBRA_NODE" --grpc 127.0.0.1:8742 \
  --ttl-secs "$PENUMBRA_SESSION_TTL_SECS" --state-dir "${HOME}/.cw-orch-kms/penumbra"
