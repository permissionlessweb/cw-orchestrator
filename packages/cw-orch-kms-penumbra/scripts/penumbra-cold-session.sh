#!/bin/sh
# One command: brings up the cold-wallet session page on 127.0.0.1:8743
# (FVK import from Zigner QR), custody gRPC on 127.0.0.1:8742 and per-tx
# approval pages on 127.0.0.1:8744. Ctrl-C or "end session" wipes the home.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cfg=${COLD_WALLET_CFG:-$here/config/cold-wallet.env.example}
. "$cfg"
bin=${PZC_BIN:-$here/target/release/penumbra-zigner-custody}
exec "$bin" --expect-address "$PENUMBRA_PINNED_ADDRESS" --policy "$here/$PENUMBRA_POLICY" \
  --page 127.0.0.1:8743 --timeout-secs 900 \
  session --node "$PENUMBRA_NODE" --grpc 127.0.0.1:8742 --approval-page 127.0.0.1:8744 \
  --ttl-secs "$PENUMBRA_SESSION_TTL_SECS" --state-dir "${HOME}/.cw-orch-kms/penumbra"
