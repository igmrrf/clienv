#!/usr/bin/env bash
# End-to-end local setup: brings up anvil + IPFS, deploys BsecSecretRegistry,
# funds the bsec wallet, and points bsec at the local stack.
#
# Requirements: docker (compose). Foundry (forge/cast) is run via the foundry docker image,
# so no host install is needed.
#
# Usage:
#   ./scripts/e2e-setup.sh
#   BSEC_E2E=1 cargo test          # run the gated end-to-end integration tests
set -euo pipefail

RPC_URL="http://localhost:8545"
# anvil default account #0 (well-known dev key; testnet only).
ANVIL_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
FOUNDRY_IMG="ghcr.io/foundry-rs/foundry:latest"
BSEC="cargo run --quiet --"

echo "==> Starting anvil + IPFS"
docker compose up -d
echo "==> Waiting for anvil RPC"
for _ in $(seq 1 30); do
  if cast_out=$(docker run --rm --network host "$FOUNDRY_IMG" cast block-number --rpc-url "$RPC_URL" 2>/dev/null); then
    echo "    anvil up (block $cast_out)"; break
  fi
  sleep 1
done

echo "==> Deploying BsecSecretRegistry to anvil"
DEPLOY_OUT=$(docker run --rm --network host -v "$PWD/contracts:/contracts" "$FOUNDRY_IMG" \
  forge create /contracts/BsecSecretRegistry.sol:BsecSecretRegistry \
  --rpc-url "$RPC_URL" --private-key "$ANVIL_KEY" --broadcast)
REGISTRY=$(echo "$DEPLOY_OUT" | grep -Eo 'Deployed to: 0x[0-9a-fA-F]{40}' | awk '{print $3}')
echo "    registry: $REGISTRY"

echo "==> Configuring bsec for local stack"
$BSEC config --network local --rpc "$RPC_URL" --registry "$REGISTRY" --ipfs-gateway "http://localhost:8080/ipfs/"

echo "==> Initializing wallet"
$BSEC init --overwrite >/tmp/bsec-init.txt
WALLET_ADDR=$(grep -Eo 'Address: 0x[0-9a-fA-F]{40}' /tmp/bsec-init.txt | awk '{print $2}')
echo "    wallet: $WALLET_ADDR"

echo "==> Funding wallet with 100 ETH from anvil account #0"
docker run --rm --network host "$FOUNDRY_IMG" \
  cast send "$WALLET_ADDR" --value 100ether --rpc-url "$RPC_URL" --private-key "$ANVIL_KEY" >/dev/null
echo "    funded"

echo "==> Done. Local stack ready."
echo "    Run gated e2e tests:  BSEC_E2E=1 cargo test"
