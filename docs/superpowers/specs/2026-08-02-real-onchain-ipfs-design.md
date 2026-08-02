# Real on-chain + real IPFS (C1/C2 fix)

Date: 2026-08-02
Branch: `feat/real-onchain-ipfs`

## Problem

The current "blockchain" and "IPFS" layers are simulations:

- **C1**: `register_secret_on_chain` writes a local JSON file, calls `eth_blockNumber`
  only to "check responsiveness" (result discarded), and fabricates a fake
  `tx_hash = keccak256(secret_id)`. The Solidity contract is never deployed or called.
  All access controls (reads/expiry/revocation/recipient) are enforced by an editable
  local file at mode 0600. Zero tamper-resistance.
- **C2**: `upload_to_ipfs` falls back to `compute_mock_cid` → `QmBsecMock<sha256[..16]>`,
  which is not a valid IPFS CID, and stores the payload only on local disk. Cross-machine
  sharing (the product's purpose) cannot work.

## Strategy (approved)

**Real-when-configured, real-local fallback, never fake.**

- Every on-chain / IPFS operation performs the real network call against whatever the
  network-config points at — remote (Polygon Amoy, Pinata) **or** local infra
  (anvil `localhost:8545`, Kubo daemon `localhost:5001`).
- Infra unreachable → honest error naming what failed. **No fabricated tx hash, no mock
  CID, no discarded `eth_blockNumber` theater.**

## Components

### `eth.rs` (new) — JSON-RPC + transaction layer

- RPC helpers: `eth_chainId`, `eth_getTransactionCount(pending)`, `eth_gasPrice`,
  `eth_estimateGas`, `eth_sendRawTransaction`, `eth_getTransactionReceipt`, `eth_call`.
- **ABI encode** for `shareSecret`, `recordRead`, `revokeSecret`, `getSecretInfo`:
  selector = `keccak256(signature)[..4]`, then head/tail encoding
  (`bytes32`/`address`/`uintN`/`bool` static, `string` dynamic).
- **ABI decode** `getSecretInfo` return tuple → `OnChainSecretInfo`.
- **Signing** (legacy type-0 tx, EIP-155): RLP
  `[nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]` → keccak256 →
  `k256` recoverable ECDSA (`sign_prehash_recoverable`) → `v = chainId*2 + 35 + recid`
  → RLP signed tx → `eth_sendRawTransaction`. Poll receipt (~60s; instant on anvil).
- New crate: **`rlp`** (vetted parity encoder — no hand-rolled encoding in security code).
- Legacy tx chosen over EIP-1559: both Amoy + anvil accept it; skips fee-market estimation.

### `blockchain.rs` — real contract calls

- `register_secret_on_chain` → sign+send `shareSecret`, wait receipt, add id to local
  index, return **real** tx hash.
- `get_secret_info_on_chain` → `eth_call getSecretInfo` + decode.
- `record_read_on_chain` / `revoke_secret_on_chain` → signed txs.
- `list_secrets_on_chain` → local index ids → `getSecretInfo` per id → filter.
- `hide` → local-only visibility (contract has no `hidden`) + best-effort revoke.
- **Local index** `~/.bsec/secret_index.json`: `{ id → { role, hidden } }`. Pointer cache
  for enumeration + hidden flag only; authoritative state comes from chain.

### Signing-key plumbing

On-chain writes now require the wallet's secp256k1 key. Thread `&WalletInfo` (or derived
`SecretKey`) into the write paths:

- `share_secret` already holds `sender_info` → pass it down.
- `view_secret` → `record_read` reuses the already-unlocked key.
- `revoke` / `hide` in `main.rs` → already unlock the wallet for its address; pass the key.

Gas: the wallet address must hold native token (Amoy faucet, or funded on anvil).
Insufficient funds → RPC error surfaced honestly. Operational note, not code.

### `ipfs.rs` — real storage

- `upload`: Pinata `pinJSONToIPFS` (JWT from config / `BSEC_PINATA_JWT`) when set, else
  Kubo `/api/v0/add` at `api_url`. Real CID. None reachable → error. No mock.
- `fetch`: local cache → Kubo `cat` → configured gateway → public gateways.
- **Integrity**: payload is AES-256-GCM; a tampered or substituted blob fails AEAD auth
  or JSON parse → error, never silent compromise. Strict CID recomputation (which needs
  reproducing IPFS dag-pb/UnixFS chunking) is therefore unnecessary. This reasoning also
  closes review finding H7.

### `network_config.rs`

Add `ipfs.api_url` (default `http://127.0.0.1:5001`) and `ipfs.pinning_jwt: Option<String>`.
Keep `gateway` for fetch.

## Verification

- Local anvil (`chain_id 31337`, `localhost:8545`) + local Kubo daemon.
- Deploy `BsecSecretRegistry` to anvil, set `registry_address`.
- Fund the bsec wallet address from an anvil pre-funded account.
- Drive: `init` → `share` → `view` → `list` → `revoke`; confirm real tx hashes, real CIDs,
  and that a tampered local index cannot grant access (state read from chain).

## Follow-up (review findings, after C1/C2 verified)

H2 BIP-44 hard-fail · H3 unencrypted-wallet warning · M1 wire real `BsecError` ·
M2 file locking / drop write-on-read · M3 full 32-byte ids · M4 client-build error ·
M5 drop legacy `Get`/`Set` + `.master_key` · H1/H5 docs · H6 HKDF · low polish.
