# Changelog

## Unreleased — real on-chain + IPFS, security & correctness hardening

Production-readiness pass. Replaces the simulated blockchain/IPFS layers with real
implementations and fixes the security/correctness findings from the code review.

### Blockchain & IPFS are now real (was a local-file simulation)

- **On-chain registry.** `share`, `view`, `revoke`, and read-accounting now perform real
  signed transactions and `eth_call` reads against the configured RPC node (remote or local
  anvil). New `src/eth.rs` provides JSON-RPC, ABI encode/decode for `BsecSecretRegistry`,
  EIP-155 legacy transaction signing (secp256k1 via `k256`), and receipt polling, with a
  hand-rolled minimal RLP encoder covered by unit tests.
- **IPFS storage.** Payloads are stored via a real IPFS backend — Pinata (`pinFileToIPFS`,
  JWT) when configured, otherwise a Kubo daemon (`/api/v0/add`); fetch falls back through the
  local cache, Kubo `cat`, then gateways. The previous `QmBsecMock…` pseudo-CID is gone.
- **No fabricated success.** With no backend reachable, commands fail with a clear error
  naming what is unreachable — no fake transaction hashes, no mock CIDs.
- A local `secret_index.json` only enumerates the wallet's known secret IDs and a local
  `hidden` flag; authoritative state (reads, revocation, expiry, recipient) always comes from
  the chain.

### Security

- **BIP-44 derivation is now a hard failure** instead of silently falling back to a raw seed
  slice. The old fallback produced a non-standard key/address that would strand funds and make
  secrets un-decryptable.
- **Unencrypted wallets warn loudly** at creation — the private key and mnemonic are stored in
  plaintext (mode 0600) unless `--password` is given.
- **ECDH → AES key derivation uses HKDF-SHA256** with a domain-separation label, replacing a
  bare `SHA-256(shared_x)`.
- **Security model documented** in the README: confidentiality is cryptographic (AES-256-GCM +
  ECDH), but TTL / max-reads / revocation are advisory against a recipient who already fetched
  the payload; `--to public` provides no confidentiality.
- **Public secrets are not read-limited.** `recordRead` previously let any caller inflate a
  public secret's `readCount` and burn its `maxReads`, denying legitimate readers. Public
  secrets are readable by anyone and cannot be meaningfully read-limited, so the contract no
  longer enforces `maxReads`/authorization for them (the count is still tracked, informational);
  the Rust view path guards the same way.
- **Wallet plaintext zeroized on init.** The serialized wallet blob (plaintext private key +
  mnemonic) is wrapped in `Zeroizing` so the encrypted path does not leave it in freed memory.

### Correctness

- **Type-driven CLI exit codes.** Real `BsecError` variants are constructed at the key error
  sites, so `handle_cli_error`'s downcast now matches instead of guessing exit codes by
  substring-matching the message.
- **`get_wallet_info` is read-only.** Removed the write-on-read that rewrote `wallet.json`
  every read to bump `last_accessed` — it raced under concurrent invocations and rewrote the
  plaintext key for unencrypted wallets.
- **Full 256-bit secret IDs** (`0x` + 64 hex) map losslessly onto the contract `bytes32` key,
  replacing the previous 64-bit, ASCII-packed 16-char ID.
- **HTTP clients propagate build errors** instead of silently degrading to a no-timeout client.

### Removed

- **Legacy `get` / `set` key-value store** and its machine-local `~/.bsec/.master_key` (stored
  in plaintext next to its data). This parallel secret store added confusion and attack surface;
  the wallet, env-file, and on-chain secret flows are unaffected.

### Tooling & configuration

- `config --registry <addr>` sets the deployed registry address; network config gains
  `ipfs.api_url` and `ipfs.pinning_jwt` (also read from `BSEC_PINATA_JWT`).
- `docker-compose.yml`: anvil now binds `0.0.0.0` (the foundry image's `/bin/sh -c` entrypoint
  had swallowed the flags, leaving it on `127.0.0.1`); healthcheck uses `cast`.
- `scripts/e2e-setup.sh` provisions the full local stack (anvil + IPFS, contract deploy,
  wallet creation + funding); `docs/smart_contracts.md` documents the same steps.
- On-chain integration tests are gated behind `BSEC_E2E=1`; the default `cargo test` suite runs
  without any network.
