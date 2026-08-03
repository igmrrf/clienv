# External Security Audit & Contract Verification Runbook

Step-by-step process for the two production gates that must be performed by a human and cannot
be automated in this repo:

1. **External smart-contract audit** of [`contracts/BsecSecretRegistry.sol`](../contracts/BsecSecretRegistry.sol) by an independent third party.
2. **On-chain contract verification** of the deployed bytecode on each target network.

These are release blockers before mainnet deployment. Track them on the checklist in
[`../production_readiness_report.md`](../production_readiness_report.md).

---

## 1. External Smart-Contract Audit

Self-review is insufficient for a contract that gates access, read limits, and expiration.
An independent auditor is required before mainnet.

### Step 1 — Freeze the audit scope

- Tag the exact commit to be audited: `git tag audit-vX.Y.Z && git push origin audit-vX.Y.Z`.
- Scope is `contracts/BsecSecretRegistry.sol` plus any library it imports.
- Freeze the Solidity compiler version and optimizer settings the audited build uses; the
  deployed bytecode must match this build exactly (see §2).
- Record the intended target networks and chain IDs (Polygon 137, Base 8453, etc.).

### Step 2 — Select an independent auditor

- Engage a firm or individual with **no authorship stake** in the contract.
- Reputable options: Trail of Bits, OpenZeppelin, ConsenSys Diligence, Spearbit, Cantina,
  Code4rena / Sherlock (competitive audit).
- Share: the frozen commit/tag, this repo's threat model (README "Security Model" section),
  the deployment guide, and the known-behavior notes below.

### Step 3 — Provide the auditor a threat-model briefing

Point the auditor at the areas the internal review already flagged so they can confirm or refute:

- **Read griefing**: `recordRead` skips the read-limit / authorization checks **and** the
  `readCount` increment for public secrets. Confirm no path lets a caller exhaust a
  non-applicable limit or waste storage-write gas.
- **Access control**: only the recorded `msg.sender` may `revokeSecret`. Confirm no other
  mutator bypasses sender identity.
- **Expiration & limits**: `expiresAt` / `maxReads` are enforced for non-public secrets only.
- **Integer / storage safety**: `readCount` overflow, re-entrancy on external calls, uninitialized
  storage, and event-log completeness for off-chain indexing.

### Step 4 — Triage findings

- Classify each finding: Critical / High / Medium / Low / Informational.
- Fix **all** Critical and High before deployment. Document accepted risk for Medium/Low with
  a written rationale.
- Re-audit (or request a fix-review) for any change to a Critical/High area.

### Step 5 — Publish the report

- Commit the final report to `docs/audits/BsecSecretRegistry-<firm>-<date>.pdf`.
- Link it from `production_readiness_report.md` and flip the checklist item to `[x]`.
- Record the audited commit hash so downstream verification (§2) can prove the deployed
  bytecode matches the audited source.

### Audit completion checklist

- [ ] Audit commit tagged and frozen
- [ ] Independent auditor engaged (no authorship stake)
- [ ] Threat-model briefing delivered
- [ ] All Critical/High findings fixed and re-reviewed
- [ ] Medium/Low findings fixed or risk-accepted in writing
- [ ] Final report committed under `docs/audits/`
- [ ] Report linked from `production_readiness_report.md`

---

## 2. On-Chain Contract Verification

After deploying to any public network, verify the source so users can audit the deployed
bytecode. Deployment commands live in [`smart_contracts.md`](smart_contracts.md) and
[`../deployment.md`](../deployment.md); this section is the **verification** procedure and its
sign-off checklist.

### Step 1 — Verify on the block explorer (Etherscan family)

Preferred: pass `--verify` during `forge create` (see the deployment guide). If deployment
succeeded but verification failed, verify retroactively:

```bash
forge verify-contract \
  <DEPLOYED_CONTRACT_ADDRESS> \
  contracts/BsecSecretRegistry.sol:BsecSecretRegistry \
  --chain-id <CHAIN_ID> \
  --etherscan-api-key "<EXPLORER_API_KEY>"
```

Explorer + API key per network:

| Network         | Chain ID | Explorer        | API key env            |
| :-------------- | :------: | :-------------- | :--------------------- |
| Polygon Mainnet | 137      | Polygonscan     | `POLYGONSCAN_API_KEY`  |
| Base Mainnet    | 8453     | Basescan        | `BASESCAN_API_KEY`     |
| Ethereum Mainnet| 1        | Etherscan       | `ETHERSCAN_API_KEY`    |

### Step 2 — Verify on Sourcify (explorer-independent)

Sourcify gives a chain-agnostic, decentralized verification record:

```bash
forge verify-contract \
  <DEPLOYED_CONTRACT_ADDRESS> \
  contracts/BsecSecretRegistry.sol:BsecSecretRegistry \
  --chain-id <CHAIN_ID> \
  --verifier sourcify
```

Confirm the match at `https://repo.sourcify.dev/contracts/full_match/<CHAIN_ID>/<ADDRESS>/`.

### Step 3 — Prove the deployed bytecode matches the audited source

- Confirm the compiler version + optimizer settings used to deploy equal those in the audited
  build (§1, Step 1).
- A **full match** on Sourcify (not just a partial match) proves metadata + source equality.
- Record the deployed address, chain ID, deploy tx hash, and audited commit in
  `production_readiness_report.md`.

### Verification completion checklist (per network)

- [ ] Contract verified on the network's block explorer
- [ ] Contract verified on Sourcify (full match)
- [ ] Compiler/optimizer settings match the audited build
- [ ] Deployed address + chain ID + deploy tx hash recorded
- [ ] Registry address configured in `bsec` (`bsec config --network <net> --registry 0x...`)
