# Secret → File Materialization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a shared `bsec` secret be materialized into one or more real files (env/pem/json/cred), carry multi-file bundles, extract keys-only schemas, and stage files for `run` with wipe-on-exit — all additive, no contract change.

**Architecture:** All new metadata rides inside the AEAD-encrypted `IpfsPayload` (confidential + tamper-proof, no on-chain change). New `src/materialize.rs` owns filename safety, encoding, format resolution, single/bundle writing, schema extraction, and the RAII staged temp dir. `secrets.rs` gains `view_payload` (returns whole decrypted payload) so materialize sees metadata. `main.rs` gains a `Materialize` command + new `share` flags; `run` gains a `--secret` staging path.

**Tech Stack:** Rust 2024, clap, serde/serde_json, aes-gcm (OsRng), base64, zeroize, anyhow, tempfile.

## Global Constraints

- No smart-contract change; no on-chain storage of kind/filename.
- Backward compat: old 3-field `IpfsPayload` JSON must deserialize (serde defaults). Never reorder/rename existing fields.
- All written secret files: mode `0600` via `wallet::write_secure_file`. Staged dirs: `0700`.
- `no_export` blocks materialize (incl. schema) AND `view --output`; allows terminal `view` + `run` staging.
- Filenames from sender metadata are attacker-influenced → `sanitize_basename` rejects traversal.
- Bundle = ONE on-chain read, not N.
- Random temp names from `OsRng` hex, never timestamps.

---

### Task 1: Data model — extend `IpfsPayload` + new types

**Files:** Modify `src/secrets.rs`; Test: inline `#[cfg(test)]` in `src/secrets.rs`.

**Produces:** `SecretKind {Env,Pem,Json,Cred}`, `BundleMember {kind,filename,content,encoding,env}`, `IpfsPayload` new optional fields `kind, filename, no_export, members, content_encoding`.

- [ ] Add types + fields per spec §3/§7 with serde defaults.
- [ ] Test: old 3-field JSON deserializes → new fields None/false/utf8 default.
- [ ] Test: round-trip with members present.

### Task 2: `materialize.rs` primitives — `sanitize_basename`, `decode_body`, `OutputFormat`

**Files:** Create `src/materialize.rs`; register `mod materialize;` in `src/main.rs`.

**Produces:** `OutputFormat`, `sanitize_basename(&str)->Result<String>`, `decode_body(&str,&str)->Result<Vec<u8>>`.

- [ ] Tests: sanitize accepts `cert.pem`; rejects `../x`, `/etc/x`, `a/b`, `a\\b`, `~/x`, `x\0`, empty, `.`, `..`.
- [ ] Tests: base64 round-trip; utf8 passthrough; invalid base64 errors.

### Task 3: format resolution + `extract_schema`

**Files:** Modify `src/materialize.rs`.

**Produces:** `resolve_format(payload, explicit)`, `extract_schema(payload)->Result<String>`.

- [ ] Resolution order: explicit `--as` > `payload.kind` > content sniff > error.
- [ ] `extract_schema`: env/json/cred → sorted `KEY=`; pem/base64 → error; no values in output.

### Task 4: single + bundle materialization

**Files:** Modify `src/materialize.rs`.

**Produces:** `OutTarget`, `materialize_single(...)->Result<PathBuf>`, `materialize_bundle(...)->Result<Vec<PathBuf>>`. Enforce no_export, 0600, overwrite guard.

### Task 5: `secrets.rs` — `view_payload` + `share_secret` new params

**Files:** Modify `src/secrets.rs`.

**Produces:** `view_payload(id,addr,pw)->Result<IpfsPayload>` (does the read/record); `share_secret` extra params.

### Task 6: `main.rs` — `Materialize` command + `share` flags + bundle manifest

**Files:** Modify `src/main.rs`; bundle manifest parse in `materialize.rs`.

### Task 7: `run --secret` staging (`StagedDir`) + `view --output` no_export guard

**Files:** Modify `src/materialize.rs` (StagedDir), `src/env_file.rs` (run path), `src/main.rs` (view guard).

### Task 8: README + CHANGELOG

**Files:** Modify `README.md`, `CHANGELOG.md`.
