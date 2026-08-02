# Secret → File Materialization (env / pem / json / cred / schema + bundles)

**Status:** Design approved, ready for implementation.
**Date:** 2026-08-02
**Scope:** Additive feature on the existing `bsec` share/view/run flow. No breaking changes; no smart-contract change.

---

## 1. Problem & Intent

Many apps consume secrets as **env vars** (covered today by `bsec run --env-file .env.enc -- <cmd>`, which injects vars into the child process with no plaintext on disk). But many apps instead require a **real file at a path**:

- TLS: `cert.pem` / `key.pem`
- Google: `service-account.json` (read via `GOOGLE_APPLICATION_CREDENTIALS=/path`)
- SSH `.netrc`, `kubeconfig`, `.npmrc`, keystores

And one app often needs **several** such files at once. Env injection can't produce files, and can't produce N distinct files.

This feature lets a shared secret be **materialized into one or more real files** (`.env`, `.pem`, `.json`, `cred`), lets a bundle carry several files at once, lets a `.env.schema` (keys-only) be extracted, and lets `run` stage files to a temp dir + inject their paths + wipe on exit. A sender can seal a secret (`--no-export`) so bsec refuses all file output.

**Backward compatibility is a first-class requirement:** existing shared secrets (which have no file metadata) must keep working — terminal `view`, `view --output`, and `run --env-file` behave exactly as before. New capability is purely additive.

---

## 2. Current State (what exists today — read before coding)

- `src/secrets.rs`
  - `IpfsPayload { content: String, content_key: String, ephemeral_pubkey: Option<String> }` — this JSON is AES-256-GCM/ECDH encrypted and stored on IPFS. **All new metadata rides inside this struct**, so it is confidential + AEAD-tamper-protected and needs no contract change.
  - `share_secret(...)` builds `IpfsPayload`, uploads to IPFS, registers on-chain.
  - `view_secret(secret_id, user_address, password) -> Result<String>` — decrypts, returns plaintext **String**. Calls `record_read_on_chain` (consumes a read).
  - `load_secret_as_env(...)` — used by `run` to get a `BTreeMap<String,String>` from a secret.
- `src/env_file.rs`
  - `parse_env_content(&str) -> BTreeMap<String,String>`, `validate_env_file`, `generate_template` (emits `KEY=#Your KEY here`), `encrypt_env_file`/`decrypt_env_file`, `load_and_parse_env`, `run_with_envs(env_file, secret_id, cmd, password)`.
  - `run_with_envs` decrypts in-memory and calls `child.env(k,v)` — **never writes a file**.
- `src/main.rs` — clap command enum. Relevant: `Share`, `View { id, output, password, json }`, `Run { env_file, secret_id, password, command }`.
- Schema file format (consumed by `validate`/`generate`): lines `KEY=` (empty value) or `KEY=<val>`, parsed by `parse_env_content`.
- Security model (README "Security Model & Limitations"): confidentiality is cryptographic; TTL/max-reads/revocation are advisory against a recipient who already fetched the payload.

---

## 3. Data Model — extend `IpfsPayload`

Add optional fields. Old payloads deserialize with these absent → `None` / `false` (serde `#[serde(default)]`). **Do not** reorder or rename existing fields.

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpfsPayload {
    pub content: String,
    pub content_key: String,
    pub ephemeral_pubkey: Option<String>,

    // --- new, all optional for backward compat ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<SecretKind>,          // intended file type of `content`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,          // suggested output filename (basename only)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_export: bool,                    // seal: refuse all file materialization
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<BundleMember>>, // present => this secret is a bundle
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretKind { Env, Pem, Json, Cred }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BundleMember {
    pub kind: SecretKind,
    pub filename: String,   // basename, e.g. "creds.json"
    pub content: String,    // the member's plaintext (whole payload is still AEAD-encrypted)
}
```

Notes:
- For a **bundle**, `members` is `Some(...)`. The top-level `content` MAY be empty (or a human note). Materialization iterates `members`.
- For a **single tagged file**, `members` is `None`; `content` is the file body, `kind`/`filename` describe it.
- `SecretRecord` (local index struct) does **not** need these fields — authoritative payload metadata lives only in the encrypted IPFS payload. Only add to `SecretRecord` if a specific view path needs it; prefer not to.

### Filename safety (critical)
`filename` and `BundleMember.filename` are attacker-influenced (set by sender). On materialization, **reject any filename that is not a plain basename**: reject if it contains `/`, `\`, `..`, a leading `~`, an absolute path, or a NUL. Always join under the user-chosen `--dir`/`--file`; never let sender metadata escape it. Add a `sanitize_basename(&str) -> Result<String>` helper and unit-test the traversal cases.

---

## 4. CLI Surface (`src/main.rs`)

### 4.1 `share` — new flags
```
--file <PATH>          Read file body as the secret content; infer kind from extension unless --as given.
--as <KIND>            One of: env | pem | json | cred. Explicit kind tag.
--filename <NAME>      Suggested output basename (default: basename of --file).
--bundle <MANIFEST>    Path to a bundle manifest JSON (see below); packs multiple files into one secret.
--no-export            Seal: mark payload.no_export = true.
```
- `--file` + `--as` set `payload.kind`, `payload.filename`, `payload.content = <file bytes as UTF-8/base64, see §7>`.
- `--bundle` reads a manifest, loads each listed file, builds `payload.members`. Mutually exclusive with `--file`/`--content`.
- Untagged share (`--content`/positional) = today's behavior (kind=None).

**Bundle manifest format** (`--bundle manifest.json`):
```json
{
  "members": [
    { "path": "./secrets/cert.pem",   "as": "pem",  "filename": "cert.pem" },
    { "path": "./secrets/creds.json",  "as": "json", "filename": "creds.json" },
    { "path": "./.env.prod",           "as": "env",  "filename": ".env" }
  ]
}
```
`as` optional (infer from extension); `filename` optional (default basename of `path`).

### 4.2 `materialize` — NEW command
```
bsec materialize <ID> [--dir <DIR>] [--file <PATH>] [--as <FMT>] [--password <PW>] [--force]
```
- `<FMT>`: `env | pem | json | cred | schema`. Default: the payload's `kind` (error if untagged and no `--as`, unless content-sniff succeeds — see §6).
- **Single secret:**
  - `--file <PATH>` → write there. Else `--dir <DIR>` + payload `filename` (or a sensible default per kind). Else current dir + filename.
- **Bundle:** requires `--dir` (or defaults to `./`); writes every member to `<dir>/<member.filename>`. `--file` is an error for bundles.
- `--as schema` → keys-only output (see §6.4). Valid for env/json/cred kinds; error for pem.
- All written files: mode `0600` (reuse `wallet::write_secure_file`). Dirs created `0700`.
- `--force` required to overwrite an existing file; otherwise error `refusing to overwrite <path> (use --force)`.
- **Decrypts ⇒ authorized read ⇒ consumes max-reads / calls `record_read_on_chain`** exactly like `view`. One materialize call = one read (a bundle counts as one read, not N).
- On success, print a loud warning: `WARNING: plaintext secret written to <path> (mode 0600). Delete when done.`

### 4.3 `run` — new `--secret` staging path
```
bsec run --secret <ID> -- <cmd...>
```
- Decrypts the secret. If it is a **bundle** (or a single file-kind secret), stage member files into a fresh `0700` temp dir under the OS temp root (e.g. `<tmp>/bsec-<random>/`).
- Inject env vars: for env-kind content, parse and inject KEY=VAL as today. For file members, inject `<UPPERCASE_STEM>_FILE=<abspath>` **and** well-known aliases where obvious (e.g. a member named `service-account.json` also sets `GOOGLE_APPLICATION_CREDENTIALS`). Keep the alias map tiny and documented; prefer explicit manifest control over magic (see Open Items).
- Run child (inherit stdio). **Wipe the temp dir on exit** — normal return, non-zero exit, signal, and panic. Use a guard struct with a `Drop` impl that removes the dir; also install a best-effort signal handler so SIGINT/SIGTERM still trigger cleanup before exit.
- Existing `run --env-file` and `run --secret-id`(current name) behavior stays; unify naming (see Open Items §9).

### 4.4 Random temp names without `Date.now`/`rand` foibles
Use `OsRng` (already a dependency via `aes_gcm`) to fill random bytes → hex for the temp dir suffix. Do not use timestamps.

---

## 5. `no_export` semantics (locked)

- `no_export == true` ⇒ `materialize` refuses **every** format **including `schema`**. Error: `sender sealed this secret (--no-export); terminal view only`.
- Terminal `view` (stdout) still works — that is the intended escape hatch.
- `view --output <file>` — **also refuse** when `no_export` (it writes plaintext to a file, same hazard as materialize). Error message as above.
- `run --secret` staging — **allowed** even when `no_export` (DEFAULT DECISION, with rationale): `run` writes only to a `0700` temp dir wiped on process exit; nothing persists, matching the "no lingering plaintext file" intent of the seal. This is the chosen default. If a future requirement wants the seal to also forbid `run` staging, gate it behind a second flag (`--no-run`) rather than overloading `--no-export`.
- **Honesty requirement:** `no_export` is an in-tool control only. A recipient holds the plaintext after decrypt and can persist it by other means. Document this in README security section; do not present it as a cryptographic guarantee.

---

## 6. Kind resolution, formats & schema

### 6.1 Resolution order for `materialize`/`view --file`
1. Explicit `--as <FMT>`.
2. `payload.kind`.
3. Content sniff (backward compat for untagged old secrets): looks like `KEY=VAL` lines ⇒ env; parses as JSON ⇒ json; `-----BEGIN` ⇒ pem; else treat as opaque `cred`.
4. If still unresolved and output needs a format ⇒ error asking for `--as`.

### 6.2 Extension inference for `share --file` (when `--as` omitted)
`.env`/`.env.*` ⇒ env; `.pem`/`.crt`/`.key` ⇒ pem; `.json` ⇒ json; else ⇒ cred.

### 6.3 File writing per kind
- `env` — write content verbatim if already `KEY=VAL` lines; if the source was a map, emit sorted `KEY=VAL`.
- `json` — write verbatim; optionally pretty-print if `--as json` and content parses.
- `pem` / `cred` — write bytes verbatim (opaque). Never reformat.

### 6.4 `--as schema` (keys-only)
- Valid only for env/json/cred that parse into a key set. Parse with `parse_env_content` (env/cred) or JSON object keys (json).
- Emit sorted `KEY=` lines (reuse the existing schema format that `validate`/`generate` consume). **No values.**
- pem / non-keyed content ⇒ error `secret is kind=pem; no schema to extract`.
- Blocked entirely when `no_export` (§5).
- Warn: `NOTE: key names disclosed (values withheld).`

---

## 7. Binary / non-UTF-8 content

Secret file bodies (esp. `pem`, keystores) may be binary. `IpfsPayload.content` is a `String`.
- Store binary members **base64-encoded** with a per-member `encoding: "base64" | "utf8"` field on `BundleMember` (and an equivalent for the single-file case — add `content_encoding: Option<String>` to `IpfsPayload`, default utf8).
- Materialization decodes base64 back to raw bytes before writing. Env/schema formats require utf8 (error if a base64/binary member is asked to become a schema).

Add `encoding` handling to §3 structs:
```rust
// BundleMember gains:
#[serde(default = "enc_utf8")] pub encoding: String, // "utf8" | "base64"
// IpfsPayload gains:
#[serde(default, skip_serializing_if = "Option::is_none")] pub content_encoding: Option<String>,
```

---

## 8. Module layout & signatures

New: `src/materialize.rs`
```rust
pub enum OutputFormat { Env, Pem, Json, Cred, Schema }

/// Decode a payload member/body to raw bytes per its encoding.
pub fn decode_body(content: &str, encoding: &str) -> Result<Vec<u8>>;

/// Reject anything that is not a safe basename (no traversal, no separators, no abs path).
pub fn sanitize_basename(name: &str) -> Result<String>;

/// Materialize a single decrypted secret to a path/dir. Enforces no_export, 0600, overwrite guard.
pub fn materialize_single(payload: &IpfsPayload, fmt: OutputFormat, out: OutTarget, force: bool) -> Result<PathBuf>;

/// Materialize a bundle's members into dir. Returns written paths.
pub fn materialize_bundle(payload: &IpfsPayload, dir: &Path, force: bool) -> Result<Vec<PathBuf>>;

/// Emit keys-only schema text for a keyed secret. Errors on pem/opaque.
pub fn extract_schema(payload: &IpfsPayload) -> Result<String>;

/// RAII temp dir (0700) that wipes itself on Drop; used by `run --secret`.
pub struct StagedDir { /* path */ }
impl StagedDir { pub fn new() -> Result<Self>; pub fn path(&self) -> &Path;
                 pub fn stage_member(&self, m: &BundleMember) -> Result<PathBuf>; }
impl Drop for StagedDir { /* recursive remove, best-effort */ }
```

Changes:
- `src/secrets.rs` — extend `IpfsPayload` (§3, §7); `share_secret` accepts new params (`kind`, `filename`, `no_export`, `members`, `content_encoding`); expose a `view_payload(secret_id, user_addr, password) -> Result<IpfsPayload>` that decrypts and returns the **whole** payload (materialize needs metadata, not just the flattened String). `view_secret` can delegate to it.
- `src/env_file.rs` / `run` — add the `--secret` staging path using `materialize::StagedDir`; keep env injection.
- `src/main.rs` — new `Materialize` command; `share` flags; `run --secret`.
- README — extend Security Model section per §5 honesty requirement + a "Materializing secrets to files" usage section.
- CHANGELOG — new entry.

---

## 9. Open items for implementer (decide + note in PR)

1. **`run` secret flag naming.** Today there is a `--secret-id` on `run`; this spec says `--secret`. Unify to one (`--secret <ID>`), alias the old for compat, or keep both. Pick, document.
2. **Env alias magic** (§4.3). Minimal well-known map (`service-account.json → GOOGLE_APPLICATION_CREDENTIALS`) is convenient but surprising. Safer default: only inject `<STEM>_FILE=<path>` and let the manifest optionally specify `"env": "GOOGLE_APPLICATION_CREDENTIALS"` per member. **Recommended:** manifest-driven `env` key per member; drop the magic map. Add `env: Option<String>` to `BundleMember` and the manifest.
3. Whether `SecretRecord`/local index should cache `kind`/`filename` for nicer `list` output. Default: no (keep authoritative metadata in the encrypted payload only).

---

## 10. Edge cases & errors (must handle)

- Untagged old secret + `materialize` with no `--as` and unsniffable content → clear error requesting `--as`.
- `--file` given for a bundle → error (bundles need `--dir`).
- Overwrite without `--force` → error.
- `no_export` + any file output (materialize, schema, `view --output`) → refuse (§5).
- Filename traversal attempt in payload/manifest → `sanitize_basename` rejects.
- base64 member asked to become `schema`/`env` → error (needs utf8 keyed content).
- Bundle counts as **one** on-chain read, not N.
- Temp dir cleanup must fire on signal/panic, not only normal return.
- Expired / revoked / read-limit-exceeded secret → same errors as `view` (materialize is a read).

---

## 11. Testing

Unit (`cargo test`, no network):
- `sanitize_basename` — accepts `cert.pem`; rejects `../x`, `/etc/x`, `a/b`, `~/x`, `x\0`.
- `IpfsPayload` serde round-trip **old JSON** (only 3 original fields) → new struct with `None`/`false` defaults. Guards backward compat.
- Kind resolution order (explicit > kind > sniff).
- `extract_schema` — env/json/cred → sorted `KEY=`; pem → error; values never present in output.
- base64 encode/decode round-trip for a binary member.
- `no_export` blocks materialize + schema + `view --output`; allows terminal view + `run` staging.

Integration (gated behind `BSEC_E2E=1`, real anvil + IPFS, mirrors existing e2e style):
- share `--file cert.pem --as pem` → materialize to `--dir` → bytes identical, mode 0600.
- share `--bundle` (pem + json + env) → materialize all three → files present; then `run --secret <id> -- sh -c 'test -f "$X_FILE"'`.
- `run --secret` leaves **no** temp dir after exit (assert cleanup); interrupt (SIGTERM) also cleans up.
- `materialize --as schema` yields keys, no values; consumes exactly one on-chain read.
- Backward compat: a secret shared **before** this feature (untagged) still `view`s and `run --env-file` still injects.

Acceptance = all unit tests pass under default `cargo test`; e2e green under `BSEC_E2E=1`; `run --env-file .env.enc` and terminal `view` behavior unchanged; no smart-contract change.

---

## 12. Non-goals

- No contract change. No on-chain storage of kind/filename (stays inside encrypted payload).
- No cross-format conversion beyond schema extraction (don't turn a pem into json, etc.).
- No attempt to make `no_export` cryptographically unbypassable — it is an in-tool, advisory control (documented).
- No secret *editing* / re-share flow — out of scope.
