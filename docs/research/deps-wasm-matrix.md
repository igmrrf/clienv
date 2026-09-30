# bsec dependencies on `wasm32-unknown-unknown`: compile/run matrix and gating

Research ticket: which of `bsec`'s dependencies compile and run on
`wasm32-unknown-unknown`, and what gating (cfg, feature, replacement) each needs.
Intent: split the Rust 2024 CLI at `bitsec/` into a wasm-safe core crate plus
native adapters, consumed by a Leptos SSR web app.

**Scope note.** The question names a target-specific set of crates; some are
direct `bsec` deps, some arrive transitively (`getrandom`, `rand`). Verdicts are
for the exact versions in `bitsec/Cargo.lock`, retrieved/verified 2026-09-30.

## Method

Two independent lines of evidence, both primary:

1. **Empirical.** Compile probe crates against `wasm32-unknown-unknown` with a
   real toolchain, mirroring `bsec`'s exact versions and feature flags. Cargo
   check output is quoted in the appendix. Toolchain used: `rustup` stable
   **1.90.0** (the Homebrew `rustc 1.98.1` on `PATH` does *not* ship the wasm
   `rust-std`; the probe used `~/.rustup/toolchains/stable-*/bin/{cargo,rustc}`
   with `RUSTC` pinned, and the target confirmed working with a trivial
   `fn main(){}` build).
2. **Primary docs/source.** docs.rs rendered sources and crate docs for the exact
   versions (`reqwest` 0.12.28, `getrandom` 0.2.17 / 0.3.4 / 0.4.3, `dirs`
   6.0.0, `rpassword` 7.5.4, `tempfile` 3.27.0, `libc` 0.2.189, `clap` 4.6.4),
   plus the Leptos book for the SSR contract.

Locked versions examined: `clap` 4.6.4, `clap_complete` 4.6.7, `argon2` 0.5.3,
`k256` 0.13.4 (`ecdsa` 0.16.9, `elliptic-curve` 0.13.8), `bip39` 2.2.2,
`bip32` 0.5.3, `sha2` 0.10.9, `sha3` 0.10.9, `hkdf` 0.12.4, `aes-gcm` 0.10.3
(`aead` 0.5.2), `zeroize` 1.9.0, `dirs` 6.0.0 (`dirs-sys` 0.5.0), `rpassword`
7.5.4, `tempfile` 3.27.0, `libc` 0.2.189, `reqwest` 0.12.28, `rand` 0.8.7
(`rand_core` 0.6.4), `getrandom` 0.2.17 / 0.3.4 / 0.4.3.

Legend: ✅ works as-is on wasm · 🟡 compiles but is not usable in the browser /
needs a replacement · ❌ absent or impossible on wasm.

---

## TL;DR verdict table

| Dependency | Compiles on `wasm32-unknown-unknown` | Runs in the browser | Gating needed |
|---|---|---|---|
| `reqwest` (**`blocking`**) | ❌ module does not exist on wasm | ❌ | Replace with async `reqwest::Client`; server-only adapter |
| `reqwest` (async `json`, `multipart`) | ✅ | ✅ (Fetch API; TLS/cookies from browser) | none beyond using async; `blocking` feature is inert |
| `argon2` | ✅ | ✅ (pure Rust) | none |
| `k256` (`ecdsa`,`arithmetic`,`ecdh`) | ✅ | ✅ (pure Rust) | none |
| `bip39` | ✅ | ✅ (pure Rust) | none |
| `bip32` | ✅ | ✅ (pure Rust) | none |
| `sha2` | ✅ | ✅ | none |
| `sha3` | ✅ | ✅ | none |
| `hkdf` | ✅ | ✅ | none |
| `aes-gcm` | ✅ | ✅ | none for AES itself; `aead::OsRng` pulls `getrandom` → needs its wasm feature |
| `zeroize` (`derive`) | ✅ | ✅ | none |
| `rand` 0.8 | ✅ | ✅ | needs `getrandom` 0.2 `js` |
| `getrandom` **0.2** | ✅ only with `js` | ✅ | feature **`js`**; without it a `compile_error!` |
| `getrandom` **0.3 / 0.4** | ✅ only with `wasm_js` | ✅ | feature **`wasm_js`** (renamed from `js`) |
| `clap` (`derive`) | ✅ | ✅ (parsing works; CLI-only in practice) | none |
| `clap_complete` | ✅ | inert (native utility) | keep in native adapter; no cfg required |
| `dirs` 6 | ✅ (explicit wasm stub) | ❌ every fn returns `None` | Replace with injected base dir / web storage |
| `rpassword` 7.5.4 | ✅ (has a `wasm` module) | ❌ default TTY path fails | Replace with DOM input, or feed `ConfigBuilder::input_reader` |
| `tempfile` 3.27 | ✅ (build+link only) | ❌ no filesystem | Replace with in-memory buffers; native-only |
| `libc` | ✅ (empty shim; APIs absent) | ❌ | Already `cfg(unix)`-gated in `bsec`; keep it that way |

Headline: the entire cryptographic core (`argon2`, `k256`, `bip39`, `bip32`,
`sha2`, `sha3`, `hkdf`, `aes-gcm`, `zeroize`, `clap`) is wasm-clean. The two hard
walls are **`reqwest::blocking`** (the module is `#[cfg(not(wasm32))]`) and the
OS-shaped crates (`dirs`, `tempfile`, `rpassword`, `libc`). Randomness is the one
feature-flag gotcha, and it is a single well-documented switch.

---

## 1. `getrandom` — the one feature flag the whole core needs

This is the pivotal gating item because `rand` 0.8, `bip32`, `elliptic-curve`
(via `k256`), and `aead`/`aes-gcm`'s `OsRng` all funnel through
`rand_core 0.6` → **`getrandom 0.2`**. `cargo tree -i getrandom@0.2.17` confirms
`rand_core 0.6.4` is the sole parent, with dependents `bip32`, `elliptic-curve`/
`k256`, `crypto-common`/`aead`/`aes-gcm`, `argon2`, `hkdf`, `bip39`, `rand`.

**Rule per major version** (verified from the crate docs):

- **`getrandom 0.2`** — on `wasm32-unknown-unknown` it "is not automatically
  supported"; "*if the `js` Cargo feature is enabled*, this crate will assume …
  JavaScript, and will call the appropriate methods" (`Crypto.getRandomValues`,
  `crypto.randomFillSync` on Node). Without it you get a hard error:
  `the wasm*-unknown-unknown targets are not supported by default, you may need
  to enable the "js" feature.`
  ([getrandom 0.2.17 docs — WebAssembly support](https://docs.rs/getrandom/0.2.17/getrandom/#webassembly-support)).
- **`getrandom 0.3 / 0.4`** — the backend was renamed to **`wasm_js`** and is an
  ordinary opt-in feature; `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'` "is
  allowed but is no longer required and does nothing."
  ([getrandom 0.3.4 docs — Opt-in backends / WASM](https://docs.rs/getrandom/0.3.4/getrandom/#opt-in-backends),
  [feature list for 0.4.3](https://docs.rs/crate/getrandom/0.4.3/features)).

**Empirical proof (this repo's exact graph).** A core probe with
`getrandom = { version = "0.2", features = ["js"] }` finished wasm check cleanly.
Removing only that line produced:

```
error: the wasm*-unknown-unknown targets are not supported by default, you may need to enable the "js" feature.
   --> .../getrandom-0.2.17/src/lib.rs:346:9
346 |         compile_error!("the wasm*-unknown-unknown targets are not supported by ...
```

**What to add.** In the *final wasm binary crate* (the Leptos app / `-web`
crate), not in the reusable library:

```toml
[dependencies]
getrandom = { version = "0.2", features = ["js"] }
```

The getrandom docs explicitly bless this: "This can be done even if `getrandom`
is not a direct dependency. Cargo allows crates to enable features for indirect
dependencies." Library crates should *not* enable `js` themselves.

**Which versions actually appear.** In the production graph only `getrandom 0.2`
is reachable on wasm. `getrandom 0.3` comes solely from `proptest`
(dev-dependency) and `getrandom 0.4` solely from `tempfile` (native-only in the
split), so the core wasm build needs only the 0.2 `js` feature. If a future core
dependency ever pulls `getrandom 0.3/0.4`, add
`getrandom = { version = "0.4", features = ["wasm_js"] }` alongside it.

---

## 2. `reqwest` — blocking does not exist on wasm; use async

`bsec` uses `reqwest::blocking::{Client, multipart::Form}` in `src/eth.rs` and
`src/ipfs.rs`. On wasm this **does not exist at all**.

Primary source — `reqwest 0.12.28` `src/lib.rs` wraps the blocking module in the
not-wasm branch exactly:

```rust
if_hyper! {                       // #[cfg(not(target_arch = "wasm32"))]
    ...
    #[cfg(feature = "blocking")]
    pub mod blocking;
}

if_wasm! {                        // #[cfg(target_arch = "wasm32")]
    mod wasm;
    pub use self::wasm::{Body, Client, ClientBuilder, Request, RequestBuilder, Response};
}
```

The module docs state the same condition outright: *"Available on crate feature
`blocking` and not (WebAssembly and (`target_os=unknown` or bare-metal)) only."*
The crate-level WASM note adds: "Some of the features are disabled in wasm:
`tls`, `cookie`, `blocking`, as well as various `ClientBuilder` methods such as
`timeout()` and `connector_layer()`."
([reqwest 0.12.28 `lib.rs` source](https://docs.rs/crate/reqwest/0.12.28/source/src/lib.rs),
[`blocking` module docs](https://docs.rs/reqwest/0.12.28/reqwest/blocking/index.html).)

Empirically, a probe that enables `features = ["blocking","json","multipart"]` and
calls `reqwest::blocking::Client::new()` fails with:

```
error[E0433]: failed to resolve: could not find `blocking` in `reqwest`
note: found an item that was configured out
   --> reqwest-0.12.28/src/lib.rs:372:13   pub mod blocking;   (gated here)
```

**Nuances.**

- Merely *enabling* the `blocking` feature on wasm is harmless — the module is
  compiled out; it does not cause a build break by itself. Referencing the API
  does.
- The async client **does** work on wasm. A probe with
  `reqwest = { default-features = false, features = ["json","multipart"] }`
  calling `Client::new().get(..).send().await`, `.json(..)` and
  `reqwest::multipart::Form::new()` finished wasm check cleanly. `multipart` is
  re-exported on wasm (`#[cfg(feature="multipart")] pub use self::wasm::multipart;`).
  File/stream bodies are not available over Fetch; `bsec`'s IPFS uploads use
  in-memory `Part::bytes`, which fits.
- TLS/cookies are supplied by the browser; the native TLS features
  (`default-tls`/`native-tls`/`rustls`) are simply unused on wasm.

**Verdict.** ❌ as-is; **replace** the blocking client with an async
`reqwest::Client`. Architecturally this belongs in a **native/server adapter**:
expose async port methods on the core and provide two impls — `reqwest::blocking`
for the CLI and async `reqwest::Client` for the web server (callable inside a
Leptos `#[server]` function, which is necessarily async). The browser itself
should not talk to Pinata/RPC directly for requests that need secrets.

---

## 3. Pure-Rust crypto — all ✅ as-is

Verified by the wasm core probe (`Finished dev profile … in 11.81s`), which
linked and called each of these with `bsec`'s exact features:

| Crate | Notes |
|---|---|
| `argon2` 0.5.3 | Pure Rust. `Argon2::default().hash_password_into(pass, salt, out)` needs no OS entropy. Pure computation works on wasm. |
| `k256` 0.13.4 | RustCrypto secp256k1, `no_std`-capable pure Rust (features `ecdsa`, `arithmetic`, `ecdh` as used). `SecretKey`, `PublicKey`, `ecdh::diffie_hellman` all wasm-clean. |
| `bip39` 2.2.2 | Pure Rust; `Mnemonic::from_entropy` / `parse` / `to_seed` work. |
| `bip32` 0.5.3 | Pure Rust; `DerivationPath` parse and `XPrv::derive_from_path` work (k256 backend). |
| `sha2` 0.10.9 | Pure Rust, `no_std`. |
| `sha3` 0.10.9 | Pure Rust (`Keccak256` for the Ethereum address/hash path). |
| `hkdf` 0.12.4 | Pure Rust, `no_std`. |
| `aes-gcm` 0.10.3 | RustCrypto AES-GCM, pure Rust soft backend on wasm. Encrypt/decrypt and `Aes256Gcm::generate_nonce(&mut OsRng)` compile and run; `aead::OsRng` is the only reason it depends on `getrandom`. |
| `zeroize` 1.9.0 | Pure Rust; `Zeroizing`, `#[zeroize(drop)]` compile. |

`rand 0.8.7` also compiles/runs on wasm but is **conditional on the `getrandom`
`js` feature** (§1); `rand::random()` and `OsRng` are the only wasm-sensitive
paths.

---

## 4. OS-shaped crates — compile, but not usable in the browser

These are the crux of the core/adapter split. All three **compile** on
`wasm32-unknown-unknown` (probe with `dirs`, `rpassword`, `tempfile` finished
check cleanly), which is a trap: a clean `cargo check` does **not** mean they
work.

### `dirs` 6.0.0 — 🟡 compiles, all functions return `None`
`dirs/src/lib.rs` has an explicit wasm branch:

```rust
#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
use wasm as sys;
```

and `dirs/src/wasm.rs` is literally commented *"Stub definitions to make things
*compile*."* with `pub fn home_dir() -> Option<PathBuf> { None }` for every
function ([dirs 6.0.0 `lib.rs`](https://docs.rs/crate/dirs/6.0.0/source/src/lib.rs),
[`wasm.rs`](https://docs.rs/crate/dirs/6.0.0/source/src/wasm.rs)). `bsec` calls
`dirs::home_dir()` in `src/wallet.rs:71`. **Replace** with an injected base
directory (a core port) whose wasm impl uses browser storage, or keep the whole
wallet-file store in the native adapter.

### `tempfile` 3.27.0 — 🟡 build+link only, no filesystem
README "Supported Platforms": Linux/Android/macOS/Windows/BSDs/Redox, then
**"Wasm (build and link only, Wasm doesn't have a filesystem)"**
([tempfile 3.27.0 crate page](https://docs.rs/crate/tempfile/3.27.0)). It pulled
`getrandom 0.4` in the lock. `tempdir()`/`NamedTempFile` cannot work in a browser;
**replace** with an in-memory buffer (`Vec<u8>`) or keep it native-only.

### `rpassword` 7.5.4 — 🟡 has a wasm module, but no terminal
Locked 7.5.4 (declared `7.3.0`) is wasm-aware: `lib.rs` has
`#[cfg(target_family = "wasm")] mod wasm;`, and the crate description says
"unix, windows, macos, **wasm**". But the wasm impl reads from a
`FilePath`/`Reader`; the default `ConfigBuilder` uses
`DEFAULT_INPUT_PATH = "/dev/stdin"` and opens it with `std::fs::OpenOptions`,
which cannot work in a browser. `bsec` calls `rpassword::read_password()` in
`src/main.rs:453` ([`wasm.rs`](https://docs.rs/crate/rpassword/7.5.4/source/src/wasm.rs),
[`config.rs`](https://docs.rs/crate/rpassword/7.5.4/source/src/config.rs)).
**Replace** with a DOM password input; if `rpassword` is retained, only via
`read_password_with_config(..input_reader(reader))` with a reader supplied from
the web form. Effectively a native-adapter concern.

### `libc` 0.2.189 — ❌ APIs absent on wasm
`libc` builds for `wasm32-unknown-unknown` but exports essentially nothing: a
probe referencing `libc::c_int` failed with
`cannot find type c_int in crate libc`. The constants/functions `bsec` uses
(`O_NOFOLLOW`, `unlink`, `rmdir`, `signal`, `sighandler_t`, `c_char`, `_exit`)
are unix-only. `bsec` already does the right thing: `libc` is declared under
`[target.'cfg(unix)'.dependencies]` and every use is inside
`#[cfg(unix)]` / `#[cfg(not(unix))]` pairs (e.g. `wallet.rs:99–119`,
`materialize.rs:491–610`). **Keep as-is**; no wasm work needed.

---

## 5. `clap` / `clap_complete` — core-safe, native in purpose

Both compiled in the wasm core probe (`clap` 4.6.4 with `derive`,
`clap_complete` 4.6.7), including `clap::Command` and
`clap_complete::generate(Shell::Bash, …)` writing to an in-memory `Vec`.
`clap`'s default features (`std`, `color`, `help`, `usage`, `error-context`,
`suggestions`) are pure Rust with no OS dependency
([clap 4.6.4 `Cargo.toml`](https://docs.rs/crate/clap/4.6.4/source/Cargo.toml)).

Verdict: ✅ compile/run. `clap_complete` generation is inert in a browser — put
it in the CLI adapter, not the core. (If the core exposes a `clap`-derived
command tree so the CLI and a future wasm CLI share parsing, that is fine and
needs no gating.)

---

## 6. Architecture implication for the split (Leptos SSR)

Leptos server functions are **isomorphic and conditionally compiled**: "On the
server, the server function creates an HTTP endpoint … For the client-side/
browser build, the body of the server function is stubbed out." They must be
`async` and arguments/returns must be `serde`-serializable
([Leptos book §25 Server Functions](https://book.leptos.dev/server/25_server_functions.html)).
This maps cleanly onto the dependency verdicts:

- **Wasm-safe core** (`no_std`/`std`, pure): `argon2`, `k256`, `bip39`, `bip32`,
  `sha2`, `sha3`, `hkdf`, `aes-gcm`, `zeroize`, `serde`/`serde_json`,
  `thiserror`/`anyhow`, `base64`. Randomness only via a core port (or the
  documented `getrandom 0.2 js` feature enabled in the wasm binary).
- **Native/server adapter** (never in the wasm bundle): `reqwest::blocking`,
  `dirs`, `tempfile`, `rpassword`, `libc`, `clap_complete`, plus all `std::fs` /
  `std::process::exit` / `std::env` I/O currently in `wallet.rs`, `env_file.rs`,
  `materialize.rs`, `ipfs.rs`, `eth.rs`. Server functions wrap the sync core with
  `spawn_blocking` where needed (per the sibling `leptos-ssr-contract.md`).
- **Wasm/web adapter**: async `reqwest::Client` (Fetch), DOM password input,
  browser storage in place of `dirs`/`tempfile`, and a randomness source backed
  by `Crypto.getRandomValues`.

Non-dependency hazards worth flagging for the same split: `std::process::exit`,
`std::fs`, `std::env::var`, and the `libc` signal-cleanup handler in
`materialize.rs` are all native-only and must not leak into the core.

---

## Appendix A — probe reproduction

Using a rustup toolchain that actually has the wasm std (the Homebrew `rustc` on
`PATH` does not):

```sh
TOOL=~/.rustup/toolchains/stable-aarch64-apple-darwin
RUSTC=$TOOL/bin/rustc $TOOL/bin/cargo check --target wasm32-unknown-unknown
```

Five probe crates were used under a scratch dir:

1. **core** — `clap`(derive), `clap_complete`, `argon2`, `k256`, `bip39`,
   `bip32`, `sha2`, `sha3`, `hkdf`, `aes-gcm`, `zeroize`(derive), `rand`, plus
   `getrandom = { version = "0.2", features = ["js"] }`, with call sites for each.
   **Result:** `Finished dev profile [unoptimized + debuginfo] target(s) in 11.81s`.
2. **core_nojs** — same, minus the `getrandom` line. **Result:** fails with the
   `getrandom-0.2.17` `compile_error!` quoted in §1.
3. **native** — `reqwest`(`blocking`,`json`,`multipart`), `tempfile`, `dirs`,
   `rpassword`, `libc`. **Result:** `reqwest::blocking` unresolved (gated at
   `reqwest-0.12.28/src/lib.rs:372`), `std::os::unix` absent,
   `libc::O_NOFOLLOW` not found. (The `dirs`/`rpassword`/`tempfile` *crates*
   themselves compiled; only the `libc`/`blocking` call sites failed.)
4. **libs** — `dirs`, `rpassword`, `tempfile` only, calling
   `home_dir`/`config_dir`/`tempdir`/`NamedTempFile`/`read_password`.
   **Result:** `Finished dev profile … in 12.79s` (compiles; runtime unusable,
   §4).
5. **rqasync** — `reqwest` async with `default-features=false`,
   `features=["json","multipart"]`. **Result:** `Finished dev profile … in 25.12s`.
6. **libconly** — `libc` only, referencing `libc::c_int`. **Result:**
   `cannot find type c_int in crate libc`.

## Appendix B — sources

- reqwest: [`blocking` module docs](https://docs.rs/reqwest/0.12.28/reqwest/blocking/index.html),
  [`lib.rs` source](https://docs.rs/crate/reqwest/0.12.28/source/src/lib.rs).
- getrandom: [0.2.17](https://docs.rs/getrandom/0.2.17/getrandom/#webassembly-support),
  [0.3.4](https://docs.rs/getrandom/0.3.4/getrandom/#opt-in-backends),
  [0.4.3 features](https://docs.rs/crate/getrandom/0.4.3/features).
- dirs: [6.0.0 `lib.rs`](https://docs.rs/crate/dirs/6.0.0/source/src/lib.rs),
  [`wasm.rs`](https://docs.rs/crate/dirs/6.0.0/source/src/wasm.rs).
- rpassword: [7.5.4 `wasm.rs`](https://docs.rs/crate/rpassword/7.5.4/source/src/wasm.rs),
  [`config.rs`](https://docs.rs/crate/rpassword/7.5.4/source/src/config.rs).
- tempfile: [3.27.0 crate page / Supported Platforms](https://docs.rs/crate/tempfile/3.27.0).
- clap: [4.6.4 `Cargo.toml`](https://docs.rs/crate/clap/4.6.4/source/Cargo.toml).
- Leptos: [book §25 Server Functions](https://book.leptos.dev/server/25_server_functions.html).
