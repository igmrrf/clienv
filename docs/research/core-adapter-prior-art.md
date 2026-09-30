# Pure Core + Native/WASM Adapters: Prior Art and Rust Conventions

Research ticket: established Rust patterns for splitting a CLI into a reusable
pure core plus native adapters, where the same core is consumed by a web/WASM
app. Context: `bsec` (a blocking CLI) is to split into something like
`bitbid-core` (pure: crypto, ABI/RLP, parsing), `bitbid-adapters` (fs,
`reqwest` blocking, process, terminal) and a `bitbid` binary; a Leptos SSR app
consumes `bitbid-core`.

Primary sources retrieved 2026-09-30. Secondary/blog sources are labelled as
such; all claims link to the owning source.

---

## TL;DR

1. **Layout:** a virtual Cargo workspace at the repo root, `crates/*` members,
   `core`/`adapters`/`cli` split. "Core" crates carry a `-core` suffix by
   strong convention (`alloy-core`, `bitwarden-core`, `banker-core`,
   `polars-core`); Rust's own API guidelines only forbid `-rs`/`-rust` suffixes.
2. **Native vs wasm:** the core must be **`no_std` + `alloc`-by-default** and
   gate native I/O out via `#[cfg]`/features. The standard vocabulary is
   `default = ["std"]` + `#[cfg(feature = "std")]`, plus
   `target_arch = "wasm32"` / `target_family = "wasm"` for target gating.
   Target-specific *dependencies* go in `[target.'cfg(...)'.dependencies]`; you
   **cannot** use `cfg(feature = ...)` in `[target]` sections.
3. **Ports & adapters:** in Rust the port *is* a trait defined by the core,
   implemented by adapters, wired only in the composition root (`main.rs`). The
   strongest real-world variant is the **sans-I/O core**: a pure state machine
   that defines storage/network traits and ships an in-memory/dummy impl, with
   real adapters (`sqlite`, `indexeddb`, `reqwest`) supplied from outside.
4. **Avoiding duplicated crypto/ABI:** every serious project surveyed pushes
   shared primitives down into `no_std` crates and keeps `wasm-bindgen`/UniFFI
   in a **thin binding crate that contains no logic**. Bitwarden's WASM crate
   states this as a rule; Matrix and CosmWasm do the same structurally.
5. **Concrete prior art:** Bitwarden SDK, Matrix Rust SDK, Alloy, CosmWasm,
   rust-bitcoin, revm (details in §4).

---

## 1. Crate naming and workspace layout

### 1.1 The tool Cargo gives you

A **virtual manifest** (a root `Cargo.toml` with `[workspace]` and no
`[package]`) is the canonical shape when there is no single primary package:
"typically useful when there isn't a 'primary' package, or you want to keep all
the packages organized in separate directories"
([Cargo Book — Workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html)).

The root manifest is the only place `[profile.*]`, `[patch]`, and `[replace]`
are honoured. It also centralises:

- `[workspace.package]` — `version`, `edition`, `license`, `authors`,
  `repository` inherited with `version.workspace = true`
  ([workspaces §package table](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-package-table)).
- `[workspace.dependencies]` — one version/feature set inherited with
  `dep.workspace = true`; features declared there are **additive** with the
  member's own ([workspaces §dependencies table](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-dependencies-table)).
- `[workspace.lints]` — shared lint config inherited with `[lints] workspace = true`
  ([workspaces §lints table](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-lints-table)).

`members = ["crates/*"]` with globs is the standard inclusion idiom; a path
dependency that lives inside the workspace directory automatically becomes a
member ([workspaces §members](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-members-and-exclude-fields)).

For a crate that will be published and depended on both by the binary and by
the web app, declare both `path` and `version` so local dev uses the working
tree and a publish resolves to the registry
([Cargo Book — Multiple locations](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#multiple-locations)):

```toml
bitbid-core = { path = "crates/core", version = "0.1.0" }
```

### 1.2 Naming conventions

- The Rust API Guidelines are explicit: "Crate names should not use `-rs` or
  `-rust` as a suffix or prefix. Every crate is Rust!"
  ([Rust API Guidelines — C-CASE](https://rust-lang.github.io/api-guidelines/naming.html#casing-conforms-to-rfc-430-c-case)).
  There is no rule against `-core`; the suffix is a community convention, not a
  requirement.
- Cargo package names may contain `-`; the crate that code imports is the
  underscore form (`bitbid-core` → `bitbid_core`). A library can be renamed on
  import with the `package` key when a short name is wanted
  ([Cargo Book — Renaming dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#renaming-dependencies-in-cargotoml)).
- The `-core` suffix is near-universal for "the pure part": `alloy-core`,
  `bitwarden-core`, `matrix-sdk-base` (the un-suffixed equivalent), `banker-core`,
  `polars-core`. rust-bitcoin uses `bitcoin_hashes`, `bitcoin-internals`,
  `bitcoin-io`, `bitcoin-units`, `bitcoin-primitives` inside one workspace
  ([rust-bitcoin/Cargo.toml](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/Cargo.toml)).

### 1.3 Layout patterns from real projects

| Project | Layout | Notes |
|---|---|---|
| Bitwarden SDK | monorepo, `crates/bitwarden-*`; categories: Bindings / Application Interfaces / Features / Core & Utility | higher crates depend on lower, "never the reverse" ([crate structure](https://contributing.bitwarden.com/architecture/sdk/crate-structure/)) |
| Matrix Rust SDK | `crates/*` + `bindings/*` + `testing/*` | documented layered graph; `matrix-sdk-base` and `matrix-sdk-crypto` are sans-I/O ([ARCHITECTURE.md](https://github.com/matrix-org/matrix-rust-sdk/blob/main/ARCHITECTURE.md)) |
| Alloy | `crates/primitives`, `crates/sol-types`, `crates/dyn-abi`, `crates/json-abi`, … under one workspace | every crate supports `no_std + alloc` ([alloy-rs/core README](https://github.com/alloy-rs/core#note-on-no_std)) |
| rust-bitcoin | workspace members `addresses`, `hashes`, `internals`, `io`, `primitives`, `units`, `bitcoin`, … | `resolver = "2"` ([Cargo.toml](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/Cargo.toml)) |

A worked, minimal example explicitly named in the ticket's shape is the
`banker` project: `banker-core` (domain + ports), `banker-adapters`
(infrastructure impls), `banker-fixtures` (test doubles), `banker-http`
(driving adapter). This is a maintainer blog, not an official doc, but it is a
faithful illustration ([Hexagonal Architecture in Rust — Cogs and Levers](https://tuttlem.github.io/2025/08/31/hexagonal-architecture-in-rust.html)).
A compiler-enforced template with the same shape is
[llmgraph-ai/hexagonal-rust-template](https://github.com/llmgraph-ai/hexagonal-rust-template)
(`domain`, `application`, `adapters`, `server`), which notes "the compiler is
the linter" because `domain` does not depend on the adapter crate.

---

## 2. Feature-flag and `cfg`-gating conventions for native vs wasm

### 2.1 `cfg` predicates you should use

- `target_arch = "wasm32"` / `not(target_arch = "wasm32")` is the basic
  discriminator. The Rust Reference documents `target_arch`, and also
  `target_family = "wasm"` (which can be true alongside `"unix"` for WASI)
  ([Rust Reference — Conditional compilation](https://doc.rust-lang.org/reference/conditional-compilation.html)).
- `#[cfg_attr(pred, attr)]` lets you conditionally attach attributes, e.g.
  `#[cfg_attr(target_os = "linux", path = "linux.rs")]`
  ([Rust Reference — cfg_attr](https://doc.rust-lang.org/reference/conditional-compilation.html#the-cfg_attr-attribute)).
- For readability, `cfg_aliases` defines real `#[cfg(wasm)]` / `#[cfg(native)]`
  names in `build.rs` and emits `cargo::rustc-check-cfg` so `unexpected_cfgs`
  stays quiet ([cfg_aliases docs](https://docs.rs/cfg_aliases/)). Example from
  the crate docs:

  ```rust
  cfg_aliases! {
      wasm: { target_arch = "wasm32" },
      native: { not(target_arch = "wasm32") },
  }
  ```

### 2.2 Feature conventions

- Follow Cargo's additive-feature rule and the API Guidelines' `std` convention:
  "if you want to optionally support `no_std` … **do not** use a `no_std`
  feature. Instead, use a `std` feature that *enables* `std`"
  ([features §feature unification](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification));
  the canonical manifest is `default = ["std"]`, `std = []`
  ([API Guidelines — C-FEATURE](https://rust-lang.github.io/api-guidelines/naming.html#feature-names-are-free-of-placeholder-words-c-feature)).
- Use `dep:` to keep internal optional deps out of the public feature surface:
  `avif = ["dep:ravif", "dep:rgb"]`
  ([features §optional dependencies](https://doc.rust-lang.org/cargo/reference/features.html#optional-dependencies)).
- Features are **unified across the graph**, so a `std` feature enabled by one
  consumer builds the dependency once, with `std`, everywhere. This is why a
  core crate must never make functionality *disappear* when a feature is
  enabled; features are additive or they are wrong
  ([features §feature unification](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification)).
- Mutually exclusive features are an anti-pattern; if unavoidable, add
  `#[cfg(all(feature = "a", feature = "b"))] compile_error!(...)` and prefer
  splitting into separate crates
  ([features §mutually exclusive features](https://doc.rust-lang.org/cargo/reference/features.html#mutually-exclusive-features)).
- Resolver `"2"` (or `"3"` in edition 2024) matters for native/wasm: it stops
  target-specific dependencies for *other* targets from leaking their features
  into the current build
  ([features §resolver 2](https://doc.rust-lang.org/cargo/reference/features.html#feature-resolver-version-2)).

### 2.3 Target-specific dependencies

Native-only crates must not be declared as unconditional dependencies of the
core, or they will be dragged into the wasm build. Put them under a target:

```toml
[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
reqwest = { version = "0.12", features = ["blocking", "json"] }
```

The Cargo Book documents the `[target.'cfg(...)'.dependencies]` form and warns
that **feature-based** target sections do not work: "you cannot use
`[target.'cfg(feature = "fancy-feature")'.dependencies]`", nor
`cfg(debug_assertions)` / `cfg(test)` / `cfg(proc_macro)`
([Cargo Book — Platform specific dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#platform-specific-dependencies)).

### 2.4 The `getrandom` / `wasm32-unknown-unknown` trap

Any core code that draws randomness (key generation, nonces, salts) will hit
`getrandom`. `wasm32-unknown-unknown` is unsupported by default because from
the target name alone the crate "cannot deduce which JavaScript interface
should be used (or if JavaScript is available at all)". Enable it with the
`wasm_js` feature (and, on `getrandom` 0.3.x, also
`RUSTFLAGS='--cfg getrandom_backend="wasm_js"'`; 0.3.4+ enables the backend by
default once the feature is on) ([getrandom WASM support](https://docs.rs/getrandom/#webassembly-support),
[getrandom 0.3.4 changelog](https://github.com/rust-random/getrandom/blob/master/CHANGELOG.md),
[0.3.4 manifest `wasm_js = ["dep:wasm-bindgen", "dep:js-sys"]`](https://docs.rs/crate/getrandom/0.3.4/source/Cargo.toml.orig)).

The rule of thumb from the Rust WASM book: "if a crate supports embedded and
`#![no_std]` usage, it probably also supports WebAssembly"
([Which crates work with WebAssembly?](https://rustwasm.github.io/book/reference/which-crates-work-with-wasm.html)).

### 2.5 Leptos SSR specifics

Leptos compiles the *same* app twice: server with the `ssr` feature, browser to
`wasm32-unknown-unknown` with the `hydrate` feature; `cargo-leptos` coordinates
both ([Life of a Page Load](https://book.leptos.dev/ssr/22_life_cycle.html)).
Two consequences for the core:

- "everything in your application must be able to run on both the client and
  the server" ([Life of a Page Load](https://book.leptos.dev/ssr/22_life_cycle.html)),
  so a **shared core** consumed by components must compile on both.
- Server-only deps "in your `Cargo.toml` … mark them `optional = true` and then
  enable them in the `ssr` feature definition"; client-only code is gated with
  `#[cfg]` or run inside `Effect::new`
  ([Hydration Bugs](https://book.leptos.dev/ssr/24_hydration_bugs.html)).
- Server functions are `async` and serialize args/results; use fixed-width
  integers because the wasm side is 32-bit
  ([Server Functions](https://book.leptos.dev/server/25_server_functions.html)).

This is the same `ssr`/`hydrate` feature-gate idiom Cargo documents; the sibling
research note [`leptos-ssr-contract.md`](./leptos-ssr-contract.md) covers the
core's obligations to Leptos in detail.

---

## 3. Ports-and-adapters / hexagonal design in Rust

### 3.1 The shape

The recurring structure across sources:

```
        driving adapters                    driven adapters
     (cli, http, wasm)                   (fs, reqwest, sqlite)
             │ call                              ▲ implement
             ▼                                   │
        application (use cases)  ──────►  ports (traits owned by core)
             │ uses
             ▼
        domain (pure: types + rules, no I/O)
```

The composition root (`main.rs`, or a `bootstrap` module) is the only place
that names concrete adapters. This is the Rust-idiomatic substitute for a DI
container ([The Deterministic Hexagon](https://imgabriel.dev/architecture/),
a named-style essay, and [llmgraph template](https://github.com/llmgraph-ai/hexagonal-rust-template),
[banker write-up](https://tuttlem.github.io/2025/08/31/hexagonal-architecture-in-rust.html)).

### 3.2 Practical rules, with sources

- **Ports are traits the core owns**, named for the *conversation* not the
  technology (`Store`, `Clock`, `Rng`, `UserRepository` — never `PostgresRepo`).
  A port signature should speak domain types only; letting `std::io::Error` or a
  wire format into a port leaks the adapter
  ([The Deterministic Hexagon](https://imgabriel.dev/architecture/)).
- **Keep ports few and thick, and split by concern.** A 47-method `Repository`
  is the named failure mode; prefer focused traits (`UserFinder`, `UserWriter`,
  `UserStatistics`) so tests need only implement what they touch
  ([Ports as Traits](https://rustz2h.com/chapter_16_advanced_architecture_and_idiomatic_rust/series_02_domain_driven_design_and_architecture/ports_as_traits)).
- **Choose `dyn` vs generics deliberately.** `&dyn Port` for the edge
  (composition root, application services) keeps signatures and compile times
  sane; generics only on hot paths where a profile demands it
  ([The Deterministic Hexagon](https://imgabriel.dev/architecture/)).
- **Async ports:** native `async fn in trait` is now usable, but if the core
  must stay `no_std`/sync it should expose **synchronous** ports and let the
  adapter or server function wrap them in `spawn_blocking` — this matches the
  "sans-I/O, state machine in, action out" model (see Matrix and revm below).
- **Inbound/driving ports** (the CLI verb, the HTTP handler, the wasm export)
  should each translate their input into a use-case call; the use case is the
  shared seam, so CLI and web exercise identical logic
  ([banker](https://tuttlem.github.io/2025/08/31/hexagonal-architecture-in-rust.html),
  [llmgraph template](https://github.com/llmgraph-ai/hexagonal-rust-template)).

### 3.3 The sans-I/O variant (strongest fit for crypto + wasm)

The Matrix Rust SDK's own architecture doc calls two crates *sans I/O*:
`matrix-sdk-crypto` is "a *sans I/O* implementation of a state machine that
handles end-to-end encryption … It defines a `CryptoStore` trait … as well as a
dummy in-memory implementation" ([ARCHITECTURE.md](https://github.com/matrix-org/matrix-rust-sdk/blob/main/ARCHITECTURE.md)).
`matrix-sdk-base` does the same for `StateStore`/`EventCacheStore`. Real
backends (`matrix-sdk-sqlite`, `matrix-sdk-indexeddb` for the browser) are
separate crates implementing those traits. This is exactly the pattern a
crypto/ABI core should adopt: the core holds the state machine and the ports,
and *every* environment (native CLI, server, browser) supplies its own store
and network adapter.

CosmWasm encodes the same idea at the contract level: `cosmwasm-std` is compiled
both to wasm (with entry points) and to native code (for tests), and the std
crate gates accordingly:

```rust
#[cfg(all(feature = "exports", target_arch = "wasm32"))]
// ... entry-point wrappers
#[cfg(not(target_arch = "wasm32"))]
pub mod testing; // "Both unit tests and integration tests are compiled to native code"
```

([cosmwasm-std `lib.rs` source](https://docs.rs/cosmwasm-std/latest/src/cosmwasm_std/lib.rs.html)).
The per-contract idiom is `#[cfg_attr(not(feature = "library"), entry_point)]`
so the *same* source compiles as a native library for tests and as a wasm
contract for deployment ([Entry points — CosmWasm book](https://book.cosmwasm.com/basics/entry-points.html),
[Entrypoints docs](https://cosmwasm.github.io/core/entrypoints)).

---

## 4. Prior art: how real projects avoid duplicate crypto/ABI across native and wasm

### 4.1 Bitwarden SDK — the closest analogue (secret manager)

A secret manager with a Rust core consumed by CLI, web (WASM) and mobile
(UniFFI). The repo's own docs group crates into Bindings / Application
Interfaces / Features / Core & Utility, with the rule that "higher-level crates
depend on lower-level ones, but never the reverse." `bitwarden-core` provides
the shared runtime (client init, auth state, HTTP) and `bitwarden-crypto` "owns
all cryptographic primitives — encryption, decryption, key derivation, and key
management" ([Crate structure](https://contributing.bitwarden.com/architecture/sdk/crate-structure/)).

The WASM binding crate is explicitly logic-free:

> "Bitwarden WASM internal exposes WebAssembly bindings for the Bitwarden SDK.
> This crate should contain no logic but rather only handle WASM unique
> conversions and bindings. **Business logic MUST be placed in the relevant
> feature crates.**"
> — [bitwarden-wasm-internal docs](https://sdk-api-docs.bitwarden.com/bitwarden_wasm_internal/index.html)

Crypto is shared, not reimplemented: `bitwarden-crypto` exposes a `wasm` feature
(`wasm -> dep:tsify, dep:wasm-bindgen`) and there is a parallel `uniffi` feature
for mobile ([bitwarden-crypto on crates.io](https://crates.io/crates/bitwarden-crypto)).
The top-level facade crate depends on both core and crypto by path with `=3.0.0`
pins ([Cargo.toml](https://github.com/bitwarden/sdk-internal/blob/main/Cargo.toml)).

**Teaches:** name a pure `-core` runtime and a pure `-crypto`; keep bindings in
a zero-logic crate; expose one `wasm` feature that turns on `wasm-bindgen` +
`getrandom` js; never fork crypto for the browser.

### 4.2 Matrix Rust SDK — sans-I/O crypto with swap-in stores

Versioning: crypto lives in `matrix-sdk-crypto`, described as a sans-I/O state
machine defining a `CryptoStore` trait. `matrix-sdk-indexeddb` implements
`CryptoStore`/`StateStore`/`EventCacheStore` "for an indexeddb backend (for use
in Web browsers, via WebAssembly)"; `matrix-sdk-sqlite` implements the same
traits natively. The wasm entry point is a **separate external crate**,
`matrix-sdk-crypto-wasm`, using `wasm-bindgen`, while native/mobile uses UniFFI
through `bindings/matrix-sdk-ffi` ([ARCHITECTURE.md](https://github.com/matrix-org/matrix-rust-sdk/blob/main/ARCHITECTURE.md),
[matrix-sdk-crypto-wasm](https://github.com/matrix-org/matrix-sdk-crypto-wasm)).

**Teaches:** put the state machine and the storage port in the core; ship an
in-memory store for tests; write one adapter per environment; the wasm binding
is an outer-layer consumer of the unchanged core. Their ARCHITECTURE.md is
itself modelled on Matklad's "ARCHITECTURE.md" essay
([matklad](https://matklad.github.io/2021/02/06/ARCHITECTURE.md.html)).

### 4.3 Alloy (`alloy-rs/core`) — ABI/RLP primitives shared everywhere

The Ethereum ABI/RLP layer that `foundry`, `revm` and `reth` all build on. It
is a workspace of focused crates — `alloy-primitives` (integers/bytes/addresses),
`alloy-sol-types` (compile-time ABI/EIP-712), `alloy-dyn-abi`, `alloy-json-abi`,
`alloy-sol-type-parser`, `syn-solidity` — under one `alloy-core` meta-crate
([README](https://github.com/alloy-rs/core)). Two explicit guarantees:

- "All crates in this workspace should support `no_std` environments, with the
  `alloc` crate." ([README — Note on no_std](https://github.com/alloy-rs/core#note-on-no_std))
- "We provide full support for all the `wasm*-*` targets." with the documented
  `getrandom` `wasm_js` fix ([README — WASM support](https://github.com/alloy-rs/core#wasm-support))

**Teaches:** ABI and RLP belong in `no_std` primitive crates with a `std`
feature; downstream (native CLI *and* browser) depend on the same crate. This is
the direct answer to "avoid duplicate ABI code." The `alloy-primitives` feature
list (`default = ["std", "map", "map-foldhash"]`, `std = [...]`) is a clean
template for the core's manifest
([primitives Cargo.toml](https://docs.rs/crate/alloy-primitives/latest/source/Cargo.toml.orig)).

### 4.4 CosmWasm — one contract source, native tests and wasm runtime

`cosmwasm-std` is the std library for wasm smart contracts, but "both unit tests
and integration tests are compiled to native code, so everything in here does
not need to compile to Wasm"; the crate gates the two paths with
`#[cfg(all(feature = "exports", target_arch = "wasm32"))]` and
`#[cfg(not(target_arch = "wasm32"))]` ([cosmwasm-std lib.rs](https://docs.rs/cosmwasm-std/latest/src/cosmwasm_std/lib.rs.html)).
The runtime side (`cosmwasm-vm`) is "an abstraction layer around the wasmer VM
… intended both for efficient writing of unit tests, as well as a public API to
run contracts" ([cosmwasm-vm README](https://github.com/CosmWasm/cosmwasm/blob/main/packages/vm/README.md)).

**Teaches:** a `library`/`exports` feature plus `target_arch` gating lets one
source tree be a native test library and a wasm artifact. Crypto helpers
(secp256k1/ed25519 verify) live in the std crate and are shared, not duplicated.

### 4.5 rust-bitcoin — no_std primitives with explicit wasm CI

Workspace members include `hashes`, `internals`, `io`, `primitives`, `units`,
`addresses`, and the `bitcoin` facade ([Cargo.toml](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/Cargo.toml)).
`bitcoin_hashes` is categorised "No standard library" and its features are
`default -> std`, `alloc -> hex?/alloc`, `std -> alloc, hex?/std`
([bitcoin_hashes on crates.io](https://crates.io/crates/bitcoin_hashes)) — the
textbook `std`/`alloc` feature graph. There is a dedicated WASM CI job that
targets the hashes crate only, run via `hashes/contrib/wasm.sh`
([rust-bitcoin commit "Remove everything from workspace except units"](https://github.com/rust-bitcoin/rust-bitcoin/commit/bdc6d3991bae92a0d7abdf1b7f18ac03962207c4),
[PR "hashes: Default to no_std"](https://github.com/rust-bitcoin/rust-bitcoin/pull/2543)).

**Teaches:** keep hash/crypto primitives in a dependency-light `no_std` crate
with `alloc`/`std` features; add a CI job that compiles that crate to wasm so
the native/wasm split cannot silently rot.

### 4.6 revm — pure, stateless precompile/execution crates

revm is split so that the pure parts are reusable: `revm-primitives`,
`revm-interpreter` (executes bytecode; `Host` is a trait), and `revm-precompile`
("Implementations of EVM precompiled contracts", where precompiles are
stateless `fn(&[u8], u64, u64)` functions), with the database/environment layers
kept behind interfaces ([revm-interpreter README](https://docs.rs/crate/revm-interpreter/latest/source/README.md),
[revm::precompile docs](https://docs.rs/revm/latest/revm/precompile/index.html),
[revm::interpreter docs](https://docs.rs/revm/latest/revm/interpreter/index.html)).
Its README states it is "used by almost all tooling and block builders … and
serving as a standard for zkVMs" ([README](https://docs.rs/crate/revm-interpreter/latest/source/README.md)),
and the architecture page is the intended orientation document
([revm architecture](https://bluealloy.github.io/revm/architecture.html)).

**Teaches:** crypto precompiles as pure functions with byte-slice in/out are
trivially portable (native, wasm, zkVM); host/environment access goes through a
trait so the same execution core runs in different VMs.

### 4.7 Cross-cutting lesson

In every case the shared, security-sensitive code (crypto, hashing, ABI/RLP,
state machine) lives **below** the platform boundary in `no_std`/sans-I/O
crates, and the platform layer (CLI I/O, `wasm-bindgen`, UniFFI) is thin and
logic-free. None of the projects maintain two copies of a crypto or ABI
algorithm; they maintain one core plus N adapters.

---

## 5. Synthesis for `bitbid` (the requested shape)

A concrete, convention-following sketch:

```
Cargo.toml                 # virtual manifest: [workspace] members = ["crates/*"]
crates/
  bitbid-core/             # no_std + alloc; default = ["std"]
    src/{crypto,abi,rlp,parse,...}.rs
    # ports owned here: BlobStore, Clock, Rng, ChainClient, SecretTransport
  bitbid-adapters/         # native only; depends on bitbid-core
    src/{fs.rs, reqwest_blocking.rs, process.rs, terminal.rs}
    [dependencies] reqwest = { ..., features = ["blocking"] }
  bitbid-cli/              # binary; composition root
    src/main.rs            # constructs adapters, injects into core use cases
  (web app)                # Leptos SSR crate; depends on bitbid-core only
```

Rules to adopt:

- `bitbid-core` sets `default = ["std"]`, `#![no_std]` + `extern crate alloc`,
  and gates every `std`-only path with `#[cfg(feature = "std")]`; crypto/ABI
  must compile with `--no-default-features` for wasm.
  ([features](https://doc.rust-lang.org/cargo/reference/features.html),
  [API Guidelines C-FEATURE](https://rust-lang.github.io/api-guidelines/naming.html#feature-names-are-free-of-placeholder-words-c-feature))
- `bitbid-adapters` is **never** depended on by `bitbid-core`; `reqwest`
  blocking / `std::fs` / `std::process` are declared there, not in core, and
  ideally under `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` if
  anything target-gated leaks upward
  ([platform-specific deps](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#platform-specific-dependencies)).
- The core defines ports as focused traits; the CLI and the Leptos server each
  are composition roots providing their own adapters (CLI: real fs/HTTP;
  web server: server-side adapters; browser: none, because server functions call
  the core on the server). This mirrors Matrix's sans-I/O split and Bitwarden's
  zero-logic bindings.
- Enable a `wasm` feature on `bitbid-core` that turns on
  `getrandom/wasm_js` + `wasm-bindgen` only if a browser-side crypto path is
  actually required; otherwise keep the RNG out of wasm entirely (deterministic
  HKDF/verify paths need no RNG).
  ([getrandom WASM support](https://docs.rs/getrandom/#webassembly-support))

---

## 6. Gotchas / anti-patterns to avoid

- **Duplicated crypto/ABI:** the failure mode all six projects avoid. If the
  wasm side re-implements RLP or ECDH, the split has failed.
- **`cfg(feature = ...)` in `[target]` sections** silently does nothing — use
  `[features]` to gate optional deps instead
  ([Cargo Book](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#platform-specific-dependencies)).
- **Non-additive features** (e.g. a `no_std` feature) break feature
  unification; always prefer an additive `std` feature
  ([features](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification)).
- **Leaking `std::io::Error`/wire types into ports** re-couples the core to an
  environment ([The Deterministic Hexagon](https://imgabriel.dev/architecture/)).
- **God-traits** (one 47-method repository) make adapters bloated and tests
  impossible to fake ([Ports as Traits](https://rustz2h.com/chapter_16_advanced_architecture_and_idiomatic_rust/series_02_domain_driven_design_and_architecture/ports_as_traits)).
- **Putting logic in the wasm/UniFFI binding crate** — Bitwarden's docs forbid it
  in capitals for exactly this reason
  ([bitwarden-wasm-internal](https://sdk-api-docs.bitwarden.com/bitwarden_wasm_internal/index.html)).
- **No wasm CI job** — rust-bitcoin keeps a dedicated wasm build for the hashes
  crate precisely so the boundary does not rot
  ([commit](https://github.com/rust-bitcoin/rust-bitcoin/commit/bdc6d3991bae92a0d7abdf1b7f18ac03962207c4)).

---

## Sources

Primary unless marked *(blog)*.

1. [The Cargo Book — Workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html)
2. [The Cargo Book — Features](https://doc.rust-lang.org/cargo/reference/features.html)
3. [The Cargo Book — Specifying Dependencies (platform-specific, renaming, multiple locations)](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
4. [The Rust Reference — Conditional Compilation (`cfg`, `cfg_attr`, `target_arch`, `target_family`)](https://doc.rust-lang.org/reference/conditional-compilation.html)
5. [Rust API Guidelines — Naming (C-CASE, C-FEATURE)](https://rust-lang.github.io/api-guidelines/naming.html)
6. [`cfg_aliases` crate docs](https://docs.rs/cfg_aliases/)
7. [`getrandom` — WebAssembly support](https://docs.rs/getrandom/#webassembly-support); [0.3.4 manifest](https://docs.rs/crate/getrandom/0.3.4/source/Cargo.toml.orig); [changelog](https://github.com/rust-random/getrandom/blob/master/CHANGELOG.md)
8. [Rust WASM Book — Which crates work with WebAssembly?](https://rustwasm.github.io/book/reference/which-crates-work-with-wasm.html)
9. [Leptos Book — Life of a Page Load](https://book.leptos.dev/ssr/22_life_cycle.html); [Hydration Bugs](https://book.leptos.dev/ssr/24_hydration_bugs.html); [Server Functions](https://book.leptos.dev/server/25_server_functions.html); [Getting Started](https://book.leptos.dev/getting_started/)
10. [Bitwarden — SDK Crate structure](https://contributing.bitwarden.com/architecture/sdk/crate-structure/); [bitwarden/sdk-internal](https://github.com/bitwarden/sdk-internal); [bitwarden-wasm-internal docs](https://sdk-api-docs.bitwarden.com/bitwarden_wasm_internal/index.html); [bitwarden-core on crates.io](https://crates.io/crates/bitwarden-core); [bitwarden-crypto on crates.io](https://crates.io/crates/bitwarden-crypto)
11. [Matrix Rust SDK — ARCHITECTURE.md](https://github.com/matrix-org/matrix-rust-sdk/blob/main/ARCHITECTURE.md); [matrix-sdk-crypto-wasm](https://github.com/matrix-org/matrix-sdk-crypto-wasm)
12. [alloy-rs/core README](https://github.com/alloy-rs/core); [alloy-core docs.rs](https://docs.rs/alloy-core/latest/alloy_core/); [alloy-primitives Cargo.toml](https://docs.rs/crate/alloy-primitives/latest/source/Cargo.toml.orig)
13. [cosmwasm-std lib.rs source](https://docs.rs/cosmwasm-std/latest/src/cosmwasm_std/lib.rs.html); [cosmwasm-vm README](https://github.com/CosmWasm/cosmwasm/blob/main/packages/vm/README.md); [CosmWasm Entry points book](https://book.cosmwasm.com/basics/entry-points.html)
14. [rust-bitcoin Cargo.toml](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/Cargo.toml); [bitcoin_hashes on crates.io](https://crates.io/crates/bitcoin_hashes); [PR #2543](https://github.com/rust-bitcoin/rust-bitcoin/pull/2543); [WASM CI commit](https://github.com/rust-bitcoin/rust-bitcoin/commit/bdc6d3991bae92a0d7abdf1b7f18ac03962207c4)
15. [revm-interpreter README](https://docs.rs/crate/revm-interpreter/latest/source/README.md); [revm::precompile docs](https://docs.rs/revm/latest/revm/precompile/index.html); [revm::interpreter docs](https://docs.rs/revm/latest/revm/interpreter/index.html); [revm architecture](https://bluealloy.github.io/revm/architecture.html)
16. *(blog)* [Hexagonal Architecture in Rust — Cogs and Levers](https://tuttlem.github.io/2025/08/31/hexagonal-architecture-in-rust.html)
17. *(blog)* [The Deterministic Hexagon](https://imgabriel.dev/architecture/)
18. *(blog)* [Ports as Traits — Rust From Zero To Hero](https://rustz2h.com/chapter_16_advanced_architecture_and_idiomatic_rust/series_02_domain_driven_design_and_architecture/ports_as_traits)
19. [llmgraph-ai/hexagonal-rust-template](https://github.com/llmgraph-ai/hexagonal-rust-template)
20. *(blog)* [matklad — ARCHITECTURE.md](https://matklad.github.io/2021/02/06/ARCHITECTURE.md.html)

Companion note in this directory: [`leptos-ssr-contract.md`](./leptos-ssr-contract.md)
(what the shared core must expose to Leptos SSR + server functions).
