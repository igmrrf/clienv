# Leptos SSR + Server Functions: Contract for a Shared Rust Core

Research ticket: what a Leptos SSR + server-functions app requires of a shared
Rust core, in the context of splitting the synchronous/blocking `bsec` CLI
(`reqwest::blocking`, `std::fs`, `argon2`) into a core the web app can call.

Versions examined (primary sources, retrieved 2026-09-30):

- `leptos` **0.8.21** (latest stable on docs.rs); `0.9.0-beta` line exists but is
  not stable. The book at `book.leptos.dev` tracks 0.7/0.8-style APIs.
- `server_fn` **0.8.13** (the RPC crate underneath `#[server]`).
- `leptos_server` **0.8.8** (`Resource`, hydration).
- `server_fn` / `leptos_axum` / `leptos_actix` integrations.

---

## TL;DR answers to (a)–(d)

**(a) Can Leptos server functions call synchronous/blocking Rust code?**
The *signature* must be `async` and must return `Result<T, ServerFnError>`, but
the *body* may run synchronous work. The official docs say this explicitly:
"Server functions must be `async`. Even if the work being done inside the
function body can run synchronously on the server, from the client's perspective
it involves an asynchronous function call."
([server_fn crate docs](https://docs.rs/server_fn/latest/server_fn/),
[book §25](https://book.leptos.dev/server/25_server_functions.html)). So an
`async fn` wrapper around the existing synchronous core can work. However, server
functions are executed on the server's async executor (Axum/Actix = Tokio). A
truly blocking call (`reqwest::blocking`, `std::fs`, expensive `argon2`) will
block a Tokio worker; it should be moved onto a blocking thread with
`tokio::task::spawn_blocking`, which "runs the provided closure on a thread where
blocking is acceptable" and explicitly exists to bridge sync APIs
([tokio `spawn_blocking` docs](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html)).

**(b) How do secrets and state pass between browser and server?**
- Server function **arguments and return values must be serializable**
  (`serde`); clients serialize args into an HTTP POST (default `serde_qs`
  URL-encoding) and the server serializes the return to JSON
  ([book §25](https://book.leptos.dev/server/25_server_functions.html),
  [`#[server]` macro docs](https://docs.rs/leptos/latest/leptos/attr.server.html)).
- The **body is server-only and is never compiled into the wasm bundle**; only
  its arguments cross the wire. Secrets belong in the body or in server-side
  state, never in a resource's serialized value.
- **Server-side state** is shared via reactive **context**: provide it on the
  router with `.leptos_routes_with_context(..., move || provide_context(pool.clone()), ...)`,
  then read it inside a server function with `use_context::<T>()` /
  `expect_context::<T>()`; alternatively use Axum/Actix **extractors** via
  `leptos_axum::extract` / `extract_with_state`
  ([book §26 Extractors](https://book.leptos.dev/server/26_extractors.html)).
- **Resources** (`Resource`, not `LocalResource`, for SSR) serialize their
  resolved value from server to client and deserialize it during hydration, so
  data loading starts on the server — which is exactly why **secret material
  must not be placed in a `Resource`** ([book §10 Resources](https://book.leptos.dev/async/10_resources.html),
  [`Resource` docs](https://docs.rs/leptos/latest/leptos/server/struct.Resource.html)).
- Important Rust constraint: server functions **cannot be generic**, and their
  `Output` must be `Send` ([`ServerFn` trait](https://docs.rs/server_fn/latest/server_fn/trait.ServerFn.html),
  [`#[server]` macro](https://docs.rs/leptos/latest/leptos/attr.server.html)).

**(c) Can the browser wasm bundle include a pure crypto subset (k256 + aes-gcm + hkdf)?**
Yes, as a compile subset, subject to three rules:
1. These RustCrypto crates are pure Rust and compile to `wasm32-unknown-unknown`.
   `k256` is "secp256k1 ... written in pure Rust" with `no_std`/`alloc` support
   ([k256 docs](https://docs.rs/k256/latest/k256/)); `aes-gcm`, `hkdf`, `sha2`
   are likewise pure Rust.
2. Any code path that draws randomness (`k256` key gen, `aes-gcm` nonce/key
   generation, `argon2` salt) needs `getrandom` on wasm. `wasm32-unknown-unknown`
   is **not supported by default**; you must enable `getrandom`'s `wasm_js`
   feature/backend (`Crypto.getRandomValues` via `wasm-bindgen`)
   ([getrandom docs](https://docs.rs/getrandom/latest/getrandom/),
   [Leptos README "Random numbers on wasm"](https://docs.rs/leptos/latest/leptos/)).
   Deterministic paths (HKDF from an existing seed, ECDSA RFC6979 signing with a
   fixed key, AES-GCM with a fixed key/nonce) need no RNG and thus no `wasm_js`.
3. Native-only dependencies must be excluded from the wasm build:
   `reqwest::blocking` is **not available on wasm** ("Blocking is fundamentally
   not allowed on the wasm target because javascript is single threaded",
   [reqwest #891](https://github.com/seanmonstar/reqwest/issues/891); wasm
   disables `blocking`/`tls`/`cookie`,
   [reqwest wasm docs](https://docs.rs/reqwest/latest/wasm32-unknown-unknown/reqwest/));
   `std::fs` "always return errors" and `std::thread::spawn` panics on
   `wasm32-unknown-unknown`
   ([rustc platform support](https://doc.rust-lang.org/nightly/rustc/platform-support/wasm32-unknown-unknown.html)).
   Those must be behind `cfg`/Cargo features that are off for the hydrate build.

**(d) Leptos version/feature constraints.**
Use Leptos **0.8.x**. Features are `--no-default-features` plus either `ssr`
(server) or `hydrate` (browser); `csr` is client-only. `ssr` transitively enables
`hydration`, `leptos_server/ssr`, `server_fn/ssr`, `tachys/ssr`; `csr`/`hydrate`
enable `getrandom?/wasm_js` ([leptos feature flags](https://docs.rs/crate/leptos/latest/features)).
`cargo-leptos` builds the lib with `--features=hydrate` and the bin with
`--features=ssr` ([cargo-leptos README](https://github.com/leptos-rs/cargo-leptos)).
`Resource` is re-exported from `leptos::server` / `leptos_server`.

---

## Detailed findings

### 1. The shape `#[server]` imposes

`#[server]` is "Declares that a function is a server function. This means that
its body will only run on the server, i.e., when the `ssr` feature on this crate
is enabled. If you call a server function from the client (i.e., when the `csr`
or `hydrate` features are enabled), it will instead make a network request to the
server."
([`#[server]` macro docs](https://docs.rs/leptos/latest/leptos/attr.server.html))

Hard requirements (same source, and
[server_fn crate docs](https://docs.rs/server_fn/latest/server_fn/)):

- Must be a top-level `fn` annotated `#[server]`, declared `async`.
- Must return `Result<T, ServerFnError>` (or `Result<T, E>` where `E:
  FromServerFnError`).
- Arguments and return types must be serializable/deserializable.
- "Server functions can't be generic." Use a concrete `#[server]` that calls a
  generic inner function.
- Not closures: no access to client reactive state; both sides only share what
  is passed as arguments.
- Must have unique paths; endpoints are mounted under a prefix (default `/api`).
- On the server, the `#[server]` body "is never compiled into the client"
  ([async quick reference](https://book.leptos.dev/server/28_async_quick_reference.html)).
- Server functions are **public API endpoints** and must sanitize returns
  ([book §25](https://book.leptos.dev/server/25_server_functions.html)).

Trait-level bounds from the [`ServerFn` trait](https://docs.rs/server_fn/latest/server_fn/trait.ServerFn.html):

```rust
pub trait ServerFn: Send + Sized {
    type Output: Send;
    type Error: FromServerFnError + Send + Sync;
    // ...
    fn run_body(self) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send;
}
```

So the **function's argument struct and its `Output` type must be `Send`**, and
the error type must be `FromServerFnError + Send + Sync`. The default encodings
are `input = PostUrl` (serde_qs) and `output = Json` (serde_json).

### 2. Synchronous/blocking core behind an async server fn

The book's server-function example makes the async-shell/sync-body split clear:
the wrapper is `async` because "calling them from the browser *must* be
asynchronous," even when the server body is synchronous
([book §25](https://book.leptos.dev/server/25_server_functions.html);
[`#[server]` docs](https://docs.rs/leptos/latest/leptos/attr.server.html)).

Where it actually runs: server functions on Axum/Actix are handled by the
framework's async runtime. `server_fn`'s Axum feature pulls in `tokio`
([server_fn feature flags](https://docs.rs/crate/server_fn/latest/features)), and
the `Server` trait only requires `fn spawn(future: impl Future<Output = ()> +
Send + 'static)` ([server_fn `Server` trait](https://docs.rs/leptos/0.8.20/leptos/server_fn/server/trait.Server.html)).
On Axum that means `tokio::spawn` on the Tokio runtime.

Consequences for a blocking core:

- Calling blocking code directly inside a server fn blocks a runtime worker.
  Tokio's own guidance: "issuing a blocking call or performing a lot of compute
  in a future without yielding is problematic, as it may prevent the executor
  from driving other futures forward." Use
  `tokio::task::spawn_blocking` for short-lived blocking work; it uses a
  dedicated blocking pool and "if you are using the single threaded runtime,
  this function will still spawn additional threads for blocking operations"
  ([tokio `spawn_blocking`](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html)).
- `reqwest::blocking` calls, `std::fs` IO, and Argon2 hashing (CPU/memory-hard)
  are all reasonable `spawn_blocking` payloads. The closure needs `F: FnOnce() ->
  R + Send + 'static`, `R: Send + 'static`, so captured values (paths, keys,
  request bodies) must be owned/`Send`.
- Long-lived blocking resources (e.g. a persistent blocking HTTP client) can be
  stored in server context and cloned into each `spawn_blocking` closure, since
  `reqwest::blocking::Client` is `Send + Sync` and cheaply cloneable.
- An Argon2 verify/hash is CPU-heavy; consider bounding concurrency via the
  blocking pool or a dedicated pool, as Tokio warns the default blocking thread
  limit is very large and "when you run CPU-bound code using `spawn_blocking`,
  you should keep this large upper limit in mind."

### 3. Moving secrets and state across the boundary

**What crosses the wire.** Only serialized arguments and the serialized `Result`.
The docs are explicit: "The *body* of a server function is never made public; ...
its return value is just a JSON or similar blob. Do not return information ...
unless it is public, or you've implemented proper security procedures"
([book §25](https://book.leptos.dev/server/25_server_functions.html)). Practical
rules for a secrets CLI:

- Never return private keys, unsealed env values, or decrypted secrets unless the
  endpoint is authenticated and intentionally exposes them.
- Return identifiers/handles, not secret material, when possible.
- Watch pointer-sized types: `usize`/`isize` can round-trip badly between 32-bit
  wasm and a 64-bit server; use `i32`/`i64` ([book §25 quirks](https://book.leptos.dev/server/25_server_functions.html)).
- The default URL encoding (`serde_qs`) has known quirks with `Option` and enum
  tuple variants; switch `input`/`output` encodings (CBOR, postcard, etc.) if hit
  ([`#[server]` encodings](https://docs.rs/leptos/latest/leptos/attr.server.html)).

**Resources and hydration.** `Resource` "serialize[s] its value from the server
to the client ... on the client, when first loading the page, the initial value
will be deserialized rather than the async task running again"
([book §10](https://book.leptos.dev/async/10_resources.html)). The serialized
value is embedded in the SSR response (in `<script>` tags per the
[async quick reference](https://book.leptos.dev/server/28_async_quick_reference.html)).
Therefore: **anything inside a `Resource` is effectively public to the browser.**
`Resource<T, Ser>` bounds `T: Send + Sync + 'static`
([`Resource` docs](https://docs.rs/leptos/latest/leptos/server/struct.Resource.html)),
and for SSR the recommendation is `Resource`, not `LocalResource`.

**Server-side shared state.** Two supported mechanisms:

1. Leptos context, provided at the router:
   ```rust
   let app = Router::new().leptos_routes_with_context(
       &leptos_options,
       routes,
       move || provide_context(connection_pool.clone()),
       /* shell */ ...,
   );
   ```
   then inside a server fn: `let state = use_context::<T>();`
   ([book §26](https://book.leptos.dev/server/26_extractors.html)).
2. Axum `State` via `#[derive(FromRef)]` + `leptos_axum::extract_with_state`,
   used with `expect_context::<MyData>()`
   ([book §26](https://book.leptos.dev/server/26_extractors.html)).

A critical subtlety: during SSR, server functions invoked while rendering have
the app's context, but their standalone HTTP endpoint handlers run **without**
the app's context unless the values were supplied to
`.leptos_routes_with_context()` ([async quick reference](https://book.leptos.dev/server/28_async_quick_reference.html)).
So shared server state must be registered through that router call, or via
`FromRef` state, to be visible to endpoint invocations.

**Client-side state.** Signals live only in the browser; server functions have
"no access to the reactive state of your app or anything else that is not passed
in as an argument" ([book §25](https://book.leptos.dev/server/25_server_functions.html)).
If the browser holds an unlocked key material and the server must act on it, it
has to be passed explicitly as a server-fn argument (and is then exposed over
HTTP — so this is a design decision, not free).

### 4. Browser wasm bundle: pure crypto subset

**Pure Rust crypto that compiles to wasm.**
- `k256` = "secp256k1 elliptic curve library written in pure Rust"
  ([k256 docs](https://docs.rs/k256/latest/k256/)); features include `arithmetic`,
  `ecdsa`, `ecdh`, `schnorr`, `sha256`; `std`/`alloc`/`no_std`.
- `aes-gcm`, `hkdf`, `sha2`, `sha3`, `zeroize`, `base64` are pure Rust
  (RustCrypto / crates.io).
- `argon2` is a "Pure Rust implementation of the Argon2 password hashing
  function" with `no_std` support; the high-level API's random salt requires the
  `getrandom` feature ([argon2 docs](https://docs.rs/argon2/latest/argon2/)).

**The one wasm trap: randomness.**
`rand`/`getrandom` on `wasm32-unknown-unknown` need a JS-backed entropy source.
"the `wasm32-unknown-unknown` ... targets ... are not automatically supported ...
To enable getrandom's functionality ... using `Crypto.getRandomValues` via
`wasm-bindgen`, enable the `wasm_js` crate feature." Without it the build fails
with a `compile_error!` ("The wasm32-unknown-unknown targets are not supported by
default; you may need to enable the `wasm_js` crate feature")
([getrandom docs](https://docs.rs/getrandom/latest/getrandom/),
[getrandom backends source](https://github.com/rust-random/getrandom/blob/master/src/backends.rs)).
Leptos itself enables `getrandom?/wasm_js` for `csr`/`hydrate`, but the Leptos
README warns this "does **not** automatically configure your app's own `rand` /
`getrandom` dependencies. If you use them directly, you need to turn on the JS
backend yourself" ([leptos docs / README](https://docs.rs/leptos/latest/leptos/)).
The recommended per-target setting:

```toml
[target.wasm32-unknown-unknown]
rustflags = ['--cfg', 'getrandom_backend="wasm_js"']
```

Note: the crate's `leptos` dependency graph currently resolves `getrandom ^0.4`,
while `getrandom` 0.3+ uses the `wasm_js` feature / `getrandom_backend` cfg. Do
not mix getrandom majors in the core and the app without checking the backend
mechanism of each.

**Native-only code that must not be in the wasm path.**
- `reqwest` (`blocking` feature) — unavailable in the browser; the client is
  fetch-based and `blocking`/`tls`/`cookie` are disabled on wasm
  ([reqwest wasm docs](https://docs.rs/reqwest/latest/wasm32-unknown-unknown/reqwest/),
  [reqwest #891](https://github.com/seanmonstar/reqwest/issues/891)).
- `std::fs` — "always return errors" on `wasm32-unknown-unknown`.
- `std::thread::spawn` — "will panic."
  ([rustc platform support](https://doc.rust-lang.org/nightly/rustc/platform-support/wasm32-unknown-unknown.html))
- Windows/Unix-specific deps (e.g. the CLI's `libc` target dep) must be gated.

So a shared core must split into at least: (i) a **portable crypto/domain subset**
pure-Rust, wasm-safe, and (ii) **native/infrastructure** code (fs, blocking HTTP,
OS) that only compiles under the server/`ssr` build. Feature-flag both directions
rather than relying only on `cfg(target_arch)`.

### 5. Leptos version and feature matrix

Current stable: `leptos 0.8.21`; `server_fn 0.8.13`; `leptos_server 0.8.8`.
A `0.9.0-beta` line is published but not stable.

Feature flags relevant to SSR vs hydrate
([leptos features](https://docs.rs/crate/leptos/latest/features)):

| Feature | Effect |
|---|---|
| `ssr` | Enables `hydration`, `leptos_macro/ssr`, `leptos_server/ssr`, `server_fn/ssr`, `tachys/ssr`. Server build. |
| `hydrate` | Enables `getrandom?/wasm_js`, `hydration`, `leptos_macro/hydrate`, `tachys/hydrate`. Browser build for hydrating SSR output. |
| `csr` | Client-only rendering (`leptos_macro/csr`), enables `getrandom?/wasm_js`. No server. |
| `hydration` | Shared SSR/hydrate plumbing (`hydration_context/browser`, `leptos_dom/hydration`, `leptos_server/hydration`). |
| `default-tls` / `rustls` | TLS for `server_fn`'s own client (e.g. non-browser calls). |
| `nightly` | Signal getter/setter call syntax. |
| `rkyv`/`bitcode`/`cbor`/`msgpack`/`postcard`/`serde-lite`/`multipart` | Alternative `server_fn`/`Resource` encodings. |

`server_fn` integration flags: on the server you need one of `axum` /
`axum-no-default` or `actix` / `actix-no-default`; the `ssr` feature pulls in
`inventory`. Browser client support comes from `gloo-net`/`web-sys` under the
appropriate cfg. ([server_fn features](https://docs.rs/crate/server_fn/latest/features))

Build wiring: `cargo-leptos` compiles the frontend library as
`wasm32-unknown-unknown` with `--no-default-features --features=hydrate` and the
server binary with `--no-default-features --features=ssr`
([cargo-leptos README](https://github.com/leptos-rs/cargo-leptos)). Feature
selection is usually done per-dependency via `[features]` and `[package.metadata.leptos]`.

`Resource` is re-exported at `leptos::server::Resource` /
`leptos::prelude::Resource`; `leptos_server` is the supporting crate
([leptos_server](https://docs.rs/leptos_server/latest/leptos_server/),
[`Resource`](https://docs.rs/leptos/latest/leptos/server/struct.Resource.html)).

---

## Concrete constraints a shared core must satisfy

1. **Async shell, sync body is allowed, but blocking must be offloaded.** Every
   public core entry point that the web layer calls should be wrappable in an
   `async fn` returning `Result<T, ServerFnError>`; blocking internals
   (`reqwest::blocking`, `std::fs`, Argon2) must be callable inside
   `tokio::task::spawn_blocking`, with `Send + 'static` closures and values.
2. **All boundary types are `serde` + `Send`.** Argument and return types must
   be `Serialize + DeserializeOwned + Send` (`Output: Send`; error:
   `FromServerFnError + Send + Sync`). Avoid `usize`/`isize`; prefer `i32`/`i64`.
3. **No generics across the boundary.** Server functions are concrete wrappers
   around generic core functions.
4. **No secrets in return values or `Resource`s.** Only serialized args/returns
   cross; `Resource` values are serialized into the SSR HTML/hydration payload.
   Server-side shared state (keys, pools, paths) goes through
   `provide_context` + `leptos_routes_with_context` (and/or Axum `FromRef`
   state) and is read with `use_context`/`expect_context`.
5. **Types shared with the UI must be `Serialize + Deserialize + Clone + Debug`**
   and `Send + Sync + 'static` if stored in a `Resource` / used in reactive
   state.
6. **Three build configurations must be expressible in Cargo features:**
   `ssr` (native, full core), `hydrate` (wasm, portable crypto subset + UI), and
   ideally `csr`. Native-only deps (`reqwest::blocking`, `std::fs`, `std::thread`,
   `libc`) must be behind server-only features, never pulled by the hydrate
   build.
7. **The portable crypto subset must be wasm-clean:** `k256` (arithmetic, ecdsa,
   ecdh), `aes-gcm`, `hkdf`, `sha2`/`sha3`, `zeroize`, `base64`, `argon2` are
   fine; any RNG use requires the `getrandom` `wasm_js` backend (or
   `--cfg getrandom_backend="wasm_js"`), and deterministic paths should avoid RNG
   entirely.
8. **Core API should return typed, serializable errors** (a `thiserror` enum
   implementing `FromServerFnError` or convertible to `ServerFnError`) rather
   than leaking internal error strings.
9. **Server function bodies must be idempotent/safe as public endpoints** (auth,
   rate limiting, no secret leakage), since every `#[server]` function is a
   reachable HTTP endpoint.
10. **Pick a stable Leptos line (0.8.x) and pin it.** Feature correctness depends
    on `ssr`/`hydrate` being mutually exclusive across the two builds; mixing
    them produces a server-fn body compiled into wasm or a networking stub on the
    server.

---

## Primary sources

- Leptos book — Server Functions: https://book.leptos.dev/server/25_server_functions.html
- Leptos book — Extractors (context `provide_context`/`use_context`, Axum `FromRef`/`extract_with_state`): https://book.leptos.dev/server/26_extractors.html
- Leptos book — Loading Data with Resources: https://book.leptos.dev/async/10_resources.html
- Leptos book — Async quick reference (Resource/Suspend/server-fn execution & context): https://book.leptos.dev/server/28_async_quick_reference.html
- Leptos book — Optimizing WASM Binary Size (serde/`Resource` encodings, `leptos_server`): https://book.leptos.dev/deployment/binary_size.html
- Leptos book — Part 2 SSR (Axum/Actix integrations): https://book.leptos.dev/ssr/index.html
- `#[server]` macro docs: https://docs.rs/leptos/latest/leptos/attr.server.html
- `server_fn` crate docs: https://docs.rs/server_fn/latest/server_fn/
- `server_fn::ServerFn` trait: https://docs.rs/server_fn/latest/server_fn/trait.ServerFn.html
- `server_fn` feature flags: https://docs.rs/crate/server_fn/latest/features
- `leptos_server` crate: https://docs.rs/leptos_server/latest/leptos_server/
- `leptos::server::Resource`: https://docs.rs/leptos/latest/leptos/server/struct.Resource.html
- `leptos` feature flags: https://docs.rs/crate/leptos/latest/features
- `cargo-leptos` README (build features): https://github.com/leptos-rs/cargo-leptos
- Tokio `spawn_blocking`: https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
- `getrandom` docs (wasm `wasm_js` backend): https://docs.rs/getrandom/latest/getrandom/
- `getrandom` backends source: https://github.com/rust-random/getrandom/blob/master/src/backends.rs
- `k256` docs/features: https://docs.rs/k256/latest/k256/
- `argon2` docs (getrandom salt): https://docs.rs/argon2/latest/argon2/
- `reqwest` wasm docs (no blocking/tls/cookie): https://docs.rs/reqwest/latest/wasm32-unknown-unknown/reqwest/
- reqwest blocking-on-wasm issue: https://github.com/seanmonstar/reqwest/issues/891
- `wasm32-unknown-unknown` platform support (fs errors, thread panic): https://doc.rust-lang.org/nightly/rustc/platform-support/wasm32-unknown-unknown.html
