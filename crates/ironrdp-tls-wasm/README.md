# ironrdp-tls-wasm

WASM-compatible TLS upgrade for IronRDP using `rustls` over abstract byte channels.

## What this fork adds

This crate is part of the [KeyleSSH fork](https://github.com/sashyo/IronRDP) of IronRDP. It enables **end-to-end TLS** between the IronRDP WASM client (running in the browser) and the RDP server, with the punchd gateway acting as a blind TCP relay.

### Architecture: e2e TLS (trustless proxy)

```
IronRDP WASM ══ WebRTC/DTLS ══ punchd ──── TCP ──── RDP Server
     │                            │                      │
     ╠══════ TLS (rustls) ════════╪══════════════════════╣
     ║                            │                      ║
     ║── X.224 + TLS + CredSSP ──┼─────────────────────►║
     ║── RDP session ◄────────────┼────────────────────►║
     ║                            │                      ║
     ╚════════════════════════════╪══════════════════════╝
                               BLIND
```

The gateway authenticates the user (JWT) and resolves the backend, but **cannot** read, modify, or record the RDP session.

### Why a separate crate

The upstream `ironrdp-tls` crate depends on `tokio-rustls` (native TLS backends), which cannot compile to `wasm32-unknown-unknown`. This crate uses `rustls` directly with `futures-io` async traits — no tokio dependency, WASM-compatible.

## API

Same interface as `ironrdp-tls`:

```rust
let (tls_stream, server_cert) = ironrdp_tls_wasm::upgrade(stream, "server-name").await?;
let pubkey = ironrdp_tls_wasm::extract_tls_server_public_key(&server_cert);
```

Where `stream` is any `Unpin + AsyncRead + AsyncWrite` — typically a WebRTC DataChannel wrapped as a WebSocket.

## Build

```bash
# Native check
cargo check -p ironrdp-tls-wasm

# As part of the WASM build
wasm-pack build crates/ironrdp-web --target web --out-dir pkg
```

## Changes from upstream IronRDP

### New crates
- **`ironrdp-tls-wasm`** — This crate. `rustls` over `futures-io` for WASM.

### Modified crates
- **`ironrdp-web`** — Added `e2e_tls` connection mode:
  - New `connect_direct()` function: sends JSON routing header to proxy, does X.224 negotiation, TLS upgrade via `ironrdp-tls-wasm`, then CredSSP/NLA and RDP session — all end-to-end through the tunnel.
  - `SessionBuilder` accepts `e2e_tls: bool` extension to switch between RDCleanPath (gateway-terminated TLS) and e2e TLS (blind proxy) modes.
  - `Session` uses boxed trait objects (`BoxedReader`/`BoxedWriter`) so both modes share the same post-connect session loop.
  - Existing RDCleanPath path is unchanged and remains the default.

### Dependencies added
- `rustls 0.23` (with `ring` backend + `wasm32_unknown_unknown_js`)
- `rustls-pki-types` (with `web` feature for WASM time)
- `futures-io`, `futures-util`
