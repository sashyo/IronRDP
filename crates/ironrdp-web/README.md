# WASM bindings for web

This crate is part of the [IronRDP] project.

[IronRDP]: https://github.com/Devolutions/IronRDP

## KeyleSSH fork changes

This is the [KeyleSSH fork](https://github.com/sashyo/IronRDP) (`feat/ironrdp-tls-wasm` branch). The following changes were made to support **e2e TLS** — end-to-end encrypted RDP sessions where the gateway is a blind proxy.

### e2e TLS mode

When `e2e_tls` is enabled, IronRDP WASM performs the full RDP connection sequence end-to-end:

1. Sends a JSON routing header (`{destination, authToken}`) to the proxy's `/ws/tcp-forward` endpoint
2. Proxy verifies JWT, opens a plain TCP connection to the RDP backend, responds with `{ok, host, port}`
3. IronRDP does X.224 negotiation through the tunnel (plaintext, visible to proxy)
4. IronRDP does TLS upgrade via `ironrdp-tls-wasm` (rustls in WASM) — **proxy is now blind**
5. CredSSP/NLA, MCS, and RDP session all happen inside the TLS tunnel

### Usage from JavaScript

```js
var builder = new wasm.SessionBuilder();
builder = builder.extension(new wasm.Extension("e2e_tls", true));
builder = builder.proxyAddress("wss://gateway/ws/tcp-forward");
// ... username, password, destination, etc.
var session = await builder.connect();
```

### Build

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
wasm-pack build crates/ironrdp-web --target web --out-dir pkg
```

Output goes to `crates/ironrdp-web/pkg/`:
- `ironrdp_web.js` — JS bindings
- `ironrdp_web_bg.wasm` — WASM binary

Copy both to the punchd bridge `public/wasm/` directory and rebuild, or deploy directly to the keylessh server's `dist/public/gateway/wasm/` directory.
