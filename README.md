# quic-rs

A from-scratch [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) server written in Rust,
built to learn the protocol from the ground up using raw syscalls (via `nix`) and manual
packet parsing — no `quinn`/`quiche`.

## What it does

`quic-rs` listens on UDP `0.0.0.0:3000`, receives a QUIC **Initial** packet, and:

1. Parses the long header — version, connection IDs, token, length (RFC 9000 §17.2.2).
2. Derives the client/server Initial secrets — key, IV, and header-protection key — from
   the Destination Connection ID (RFC 9001 §5.2).
3. Removes header protection and recovers the packet number (RFC 9001 §5.4).
4. AEAD-decrypts the payload with AES-128-GCM, exposing the QUIC frames — the CRYPTO frame
   that carries the TLS 1.3 ClientHello (RFC 9001 §5.3).

It does **not** yet send a response or complete the handshake.

## Layout

| File | Responsibility |
| --- | --- |
| `src/main.rs` | Binary entry point. |
| `src/lib.rs` | Crate root and module declarations. |
| `src/server.rs` | UDP socket setup and the receive loop. |
| `src/packet.rs` | Initial long-header parsing and decryption orchestration. |
| `src/crypto.rs` | HKDF key schedule, header protection, and AEAD decryption. |
| `src/varint.rs` | QUIC variable-length integer decoding. |
| `tests/rfc9001_vectors.rs` | RFC 9001 Appendix A known-answer tests. |

## Build, test & run

```sh
cargo build
cargo test     # verifies key derivation + decryption against RFC 9001 Appendix A
cargo run      # listens on 0.0.0.0:3000 for one Initial packet
```

## Credit

This project began as a restructured and extended version of
[`datasalaryman/quic-server-from-scratch`](https://github.com/datasalaryman/quic-server-from-scratch).
The original key-derivation and packet-parsing bugs were fixed, the code was reorganized
into focused modules, and the full Initial-packet decryption path (header protection +
AEAD) was added.
