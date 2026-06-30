//! A from-scratch QUIC server.
//!
//! `quic-rs` listens on UDP, receives a QUIC Initial packet, derives the Initial
//! keys from the Destination Connection ID, removes header protection, and
//! AEAD-decrypts the payload to expose the TLS ClientHello — all implemented by
//! hand against RFC 9000 (transport) and RFC 9001 (TLS).

pub mod crypto;
pub mod packet;
pub mod server;
pub mod varint;

pub use server::run;
