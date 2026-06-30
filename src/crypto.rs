//! QUIC Initial-packet cryptography (RFC 9001 §5).
//!
//! Implements the Initial key schedule (HKDF), header protection, and AEAD
//! payload decryption for QUIC version 1, which uses `AEAD_AES_128_GCM` and
//! AES-128 based header protection.

use hkdf::Hkdf;
use ring::aead::quic::{AES_128, HeaderProtectionKey};
use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::error::Unspecified;
use sha2::Sha256;

/// The QUIC v1 Initial salt (RFC 9001 §5.2): a fixed, public constant.
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// One direction's Initial secrets: the AEAD key, the IV, and the
/// header-protection key.
#[derive(Debug, Clone)]
pub struct DirectionalKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

/// The client and server Initial keys derived from a connection's DCID.
#[derive(Debug, Clone)]
pub struct ConnectionKeys {
    pub client: DirectionalKeys,
    pub server: DirectionalKeys,
}

/// Builds the TLS 1.3 `HkdfLabel` structure and runs HKDF-Expand (RFC 8446 §7.1):
/// `uint16 length` ‖ `opaque label<"tls13 " + label>` ‖ `opaque context = ""`.
fn hkdf_expand_label(prk: &Hkdf<Sha256>, label: &[u8], out_len: usize) -> Vec<u8> {
    let full_label = [b"tls13 ", label].concat();

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(0); // zero-length context

    let mut okm = vec![0u8; out_len];
    prk.expand(&info, &mut okm)
        .expect("HKDF-Expand-Label output length is valid");
    okm
}

/// Expands one direction's `key`/`iv`/`hp` from its Initial secret
/// (RFC 9001 §5.1, labels `quic key` / `quic iv` / `quic hp`).
fn directional_keys(secret: &[u8]) -> DirectionalKeys {
    let prk = Hkdf::<Sha256>::from_prk(secret).expect("Initial secret is a valid PRK length");

    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    key.copy_from_slice(&hkdf_expand_label(&prk, b"quic key", 16));
    iv.copy_from_slice(&hkdf_expand_label(&prk, b"quic iv", 12));
    hp.copy_from_slice(&hkdf_expand_label(&prk, b"quic hp", 16));

    DirectionalKeys { key, iv, hp }
}

/// Derives the client and server Initial keys from the Destination Connection ID
/// (RFC 9001 §5.2).
///
/// `initial_secret = HKDF-Extract(initial_salt, client_dcid)`, then each side's
/// secret is `HKDF-Expand-Label(initial_secret, "client in" | "server in", "", 32)`.
pub fn derive_initial_keys(dcid: &[u8]) -> ConnectionKeys {
    let extract = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), dcid);

    let client_secret = hkdf_expand_label(&extract, b"client in", 32);
    let server_secret = hkdf_expand_label(&extract, b"server in", 32);

    ConnectionKeys {
        client: directional_keys(&client_secret),
        server: directional_keys(&server_secret),
    }
}

/// Computes the 5-byte header-protection mask from a 16-byte ciphertext sample
/// (RFC 9001 §5.4.1). For `AEAD_AES_128_GCM` the header-protection cipher is
/// AES-128 (one ECB block).
pub fn header_protection_mask(hp_key: &[u8; 16], sample: &[u8]) -> [u8; 5] {
    let key = HeaderProtectionKey::new(&AES_128, hp_key).expect("valid AES-128 hp key");
    key.new_mask(sample)
        .expect("header-protection sample is 16 bytes")
}

/// AEAD-decrypts an Initial packet payload (RFC 9001 §5.3).
///
/// * `header` is the associated data: the packet header from the first byte
///   through the (unmasked) packet number.
/// * `payload` is the ciphertext including the trailing 16-byte GCM tag.
/// * `packet_number` is the full decoded packet number used to build the nonce.
///
/// The nonce is `iv` XOR the packet number left-padded to 12 bytes (big-endian).
pub fn decrypt_payload(
    keys: &DirectionalKeys,
    packet_number: u64,
    header: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let mut nonce = keys.iv;
    let pn_bytes = packet_number.to_be_bytes(); // 8 bytes, big-endian
    for (n, p) in nonce[4..].iter_mut().zip(pn_bytes.iter()) {
        *n ^= *p;
    }

    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &keys.key)?);

    let mut in_out = payload.to_vec();
    let plaintext = key.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(header),
        &mut in_out,
    )?;

    Ok(plaintext.to_vec())
}
