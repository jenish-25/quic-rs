//! Parsing and decryption of QUIC Initial packets
//! (RFC 9000 §17.2.2, RFC 9001 §5).

use std::io::{Error, ErrorKind};

use crate::crypto;
use crate::varint::read_varint;

/// A parsed and decrypted QUIC Initial packet.
#[derive(Debug)]
pub struct InitialPacket {
    /// QUIC version from the long header.
    pub version: u32,
    /// Destination Connection ID (the value the client chose; the key material).
    pub dcid: Vec<u8>,
    /// Source Connection ID.
    pub scid: Vec<u8>,
    /// Decoded packet number.
    pub packet_number: u64,
    /// Decrypted QUIC frames: the CRYPTO frame carrying the TLS ClientHello,
    /// followed by any PADDING.
    pub frames: Vec<u8>,
}

fn invalid(msg: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, msg)
}

/// Parses a QUIC Initial packet from a received datagram, removes header
/// protection, recovers the packet number, and AEAD-decrypts the payload,
/// returning the plaintext frames.
pub fn decrypt_initial(datagram: &[u8]) -> Result<InitialPacket, Error> {
    let mut pos = 0;

    let first_byte = datagram[pos];
    pos += 1;

    // Long-header form (bit 7 set), fixed bit (bit 6 set), Initial type
    // (bits 5-4 == 00).
    if first_byte & 0x80 == 0 || first_byte & 0x30 != 0 {
        return Err(invalid("not a QUIC long-header Initial packet"));
    }

    let version = u32::from_be_bytes(
        datagram[pos..pos + 4]
            .try_into()
            .map_err(|_| invalid("truncated version"))?,
    );
    pos += 4;

    let dcid_len = datagram[pos] as usize;
    pos += 1;
    let dcid = datagram[pos..pos + dcid_len].to_vec();
    pos += dcid_len;

    let scid_len = datagram[pos] as usize;
    pos += 1;
    let scid = datagram[pos..pos + scid_len].to_vec();
    pos += scid_len;

    // Token-length varint, then skip the token itself.
    let (token_len, next) = read_varint(datagram, pos);
    pos = next + token_len as usize;

    // Length varint: covers the packet number plus the encrypted payload.
    let (length, next) = read_varint(datagram, pos);
    pos = next;

    // `pos` now points at the start of the packet number.
    let pn_offset = pos;
    let payload_end = pn_offset + length as usize;
    if payload_end > datagram.len() || datagram.len() < pn_offset + 4 + 16 {
        return Err(invalid("packet shorter than its declared length"));
    }

    // Derive the Initial keys from the client's DCID and use the client keys to
    // decrypt the client-sent Initial packet.
    let keys = crypto::derive_initial_keys(&dcid);
    let client = &keys.client;

    // --- Remove header protection (RFC 9001 §5.4) ---
    // The sample is taken 4 bytes past the packet-number offset (the maximum
    // packet-number length), since the real length is not yet known.
    let sample_offset = pn_offset + 4;
    let sample = &datagram[sample_offset..sample_offset + 16];
    let mask = crypto::header_protection_mask(&client.hp, sample);

    // For a long header, the low 4 bits of the first byte are protected.
    let unmasked_first = first_byte ^ (mask[0] & 0x0f);
    let pn_len = ((unmasked_first & 0x03) + 1) as usize;

    // Unmask the packet-number bytes and decode the (truncated) packet number.
    // For the first Initial packet there is no larger acknowledged packet, so
    // the truncated value is the full packet number.
    let mut pn_bytes = Vec::with_capacity(pn_len);
    let mut packet_number: u64 = 0;
    for i in 0..pn_len {
        let b = datagram[pn_offset + i] ^ mask[1 + i];
        pn_bytes.push(b);
        packet_number = (packet_number << 8) | b as u64;
    }

    // --- AEAD decrypt (RFC 9001 §5.3) ---
    // Associated data is the header through the packet number, with the first
    // byte and packet-number bytes in their unmasked form.
    let mut header = datagram[..pn_offset + pn_len].to_vec();
    header[0] = unmasked_first;
    header[pn_offset..pn_offset + pn_len].copy_from_slice(&pn_bytes);

    let payload = &datagram[pn_offset + pn_len..payload_end];
    let frames = crypto::decrypt_payload(client, packet_number, &header, payload)
        .map_err(|_| invalid("AEAD decryption failed"))?;

    Ok(InitialPacket {
        version,
        dcid,
        scid,
        packet_number,
        frames,
    })
}
