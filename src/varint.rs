//! QUIC variable-length integer decoding (RFC 9000 §16).

/// Reads a QUIC variable-length integer starting at `pos`.
///
/// The two most-significant bits of the first byte encode the length of the
/// integer in bytes: `00` → 1, `01` → 2, `10` → 4, `11` → 8. The remaining six
/// bits of that first byte are the most-significant bits of the value. Returns
/// the decoded value together with the position immediately after the integer.
pub fn read_varint(buf: &[u8], pos: usize) -> (u64, usize) {
    let len = 1usize << (buf[pos] >> 6);

    // The low six bits of the first byte are part of the value.
    let mut value = (buf[pos] & 0x3f) as u64;
    for &byte in &buf[pos + 1..pos + len] {
        value = (value << 8) | byte as u64;
    }

    (value, pos + len)
}
