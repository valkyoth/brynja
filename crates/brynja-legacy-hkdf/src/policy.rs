/// Full SHA-1 digest size; HKDF never uses a truncated HMAC tag.
pub const HASH_BYTES: usize = 20;
/// RFC 5869 output limit: 255 full SHA-1 digest blocks.
pub const MAX_OUTPUT_BYTES: usize = 5100;

// This is the runtime admission predicate, also compiled by the proof fixture.
pub(crate) fn expansion_blocks(length: usize) -> Option<u8> {
    if length > MAX_OUTPUT_BYTES {
        return None;
    }
    u8::try_from(length.div_ceil(HASH_BYTES)).ok()
}
