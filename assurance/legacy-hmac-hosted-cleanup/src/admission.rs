//! Typed public metadata projections, independent of the host walker.
use super::host::{Limits, Md5, Md5BatchLimits, Request, Session, Sha1CompiledSession};

#[inline(never)]
pub fn scalar_key_limit(value: &Limits) -> usize {
    value.max_key_bytes
}
#[inline(never)]
pub fn scalar_chunk_limit(value: &Limits) -> usize {
    value.max_chunks
}
#[inline(never)]
pub fn scalar_bit_limit(value: &Limits) -> u128 {
    value.max_message_bits
}
#[inline(never)]
pub fn batch_key_limit(value: &Md5BatchLimits) -> usize {
    value.max_key_bytes
}
#[inline(never)]
pub fn batch_bit_limit(value: &Md5BatchLimits) -> u128 {
    value.max_message_bits
}
#[inline(never)]
pub fn key_length(value: &Request<'_>) -> usize {
    value.key.len()
}
#[inline(never)]
pub fn chunk_count(value: &Request<'_>) -> usize {
    value.chunks.len()
}
#[inline(never)]
pub fn tail_length(value: &Request<'_>) -> usize {
    value.tail.bytes.len()
}
#[inline(never)]
pub fn tail_bits(value: &Request<'_>) -> u8 {
    value.tail.valid_bits
}
#[inline(never)]
pub fn scalar_width(value: &Session<Md5>) -> usize {
    value.tag_bytes()
}
#[inline(never)]
pub fn compiled_width(value: &Sha1CompiledSession) -> usize {
    value.tag_bytes()
}
