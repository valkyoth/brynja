//! Reproducible, public, non-uniform oracle inputs (arithmetic modulo 256).
pub fn key(length: usize) -> Vec<u8> {
    (0..=255_u8)
        .cycle()
        .take(length)
        .map(|n| n.wrapping_mul(0x9d) ^ 0x5a)
        .collect()
}
pub fn message(length: usize) -> Vec<u8> {
    (0..=255_u8)
        .cycle()
        .take(length)
        .map(|n| n.wrapping_mul(0x3b) ^ 0xc1)
        .collect()
}
