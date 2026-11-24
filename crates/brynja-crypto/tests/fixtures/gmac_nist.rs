//! Shared GMAC test decoder and public AES-128 fixture from NIST GCMVS
//! gcmEncryptExtIV128.rsp, Count=0, PTlen=0, AADlen=128, IVlen=96, Taglen=128.
//! These are replay inputs, not a source of IVs for signing.

extern crate alloc;
use super::GmacError;

pub const AES128: [&str; 4] = [
    "77be63708971c4e240d1cb79e8d77feb",
    "e0e00f19fed7ba0136a797f3",
    "7a43ec1d9c0a5a78a0b16533a6213cab",
    "209fcc8d3675ed938e9c7166709dd946",
];

pub fn bytes<const N: usize>(hex: &str) -> Result<[u8; N], GmacError> {
    let (pairs, tail) = hex.as_bytes().as_chunks::<2>();
    if pairs.len() != N || !tail.is_empty() {
        return Err(GmacError::Length);
    }
    pairs
        .iter()
        .map(|pair| {
            u8::from_str_radix(
                core::str::from_utf8(pair).map_err(|_| GmacError::Length)?,
                16,
            )
            .map_err(|_| GmacError::Length)
        })
        .collect::<Result<alloc::vec::Vec<_>, _>>()?
        .try_into()
        .map_err(|_| GmacError::Length)
}
