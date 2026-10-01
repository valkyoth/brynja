//! Miri prefix-only model: exact production prefix source, synthetic byte sink.
//! Does not execute or qualify AVX2, VBS, the real engine or protected placement.
#![forbid(unsafe_code)]
pub use brynja_hash_sha3::Fips202BitString;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    PrefixEncoding,
    LengthOverflow,
    Terminal,
    SecretMemory,
}
mod engine {
    pub struct Engine<'a> {
        pub bytes: Vec<u8>,
        pub lifetime: core::marker::PhantomData<&'a ()>,
    }
    impl Engine<'_> {
        pub fn update(&mut self, bytes: &[u8]) -> Result<(), super::Error> {
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }
    }
}
mod sha3_accelerated_prefix;
