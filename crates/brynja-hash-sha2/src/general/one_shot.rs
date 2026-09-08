use super::{
    HardenedSha512T, Sha512TBits, Sha512TDigest, Sha512TError, Sha512TSecretDigest, secret,
};
use crate::{BitString, PublicDeclassification};

/// Hashes confidential bytes and deliberately returns a public digest.
/// Synchronous linear work; caller inputs remain caller-owned.
pub fn hardened_sha512_t_public(
    parameter: Sha512TBits,
    input: &[u8],
    authority: PublicDeclassification,
) -> Result<Sha512TDigest, Sha512TError> {
    let mut state = HardenedSha512T::new(parameter);
    state.update(input)?;
    state.finalize_public(authority)
}
/// Hashes confidential canonical bits with explicit public declassification.
pub fn hardened_sha512_t_bits_public(
    parameter: Sha512TBits,
    input: BitString<'_>,
    authority: PublicDeclassification,
) -> Result<Sha512TDigest, Sha512TError> {
    HardenedSha512T::new(parameter).finalize_bits_public(input, authority)
}
/// Hashes confidential bytes into a typed secret owner. All errors clear output.
/// Destination admission precedes hashing; wrong-size clearing is linear in
/// destination length. Caller inputs are never erased by this API.
pub fn hardened_sha512_t_secret<'a>(
    parameter: Sha512TBits,
    input: &[u8],
    destination: &'a mut [u8],
) -> Result<Sha512TSecretDigest<'a>, Sha512TError> {
    let guard = secret::begin(parameter, destination)?;
    let mut state = HardenedSha512T::new(parameter);
    state.update(input)?;
    state.finish_secret(None, guard)
}
/// Hashes confidential canonical bits into a parameter-bound secret owner.
pub fn hardened_sha512_t_bits_secret<'a>(
    parameter: Sha512TBits,
    input: BitString<'_>,
    destination: &'a mut [u8],
) -> Result<Sha512TSecretDigest<'a>, Sha512TError> {
    let guard = secret::begin(parameter, destination)?;
    let mut state = HardenedSha512T::new(parameter);
    state.finish_secret(Some(input), guard)
}
