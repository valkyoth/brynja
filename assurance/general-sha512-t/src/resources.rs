//! Object storage ceilings, not total stack/high-water or physical-erasure claims.
use crate::acceptance::{Error, ensure};
use brynja_hash_sha2::{HardenedSha512T, Sha512T, Sha512TBits, Sha512TDigest, Sha512TSecretDigest};

/// Fixed source-owned objects remain independent of input length and public t.
pub fn check() -> Result<(), Error> {
    ensure(core::mem::size_of::<Sha512T>() <= 256)?;
    ensure(core::mem::size_of::<HardenedSha512T>() <= 1200)?;
    ensure(core::mem::size_of::<Sha512TDigest>() <= 72)?;
    ensure(core::mem::size_of::<Sha512TSecretDigest<'_>>() <= 32)?;
    for t in 1..512 {
        if t == 384 {
            continue;
        }
        let p = Sha512TBits::new(t)?;
        let state = HardenedSha512T::new(p);
        ensure(p.output_bytes() <= 64)?;
        ensure(state.check_additional_bits(u128::MAX).is_ok())?;
        ensure(state.check_additional_bytes(u128::MAX).is_err())?;
        ensure(state.message_bytes() == 0)?;
        state.cancel();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixed_storage_and_public_work_bounds() -> Result<(), super::Error> {
        super::check()
    }
}
