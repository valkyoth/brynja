//! Fixed, independent corpus acceptance of ordinary explicit CPU routes.
#![no_std]
use brynja_crypto_cpu::{Sha512BackendHealth, Sha512BackendSession};
use brynja_general_sha512_t_consumer::{acceptance::Error, visit_corpus};
use brynja_hash_sha2::*;

fn ensure(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Mismatch) }
}
fn check(
    value: Result<Sha512TDigest, Sha512TAcceleratedError>,
    p: Sha512TBits,
    expected: &[u8],
) -> Result<(), Error> {
    let digest = value.map_err(|_| Error::Mismatch)?;
    ensure(digest.parameter() == p && digest.as_bytes() == expected)
}

/// Checks all 4590 frozen vectors, byte/bit one-shot and irregular streams.
pub fn run(corpus: &str, backend: &Sha512BackendSession) -> Result<usize, Error> {
    ensure(backend.health() == Sha512BackendHealth::Healthy)?;
    visit_corpus(corpus, |t, bits, bytes, expected| {
        let p = Sha512TBits::new(t)?;
        let width = if bits == 0 {
            0
        } else {
            ((bits - 1) % 8 + 1) as u8
        };
        let input = BitString::new(bytes, width).map_err(|_| Error::Corpus)?;
        check(sha512_t_bits_with_backend(p, input, backend), p, expected)?;
        if bits % 8 == 0 {
            check(sha512_t_with_backend(p, bytes, backend), p, expected)?;
        }
        for stride in [1, 19, 128] {
            let mut state = Sha512T::new(p);
            let complete = bits / 8;
            for chunk in bytes[..complete].chunks(stride) {
                state
                    .update_with_backend(chunk, backend)
                    .map_err(|_| Error::Mismatch)?;
            }
            ensure(state.message_bytes() == complete as u128)?;
            state
                .update_with_backend(&[], backend)
                .map_err(|_| Error::Mismatch)?;
            if bits % 8 == 0 {
                check(state.finalize_with_backend(backend), p, expected)?;
            } else {
                let tail = BitString::new(&bytes[complete..], (bits % 8) as u8)
                    .map_err(|_| Error::Corpus)?;
                check(state.finalize_bits_with_backend(tail, backend), p, expected)?;
            }
        }
        Ok(())
    })
}

/// Injected KAT-failure evidence must reject every API without mutation/fallback.
pub fn quarantine(backend: &Sha512BackendSession) -> Result<(), Error> {
    ensure(backend.health() == Sha512BackendHealth::Quarantined)?;
    let expected = Some(Sha512TAcceleratedError::Backend(
        Sha512AcceleratedError::BackendQuarantined,
    ));
    let p = Sha512TBits::new(9)?;
    let bits = BitString::new(&[0xa0], 3).map_err(|_| Error::Corpus)?;
    for bytes in [&[][..], &[0x55; 129][..]] {
        let mut state = Sha512T::new(p);
        state.update(b"abc")?;
        ensure(state.update_with_backend(bytes, backend).err() == expected)?;
        ensure(state.message_bytes() == 3)?;
        ensure(state.finalize()? == sha512_t(p, b"abc")?)?;
        ensure(sha512_t_with_backend(p, bytes, backend).err() == expected)?;
    }
    ensure(Sha512T::new(p).finalize_with_backend(backend).err() == expected)?;
    ensure(
        Sha512T::new(p)
            .finalize_bits_with_backend(bits, backend)
            .err()
            == expected,
    )?;
    ensure(sha512_t_bits_with_backend(p, bits, backend).err() == expected)?;
    Ok(())
}
