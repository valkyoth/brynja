use super::Error;
use brynja_cipher_chacha::ChaCha20;
use brynja_core::clear_owned_region;
use brynja_mac_poly1305::{OneTimeKey, Poly1305};

struct Clear<'a>(&'a mut [u8]);
impl Drop for Clear<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0);
    }
}

pub(super) enum Buffers<'a> {
    InPlace(&'a mut [u8]),
    Separate(&'a [u8], &'a mut [u8]),
}

impl Buffers<'_> {
    pub(super) fn admit(&self, aad: &[u8], work: &[u8]) -> Result<Frame, Error> {
        let len = match self {
            Self::Separate(input, out) if input.len() == out.len() => input.len(),
            Self::InPlace(data) => data.len(),
            _ => return Err(Error::Length),
        };
        if len != work.len() {
            return Err(Error::Length);
        }
        Frame::new(
            u64::try_from(aad.len()).map_err(|_| Error::Length)?,
            u64::try_from(len).map_err(|_| Error::Length)?,
        )
    }

    pub(super) fn transact<T>(
        self,
        work: &mut [u8],
        compute: impl FnOnce(&[u8], &mut [u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let work = Clear(work);
        let input: &[u8] = match &self {
            Self::InPlace(data) => data,
            Self::Separate(src, _) => src,
        };
        let result = compute(input, work.0)?;
        let (Self::InPlace(out) | Self::Separate(_, out)) = self;
        out.copy_from_slice(work.0);
        Ok(result)
    }
}

pub(super) fn crypt(
    key: &[u8; 32],
    nonce: [u8; 12],
    input: &[u8],
    work: &mut [u8],
) -> Result<(), Error> {
    ChaCha20::new(key, nonce, 1)
        .apply_keystream(input, work)
        .map_err(|_| Error::Invariant)
}

pub(super) struct Frame {
    aad: u64,
    payload: u64,
}
impl Frame {
    fn new(aad: u64, payload: u64) -> Result<Self, Error> {
        // Only counters 1..=u32::MAX are available for payload.
        const PAYLOAD_LIMIT: u64 = (1_u64 << 38) - 64;
        if payload > PAYLOAD_LIMIT {
            return Err(Error::Length);
        }
        aad.checked_next_multiple_of(16)
            .and_then(|a| a.checked_add(payload.checked_next_multiple_of(16)?))
            .and_then(|sum| sum.checked_add(16))
            .ok_or(Error::Length)?;
        Ok(Self { aad, payload })
    }

    pub(super) fn with_mac<T>(
        &self,
        key: &[u8; 32],
        nonce: [u8; 12],
        aad: &[u8],
        cipher: &[u8],
        finish: impl FnOnce(Poly1305<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut storage = [0; 32];
        // The guard also covers interruptions during derivation, before the
        // Poly1305 owner takes responsibility for the same storage.
        let guarded = Clear(&mut storage);
        ChaCha20::new(key, nonce, 0)
            .apply_keystream_in_place(guarded.0)
            .map_err(|_| Error::Invariant)?;
        let exact = guarded.0.first_chunk_mut::<32>().ok_or(Error::Invariant)?;
        let mut mac = OneTimeKey::from_rfc8439_key(exact).start();
        for data in [aad, cipher] {
            let padding = data.len().wrapping_neg() & 15;
            let zeros = [0; 16];
            mac.update(data).map_err(|_| Error::Invariant)?;
            mac.update(zeros.get(..padding).ok_or(Error::Invariant)?)
                .map_err(|_| Error::Invariant)?;
        }
        for length in [self.aad, self.payload] {
            mac.update(&length.to_le_bytes())
                .map_err(|_| Error::Invariant)?;
        }
        finish(mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_without_large_allocations() {
        let max = u64::from(u32::MAX) * 64;
        assert!(Frame::new(0, max).is_ok());
        assert!(Frame::new(0, max + 1).is_err());
        // Largest representable padded transcript is u64::MAX - 15.
        assert!(Frame::new(u64::MAX - 31, 0).is_ok());
        assert!(Frame::new(u64::MAX - 30, 0).is_err());
        assert!(Frame::new(u64::MAX, 0).is_err());
        assert!(Frame::new(u64::MAX - 31, 1).is_err());
    }
}
