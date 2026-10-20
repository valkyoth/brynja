use super::{Algorithm, Bits, Cancellation, Error, Request, TagPolicy};
use brynja_mac_hmac as mac;

// Private sealed bridge: canonical input contents are inspected on the worker.
pub trait Backend: mac::Algorithm {
    fn tail(bits: Bits<'_>) -> Result<Self::FinalInput<'_>, Error>;
}
macro_rules! bridge {
    ($bits:ident; $($name:ident),+) => {$(
        impl Backend for mac::$name {
            fn tail(bits: Bits<'_>) -> Result<Self::FinalInput<'_>, Error> {
                mac::$bits::new(bits.bytes, bits.valid_bits).map_err(|_| Error::InvalidBits)
            }
        }
    )+};
}
bridge!(Sha2BitString; Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256);
bridge!(Fips202BitString; Sha3_224, Sha3_256, Sha3_384, Sha3_512);
impl<const T: u16> Backend for mac::Sha512T<T> {
    fn tail(bits: Bits<'_>) -> Result<Self::FinalInput<'_>, Error> {
        mac::Sha2BitString::new(bits.bytes, bits.valid_bits).map_err(|_| Error::InvalidBits)
    }
}

fn checkpoint(cancel: &Cancellation) -> Result<(), Error> {
    #[cfg(test)]
    super::tests::checkpoint(cancel);
    cancel.check()
}

pub(super) fn run<A: Algorithm>(
    policy: TagPolicy,
    request: Request<'_>,
    candidate: Option<&[u8]>,
    cancel: &Cancellation,
    staging: &mut [u8],
    destination: &mut [u8],
) -> Result<Option<bool>, Error> {
    checkpoint(cancel)?;
    // Validate canonical contents only after entry, then chunk the byte prefix.
    let _ = A::tail(request.tail)?;
    let split = if request.tail.valid_bits == 8 || request.tail.bytes.is_empty() {
        request.tail.bytes.len()
    } else {
        request
            .tail
            .bytes
            .len()
            .checked_sub(1)
            .ok_or(Error::InvalidBits)?
    };
    let (complete, partial) = request
        .tail
        .bytes
        .split_at_checked(split)
        .ok_or(Error::Invariant)?;
    let tail = A::tail(Bits {
        bytes: partial,
        valid_bits: if partial.is_empty() {
            0
        } else {
            request.tail.valid_bits
        },
    })?;
    let mut state = match policy {
        TagPolicy::Full => mac::Hmac::<A>::new(request.key),
        TagPolicy::Bytes(bytes) => mac::Hmac::<A>::with_tag_length(request.key, bytes),
    }
    .map_err(Error::Mac)?;
    #[cfg(test)]
    super::tests::observe(&state, staging, destination);
    for chunk in request
        .chunks
        .iter()
        .copied()
        .chain(core::iter::once(complete))
    {
        checkpoint(cancel)?;
        for part in chunk.chunks(4096) {
            checkpoint(cancel)?;
            state.update(part).map_err(Error::Mac)?;
        }
    }
    checkpoint(cancel)?;
    let result = if let Some(candidate) = candidate {
        // Only the explicitly released boolean crosses back to the host stack.
        Some(
            state
                .verify_bits(tail, candidate)
                .map_err(Error::Mac)?
                .expose_public(),
        )
    } else {
        let secret = state
            .finalize_bits_secret(tail, staging)
            .map_err(Error::Mac)?;
        checkpoint(cancel)?;
        brynja_core::copy_secret_region(destination, secret.expose())
            .map_err(|_| Error::Invariant)?;
        #[cfg(test)]
        super::tests::after_write();
        None
    };
    checkpoint(cancel)?;
    Ok(result)
}
