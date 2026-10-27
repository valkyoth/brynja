use super::{Algorithm, Bits, Cancellation, Error, Kernel, Request, TagPolicy};
use brynja_crypto_cpu::static_execution::Authority;
use brynja_mac_hmac::execution::{Algorithm as CpuAlgorithm, Hmac};

// Called only after resident-stack entry. No keyed state in the launch record.
pub(super) fn probe<A: Algorithm + for<'a> CpuAlgorithm<'a>>(kernel: Kernel) -> Result<(), Error> {
    let owner = Authority::new(kernel).map_err(Error::Backend)?;
    let state = Hmac::<A>::from_static(&owner, &[]).map_err(Error::Mac)?;
    if state.kernel() != kernel {
        return Err(Error::Invariant);
    }
    state.cancel();
    owner.session().map(|_| ()).map_err(Error::Backend)
}

fn checkpoint(cancel: &Cancellation, owner: &Authority) -> Result<(), Error> {
    #[cfg(test)]
    {
        super::super::tests::checkpoint(cancel);
        super::super::tests::revoke(owner);
    }
    // A concurrent cancellation must not mask backend revocation.
    let _ = owner.session().map_err(Error::Backend)?;
    cancel.check()
}

pub(super) fn run<A: Algorithm + for<'a> CpuAlgorithm<'a>>(
    kernel: Kernel,
    policy: TagPolicy,
    request: Request<'_>,
    candidate: Option<&[u8]>,
    cancel: &Cancellation,
    staging: &mut [u8],
    destination: &mut [u8],
) -> Result<Option<bool>, Error> {
    cancel.check()?;
    let owner = Authority::new(kernel).map_err(Error::Backend)?;
    checkpoint(cancel, &owner)?;
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
        TagPolicy::Full => Hmac::<A>::from_static(&owner, request.key),
        TagPolicy::Bytes(bytes) => {
            Hmac::<A>::from_static_with_tag_length(&owner, request.key, bytes)
        }
    }
    .map_err(Error::Mac)?;
    if state.kernel() != kernel {
        return Err(Error::Invariant);
    }
    #[cfg(test)]
    {
        super::super::tests::observe(&owner, staging, destination);
        super::super::tests::observe(&state, staging, destination);
    }
    for chunk in request
        .chunks
        .iter()
        .copied()
        .chain(core::iter::once(complete))
    {
        checkpoint(cancel, &owner)?;
        for part in chunk.chunks(4096) {
            checkpoint(cancel, &owner)?;
            state.update(part).map_err(Error::Mac)?;
        }
    }
    checkpoint(cancel, &owner)?;
    let result = if let Some(candidate) = candidate {
        Some(match state.verify_bits(tail, candidate) {
            Ok(()) => true,
            Err(brynja_mac_hmac::Error::Mismatch) => false,
            Err(error) => return Err(Error::Mac(error)),
        })
    } else {
        let secret = state
            .finalize_bits_secret(tail, staging)
            .map_err(Error::Mac)?;
        checkpoint(cancel, &owner)?;
        brynja_core::copy_secret_region(destination, secret.expose())
            .map_err(|_| Error::Invariant)?;
        #[cfg(test)]
        super::super::tests::after_write();
        None
    };
    checkpoint(cancel, &owner)?;
    Ok(result)
}
