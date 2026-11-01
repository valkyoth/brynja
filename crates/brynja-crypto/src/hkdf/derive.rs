use core::marker::PhantomData;

use brynja_core::{
    OwnedSecretRegion, SecretRegionInitialization, clear_owned_region, copy_secret_region,
};
use brynja_mac_hmac::Hmac;

use super::{ExpansionLength, ParameterError, Tls13Label};

// Test instrumentation is absent from normal builds and is not a public hook.
#[cfg(test)]
#[path = "fault_support.rs"]
mod fault;

mod sealed {
    pub trait Modern {}
    impl Modern for brynja_mac_hmac::Sha224 {}
    impl Modern for brynja_mac_hmac::Sha256 {}
    impl Modern for brynja_mac_hmac::Sha384 {}
    impl Modern for brynja_mac_hmac::Sha512 {}
    impl Modern for brynja_mac_hmac::Sha512_224 {}
    impl Modern for brynja_mac_hmac::Sha512_256 {}
}

/// Sealed admission of the six standard byte-aligned SHA-2 HMAC identities.
///
/// No general SHA-512/t, legacy hash, SHA-3 or downstream implementation is
/// admitted. This is a portable construction, not CPU authority or certification.
///
/// ```compile_fail
/// use brynja_crypto::hkdf::Prk;
/// let mut storage = [0; 32];
/// let _ = Prk::<brynja_crypto::hmac::Sha3_256>::extract(None, b"ikm", &mut storage);
/// ```
pub trait Algorithm: brynja_mac_hmac::Algorithm + sealed::Modern {}
impl<A: brynja_mac_hmac::Algorithm + sealed::Modern> Algorithm for A {}

/// Value-free error from HKDF admission or secret processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid public length or TLS label; the destination is unchanged.
    Parameters(ParameterError),
    /// An imported PRK is shorter than the selected full digest.
    PrkLength,
    /// Extract/import destination has the wrong exact length; it is unchanged.
    DestinationLength,
    /// HMAC processing failed after secret output admission; that output clears.
    Hmac(brynja_mac_hmac::Error),
    /// An owned-memory or internal bound invariant failed.
    SecretMemory,
}

impl From<ParameterError> for Error {
    fn from(value: ParameterError) -> Self {
        Self::Parameters(value)
    }
}
impl From<brynja_mac_hmac::Error> for Error {
    fn from(value: brynja_mac_hmac::Error) -> Self {
        Self::Hmac(value)
    }
}
impl From<brynja_core::SecretMemoryError> for Error {
    fn from(_: brynja_core::SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}

// Never return populated scratch by value. Both buffers clear on errors/unwind.
struct Scratch<const N: usize>([u8; N]);
impl<const N: usize> Scratch<N> {
    fn new() -> Self {
        Self([0; N])
    }
    fn prefix(&mut self, size: usize) -> Result<&mut [u8], Error> {
        self.0.get_mut(..size).ok_or(Error::SecretMemory)
    }
}
impl<const N: usize> Drop for Scratch<N> {
    fn drop(&mut self) {
        #[cfg(test)]
        let populated = self.0.iter().any(|byte| *byte != 0);
        let _ = clear_owned_region(&mut self.0);
        #[cfg(test)]
        fault::observe_scratch(populated, &self.0);
    }
}

/// Affine caller-backed pseudorandom key, bound to one admitted SHA-2 identity.
///
/// Drop clears its complete region. No Clone, Copy, Debug, Send or Sync is
/// exposed. Expansion borrows the owner, allowing deliberate domain-separated
/// reuse without exporting or reconstructing the PRK. Safe borrows prohibit
/// input/output overlap; disjoint slices of one allocation are supported.
///
/// ```
/// use brynja_crypto::hkdf::{Prk, Sha256, Error};
/// let mut prk_bytes = [0; 32];
/// let prk = Prk::<Sha256>::extract(Some(b"salt"), b"input key material", &mut prk_bytes)?;
/// let mut output = [0; 42];
/// let key = prk.expand(b"application context", &mut output)?;
/// assert_eq!(key.expose().len(), 42);
/// drop(key);
/// assert_eq!(output, [0; 42]);
/// drop(prk);
/// assert_eq!(prk_bytes, [0; 32]);
/// # Ok::<(), Error>(())
/// ```
///
/// ```compile_fail
/// use brynja_crypto::hkdf::{Prk, Sha256};
/// let mut bytes = [0; 32];
/// let prk = Prk::<Sha256>::extract(None, b"ikm", &mut bytes).unwrap();
/// let _duplicate = prk.clone();
/// ```
///
/// ```compile_fail
/// use brynja_crypto::hkdf::{Prk, Sha256};
/// let mut bytes = [0; 32];
/// let prk = Prk::<Sha256>::extract(None, b"ikm", &mut bytes).unwrap();
/// println!("{prk:?}");
/// ```
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_crypto::hkdf::Prk<'static, brynja_crypto::hkdf::Sha256>>();
/// ```
///
/// ```compile_fail
/// use brynja_crypto::hkdf::{Prk, Sha256};
/// let mut bytes = [0; 32];
/// let prk = Prk::<Sha256>::extract(None, b"ikm", &mut bytes).unwrap();
/// let _key = prk.expand(b"info", &mut bytes).unwrap();
/// ```
#[must_use = "keep PRK ownership live until expansion is complete"]
pub struct Prk<'a, A: Algorithm> {
    region: OwnedSecretRegion<'a>,
    local: PhantomData<(A, *mut ())>,
}

impl<'a, A: Algorithm> Prk<'a, A> {
    /// Extracts exactly one full digest into clearing caller-owned storage.
    ///
    /// `None` means HashLen zero bytes; `Some(&[])` is an explicitly empty salt.
    /// They give the same result for these HMAC identities, but remain explicit
    /// choices. Empty IKM is accepted mathematically, not as an entropy claim.
    /// Wrong destination length is unchanged. Once admitted, errors or unwind
    /// clear the complete destination. Caller-owned salt/IKM are not cleared.
    pub fn extract(
        salt: Option<&[u8]>,
        ikm: &[u8],
        destination: &'a mut [u8],
    ) -> Result<Self, Error> {
        if destination.len() != A::TAG_BYTES {
            return Err(Error::DestinationLength);
        }
        let mut initialization = SecretRegionInitialization::begin(destination)?;
        #[cfg(test)]
        fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        let zeros = [0; 64];
        let default_salt = zeros.get(..A::TAG_BYTES).ok_or(Error::SecretMemory)?;
        let mut mac = Hmac::<A>::new(salt.unwrap_or(default_salt))?;
        #[cfg(test)]
        fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        mac.update(ikm)?;
        #[cfg(test)]
        fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        let mut block = Scratch::<64>::new();
        let tag = mac.finalize_secret(block.prefix(A::TAG_BYTES)?)?;
        #[cfg(test)]
        fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        initialization.write(tag.expose())?;
        #[cfg(test)]
        fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        Ok(Self {
            region: initialization.finish()?,
            local: PhantomData,
        })
    }

    /// Copies an already pseudorandom key of at least HashLen bytes into ownership.
    ///
    /// This does not extract entropy or establish that the input is pseudorandom.
    /// Use Extract for raw input key material. Destination must exactly match
    /// input length; either public length rejection leaves it unchanged.
    /// The caller retains responsibility for clearing the imported input.
    pub fn import(input: &[u8], destination: &'a mut [u8]) -> Result<Self, Error> {
        if input.len() < A::TAG_BYTES {
            return Err(Error::PrkLength);
        }
        if destination.len() != input.len() {
            return Err(Error::DestinationLength);
        }
        let mut initialization = SecretRegionInitialization::begin(destination)?;
        #[cfg(test)]
        fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        initialization.write(input)?;
        #[cfg(test)]
        fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        Ok(Self {
            region: initialization.finish()?,
            local: PhantomData,
        })
    }

    /// Explicitly borrows the secret PRK; application copies need their own cleanup.
    pub fn expose(&self) -> &[u8] {
        self.region.expose()
    }

    /// Expands to exactly the destination length, at most 255 full digest blocks.
    ///
    /// Empty output is allowed and performs no HMAC. Public length rejection
    /// leaves destination unchanged. Once admitted, operational errors/unwind
    /// clear the entire destination; partial output is never returned. Successful
    /// output clears on owner Drop. PRK remains reusable on success or failure.
    pub fn expand<'b>(
        &self,
        info: &[u8],
        destination: &'b mut [u8],
    ) -> Result<DerivedKey<'b, A>, Error> {
        let plan = ExpansionLength::new(A::TAG_BYTES, destination.len())?;
        if destination.is_empty() {
            return Ok(DerivedKey {
                region: None,
                local: PhantomData,
            });
        }
        let mut remaining = destination.len();
        let mut initialization = SecretRegionInitialization::begin(destination)?;
        #[cfg(test)]
        fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        let mut previous = Scratch::<64>::new();
        let mut block = Scratch::<64>::new();
        for counter in plan.counters() {
            let mut mac = Hmac::<A>::new(self.expose())?;
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            if counter != 1 {
                mac.update(previous.prefix(A::TAG_BYTES)?)?;
            }
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            mac.update(info)?;
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            mac.update(&[counter])?;
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            let tag = mac.finalize_secret(block.prefix(A::TAG_BYTES)?)?;
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            let take = remaining.min(A::TAG_BYTES);
            initialization.write(tag.expose().get(..take).ok_or(Error::SecretMemory)?)?;
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            remaining = remaining.checked_sub(take).ok_or(Error::SecretMemory)?;
            if remaining != 0 {
                copy_secret_region(previous.prefix(A::TAG_BYTES)?, tag.expose())?;
            }
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        }
        Ok(DerivedKey {
            region: Some(initialization.finish()?),
            local: PhantomData,
        })
    }

    /// Encodes the TLS 1.3 label then expands to the destination's exact length.
    ///
    /// Label excludes `tls13 `; context is used verbatim, not hashed. Wire/length
    /// errors leave destination unchanged. This helper does not select a cipher
    /// suite or assert that every admitted hash is a TLS cipher-suite hash.
    pub fn expand_label<'b>(
        &self,
        label: &[u8],
        context: &[u8],
        destination: &'b mut [u8],
    ) -> Result<DerivedKey<'b, A>, Error> {
        let label = Tls13Label::new(label, context, destination.len())?;
        let mut encoded = Scratch::<514>::new();
        self.expand(label.encode(&mut encoded.0)?, destination)
    }
}

/// Completely initialized output key material; Drop clears its caller buffer.
///
/// Neither a public tag nor a Copy/Clone/Debug/Send/Sync owner. An empty output
/// has no owned region. Application-created copies require separate cleanup.
///
/// ```compile_fail
/// fn copy<T: Copy>() {}
/// copy::<brynja_crypto::hkdf::DerivedKey<'static, brynja_crypto::hkdf::Sha256>>();
/// ```
///
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_crypto::hkdf::DerivedKey<'static, brynja_crypto::hkdf::Sha256>>();
/// ```
#[must_use = "keep secret ownership live until the derived key is no longer needed"]
pub struct DerivedKey<'a, A: Algorithm> {
    region: Option<OwnedSecretRegion<'a>>,
    local: PhantomData<(A, *mut ())>,
}
impl<A: Algorithm> DerivedKey<'_, A> {
    /// Borrows derived secret bytes, without transferring their clearing owner.
    pub fn expose(&self) -> &[u8] {
        self.region.as_ref().map_or(&[], OwnedSecretRegion::expose)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_faults<A: Algorithm>() -> Result<(), Error> {
        fault::exercise(A::TAG_BYTES, 5, |destination| {
            let _prk =
                Prk::<A>::extract(Some(b"public test salt"), b"public test ikm", destination)?;
            Ok::<(), Error>(())
        })
    }

    fn expand_faults<A: Algorithm>() -> Result<(), Error> {
        let mut bytes = [0; 64];
        let storage = bytes.get_mut(..A::TAG_BYTES).ok_or(Error::SecretMemory)?;
        let prk = Prk::<A>::extract(None, b"public test ikm", storage)?;
        let mut expected = [0; 64];
        let expected = expected
            .get_mut(..A::TAG_BYTES)
            .ok_or(Error::SecretMemory)?;
        expected.copy_from_slice(prk.expose());
        // Three blocks: one admission point plus seven points per block.
        let length = A::TAG_BYTES
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::SecretMemory)?;
        fault::exercise(length, 22, |destination| {
            let result = prk.expand(b"public context", destination).map(drop);
            assert_eq!(prk.expose(), expected);
            result
        })?;
        // Also checked after unwinding, where the closure's assertion was skipped.
        assert_eq!(prk.expose(), expected);
        assert!(fault::saw_populated_scratch(64));
        let mut output = [0; 1];
        let _key = prk.expand(b"usable after every injection", &mut output)?;
        Ok(())
    }

    #[test]
    fn hkdf_fault_extract_all_modern_identities() -> Result<(), Error> {
        extract_faults::<super::super::Sha224>()?;
        extract_faults::<super::super::Sha256>()?;
        extract_faults::<super::super::Sha384>()?;
        extract_faults::<super::super::Sha512>()?;
        extract_faults::<super::super::Sha512_224>()?;
        extract_faults::<super::super::Sha512_256>()
    }

    #[test]
    fn hkdf_fault_expand_all_modern_identities() -> Result<(), Error> {
        expand_faults::<super::super::Sha224>()?;
        expand_faults::<super::super::Sha256>()?;
        expand_faults::<super::super::Sha384>()?;
        expand_faults::<super::super::Sha512>()?;
        expand_faults::<super::super::Sha512_224>()?;
        expand_faults::<super::super::Sha512_256>()
    }

    #[test]
    fn hkdf_fault_import_clears_entire_region() -> Result<(), Error> {
        fault::exercise(80, 2, |destination| {
            let _prk = Prk::<super::super::Sha256>::import(&[0x42; 80], destination)?;
            Ok::<(), Error>(())
        })
    }

    #[test]
    fn hkdf_fault_tls_label_scratch_clears() -> Result<(), Error> {
        let mut storage = [0; 32];
        let prk = Prk::<super::super::Sha256>::extract(None, b"public test ikm", &mut storage)?;
        fault::exercise(65, 22, |destination| {
            prk.expand_label(b"key", b"public context", destination)
                .map(drop)
        })?;
        assert!(fault::saw_populated_scratch(514));
        Ok(())
    }

    #[test]
    fn hkdf_fault_populated_scratch_drop_and_unwind() {
        fault::exercise_scratch(
            || {
                let mut scratch = Scratch::<64>::new();
                scratch.0.fill(0x42);
                fault::unwind_if_requested();
            },
            64,
        );
    }
}
