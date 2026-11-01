//! Explicit legacy-only RFC 5869 HKDF-SHA-1 compatibility.
//!
//! For historical protocol requirements, not new protocol selection. Both PRK
//! constructors require [`LegacyUse`]. There is no generic digest parameter,
//! MD5 HKDF, TLS 1.3 label expansion, backend selection or modern fallback.
//! The existing legacy HMAC dependency also contains MD5, but this API never
//! selects it. Modern `brynja-crypto` does not depend on this crate.
//!
//! Development implementation: HKDF-specific proof, fault, compiler and security
//! qualification is unfinished. Reusing hardened HMAC is not qualification of
//! this composition. All production code is allocation-free and `no_std`.
//! Input entropy, salt selection and domain separation remain protocol duties.
//! This is not password hashing, certification or protected/resident memory.
//!
//! Caller-backed PRK/output and internal scratch clear on ordinary Drop and
//! recoverable unwind. Caller copies, forgotten owners, compiler spills/moves,
//! paging, aborts and process termination are outside that guarantee.

#![no_std]
#![forbid(unsafe_code)]

use brynja_core::{
    OwnedSecretRegion, SecretRegionInitialization, clear_owned_region, copy_secret_region,
};
use brynja_legacy_hmac::{Hmac, Sha1};

// Test-only controls; no fault callback or feature is exposed in normal builds.
#[cfg(test)]
#[path = "fault_support.rs"]
mod fault;
use core::marker::PhantomData;

pub use brynja_legacy_hmac::LegacyUse;

mod policy;
pub use policy::{HASH_BYTES, MAX_OUTPUT_BYTES};

/// Value-free rejection from legacy HKDF admission or processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Imported pseudorandom key is shorter than 20 bytes; output is unchanged.
    PrkLength,
    /// Extract/import destination has the wrong exact length; it is unchanged.
    DestinationLength,
    /// Expansion exceeds 5100 bytes; destination is unchanged.
    OutputLength,
    /// Legacy HMAC failed after output admission; that destination clears.
    Hmac(brynja_legacy_hmac::Error),
    /// Secret storage or a private bound invariant failed.
    SecretMemory,
}

impl From<brynja_legacy_hmac::Error> for Error {
    fn from(error: brynja_legacy_hmac::Error) -> Self {
        Self::Hmac(error)
    }
}
impl From<brynja_core::SecretMemoryError> for Error {
    fn from(_: brynja_core::SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}

// No populated scratch is returned by value or made Copy/Clone.
struct Scratch([u8; HASH_BYTES]);
impl Scratch {
    fn new() -> Self {
        Self([0; HASH_BYTES])
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        #[cfg(test)]
        let populated = self.0.iter().any(|byte| *byte != 0);
        let _ = clear_owned_region(&mut self.0);
        #[cfg(test)]
        fault::observe_scratch(populated, &self.0);
    }
}

/// Affine, local HKDF-SHA-1 PRK in clearing caller-owned storage.
///
/// No Clone, Copy, Debug, Send or Sync. Expansion borrows the PRK, permitting
/// deliberate domain-separated reuse. Shared borrows expose secrets only when
/// explicitly requested; caller copies require their own cleanup.
///
/// ```
/// use brynja_legacy_hkdf::{Sha1Prk, LegacyUse, Error};
/// let mut storage = [0; 20];
/// let prk = Sha1Prk::extract(LegacyUse::acknowledge(), None, b"ikm", &mut storage)?;
/// let mut output = [0; 42];
/// let key = prk.expand(b"historical protocol context", &mut output)?;
/// assert_eq!(key.expose().len(), 42);
/// drop(key);
/// assert_eq!(output, [0; 42]);
/// drop(prk);
/// assert_eq!(storage, [0; 20]);
/// # Ok::<(), Error>(())
/// ```
///
/// ```compile_fail
/// use brynja_legacy_hkdf::Sha1Prk;
/// let mut storage = [0; 20];
/// let _prk = Sha1Prk::extract(None, b"ikm", &mut storage);
/// ```
///
/// ```compile_fail
/// use brynja_legacy_hkdf::{Sha1Prk, LegacyUse};
/// let mut storage = [0; 20];
/// let _prk = Sha1Prk::<brynja_legacy_hmac::Md5>::extract(LegacyUse::acknowledge(), None, b"ikm", &mut storage);
/// ```
///
/// ```compile_fail
/// use brynja_legacy_hkdf::{Sha1Prk, LegacyUse};
/// let mut storage = [0; 20];
/// let prk = Sha1Prk::extract(LegacyUse::acknowledge(), None, b"ikm", &mut storage).unwrap();
/// let _copy = prk.clone();
/// ```
///
/// ```compile_fail
/// use brynja_legacy_hkdf::{Sha1Prk, LegacyUse};
/// let mut storage = [0; 20];
/// let prk = Sha1Prk::extract(LegacyUse::acknowledge(), None, b"ikm", &mut storage).unwrap();
/// println!("{prk:?}");
/// ```
///
/// ```compile_fail
/// use brynja_legacy_hkdf::{Sha1Prk, LegacyUse};
/// let mut storage = [0; 20];
/// let prk = Sha1Prk::extract(LegacyUse::acknowledge(), None, b"ikm", &mut storage).unwrap();
/// let _key = prk.expand(b"info", &mut storage);
/// ```
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_legacy_hkdf::Sha1Prk<'static>>();
/// ```
#[must_use = "keep legacy PRK ownership live until expansion is complete"]
pub struct Sha1Prk<'a> {
    region: OwnedSecretRegion<'a>,
    local: PhantomData<*mut ()>,
}

impl<'a> Sha1Prk<'a> {
    /// Extracts a full SHA-1 PRK with explicit legacy acknowledgement.
    ///
    /// `None` uses 20 zero salt bytes; `Some(&[])` explicitly supplies empty salt.
    /// Empty IKM is mathematically accepted, not an entropy guarantee. Destination
    /// must be exactly 20 bytes. Length rejection preserves it; after admission,
    /// operational errors/unwind clear it. Salt/IKM remain caller-owned.
    pub fn extract(
        acknowledgement: LegacyUse,
        salt: Option<&[u8]>,
        ikm: &[u8],
        destination: &'a mut [u8],
    ) -> Result<Self, Error> {
        if destination.len() != HASH_BYTES {
            return Err(Error::DestinationLength);
        }
        let mut initialization = SecretRegionInitialization::begin(destination)?;
        #[cfg(test)]
        fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        let zeros = [0; HASH_BYTES];
        let mut mac = Hmac::<Sha1>::new(acknowledgement, salt.unwrap_or(&zeros))?;
        #[cfg(test)]
        fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        mac.update(ikm)?;
        #[cfg(test)]
        fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        let mut block = Scratch::new();
        let tag = mac.finalize_secret(&mut block.0)?;
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

    /// Copies an already pseudorandom key of at least 20 bytes into ownership.
    ///
    /// Requires separate legacy acknowledgement even when Extract is skipped.
    /// Destination must exactly match input length. Public length errors preserve
    /// it; later failures clear it. Import does not extract entropy and does not
    /// clear the caller's input. Safe borrowing excludes overlapping buffers.
    ///
    /// ```compile_fail
    /// use brynja_legacy_hkdf::Sha1Prk;
    /// let mut storage = [0; 20];
    /// let _prk = Sha1Prk::import(&[1; 20], &mut storage);
    /// ```
    pub fn import(_: LegacyUse, input: &[u8], destination: &'a mut [u8]) -> Result<Self, Error> {
        if input.len() < HASH_BYTES {
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

    /// Explicitly borrows secret PRK bytes; application copies need separate cleanup.
    pub fn expose(&self) -> &[u8] {
        self.region.expose()
    }

    /// Expands into exactly the destination length, up to 5100 bytes.
    ///
    /// Empty output performs no HMAC. Oversized output is rejected unchanged.
    /// Once admitted, operational errors/unwind clear the whole destination;
    /// partial output is not returned. Successful output clears on owner Drop.
    /// PRK stays reusable. Borrowing prohibits overlap with PRK/info but permits
    /// disjoint slices of one allocation. Construction's acknowledgement covers
    /// subsequent SHA-1 expansions; there is no protocol negotiation or fallback.
    pub fn expand<'b>(
        &self,
        info: &[u8],
        destination: &'b mut [u8],
    ) -> Result<DerivedKey<'b>, Error> {
        let blocks = policy::expansion_blocks(destination.len()).ok_or(Error::OutputLength)?;
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
        let mut previous = Scratch::new();
        let mut block = Scratch::new();
        for counter in 1..=blocks {
            let mut mac = Hmac::<Sha1>::new(LegacyUse::acknowledge(), self.expose())?;
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            if counter != 1 {
                mac.update(&previous.0)?;
            }
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            mac.update(info)?;
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            mac.update(&[counter])?;
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            let tag = mac.finalize_secret(&mut block.0)?;
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            let take = remaining.min(HASH_BYTES);
            initialization.write(tag.expose().get(..take).ok_or(Error::SecretMemory)?)?;
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
            remaining = remaining.checked_sub(take).ok_or(Error::SecretMemory)?;
            if remaining != 0 {
                copy_secret_region(&mut previous.0, tag.expose())?;
            }
            #[cfg(test)]
            fault::checkpoint().map_err(|()| Error::SecretMemory)?;
        }
        Ok(DerivedKey {
            region: Some(initialization.finish()?),
            local: PhantomData,
        })
    }
}

/// Complete legacy-derived secret output; Drop clears its entire caller buffer.
///
/// No Copy, Clone, Debug, Send or Sync. An empty output owns no memory region.
///
/// ```compile_fail
/// fn copy<T: Copy>() {}
/// copy::<brynja_legacy_hkdf::DerivedKey<'static>>();
/// ```
///
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<brynja_legacy_hkdf::DerivedKey<'static>>();
/// ```
#[must_use = "keep clearing ownership live until the derived key is no longer needed"]
pub struct DerivedKey<'a> {
    region: Option<OwnedSecretRegion<'a>>,
    local: PhantomData<*mut ()>,
}
impl DerivedKey<'_> {
    /// Borrows secret output without transferring its clearing owner.
    pub fn expose(&self) -> &[u8] {
        self.region.as_ref().map_or(&[], OwnedSecretRegion::expose)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_fault_extract_clears_admitted_output() -> Result<(), Error> {
        fault::exercise(20, 5, |destination| {
            let _prk = Sha1Prk::extract(
                LegacyUse::acknowledge(),
                Some(b"public salt"),
                b"public ikm",
                destination,
            )?;
            Ok::<(), Error>(())
        })
    }

    #[test]
    fn hkdf_fault_expand_clears_output_and_retains_prk() -> Result<(), Error> {
        let mut storage = [0; 20];
        let prk = Sha1Prk::extract(LegacyUse::acknowledge(), None, b"public ikm", &mut storage)?;
        let mut expected = [0; 20];
        expected.copy_from_slice(prk.expose());
        fault::exercise(41, 22, |destination| {
            let result = prk.expand(b"public info", destination).map(drop);
            assert_eq!(prk.expose(), expected);
            result
        })?;
        assert_eq!(prk.expose(), expected);
        assert!(fault::saw_populated_scratch(20));
        let mut output = [0; 1];
        let _key = prk.expand(b"usable after injection", &mut output)?;
        Ok(())
    }

    #[test]
    fn hkdf_fault_import_clears_entire_region() -> Result<(), Error> {
        fault::exercise(80, 2, |destination| {
            let _prk = Sha1Prk::import(LegacyUse::acknowledge(), &[0x42; 80], destination)?;
            Ok::<(), Error>(())
        })
    }

    #[test]
    fn hkdf_fault_populated_scratch_drop_and_unwind() {
        fault::exercise_scratch(
            || {
                let mut scratch = Scratch::new();
                scratch.0.fill(0x42);
                fault::unwind_if_requested();
            },
            20,
        );
    }
}
