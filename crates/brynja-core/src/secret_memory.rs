//! Affine ownership for one caller-owned secret-memory region.
//!
//! The safe state machine exclusively borrows one complete region. It clears
//! pre-existing bytes before initialization, permits only sequential writes,
//! admits readable ownership only after exact complete initialization, and
//! clears the complete region on every explicit or `Drop` exit.
//!
//! ```compile_fail
//! let mut bytes = [0_u8; 4];
//! let initialization =
//!     brynja_core::SecretRegionInitialization::begin(&mut bytes).unwrap();
//! let _copy = initialization.clone();
//! ```
//!
//! ```compile_fail
//! let mut bytes = [0_u8; 4];
//! let initialization =
//!     brynja_core::SecretRegionInitialization::begin(&mut bytes).unwrap();
//! println!("{initialization:?}");
//! ```

use crate::secret_memory_volatile::zeroize_region_volatile;

/// A closed, value-free owned-secret-memory failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SecretMemoryError {
    /// A zero-byte region cannot own a secret.
    EmptyRegion,
    /// Computing the next initialization boundary overflowed `usize`.
    LengthOverflow,
    /// The complete requested initialization write did not fit.
    InsufficientCapacity,
    /// Readable ownership was requested before exact complete initialization.
    IncompleteInitialization,
}

/// Non-copyable evidence that one complete borrowed region was cleared.
///
/// This token proves that Brynja's volatile-store primitive returned for the
/// region. It does not prove cache eviction, DMA completion, register erasure,
/// removal of copies, crash-dump exclusion, or physical-memory destruction.
#[must_use = "clearing completion must govern the next secret state"]
pub struct OwnedRegionClearComplete {
    _private: (),
}

/// Clears every byte in one non-empty, exclusively borrowed Rust allocation.
///
/// The volatile stores are preserved against compiler elision. This function
/// does not flush CPU or device caches, synchronize DMA, erase registers or
/// copies, remove crash dumps, or destroy physical memory. Those are separate
/// platform duties represented by [`crate::SecretDestructor`].
pub fn clear_owned_region(
    region: &mut [u8],
) -> Result<OwnedRegionClearComplete, SecretMemoryError> {
    if region.is_empty() {
        return Err(SecretMemoryError::EmptyRegion);
    }
    zeroize_region_volatile(region);
    Ok(OwnedRegionClearComplete { _private: () })
}

/// Write-only initialization of one caller-owned secret region.
///
/// Construction immediately clears the complete pre-existing region. Writes
/// are sequential and failure-atomic. Read access does not exist until
/// [`finish`](Self::finish) confirms exact complete initialization. Dropping an
/// incomplete value clears the complete region.
#[must_use = "secret initialization must finish or clear its complete region"]
pub struct SecretRegionInitialization<'region> {
    region: Option<&'region mut [u8]>,
    initialized: usize,
}

impl<'region> SecretRegionInitialization<'region> {
    /// Clears and exclusively borrows one non-empty caller-owned region.
    pub fn begin(region: &'region mut [u8]) -> Result<Self, SecretMemoryError> {
        let _completion = clear_owned_region(region)?;
        Ok(Self {
            region: Some(region),
            initialized: 0,
        })
    }

    /// Writes one complete sequential initialization fragment.
    ///
    /// Overflow or insufficient capacity changes neither bytes nor state.
    pub fn write(&mut self, input: &[u8]) -> Result<(), SecretMemoryError> {
        let region_len = match self.region.as_deref() {
            Some(region) => region.len(),
            None => return Err(SecretMemoryError::IncompleteInitialization),
        };
        let end = checked_write_end(self.initialized, input.len(), region_len)?;
        let destination = match self
            .region
            .as_deref_mut()
            .and_then(|region| region.get_mut(self.initialized..end))
        {
            Some(destination) => destination,
            None => return Err(SecretMemoryError::InsufficientCapacity),
        };
        for (output, byte) in destination.iter_mut().zip(input.iter()) {
            *output = *byte;
        }
        self.initialized = end;
        Ok(())
    }

    /// Admits read-only secret ownership after exact complete initialization.
    ///
    /// An incomplete call returns a value-free error and `Drop` clears the
    /// complete region before the caller can regain access.
    pub fn finish(mut self) -> Result<OwnedSecretRegion<'region>, SecretMemoryError> {
        let complete = match self.region.as_deref() {
            Some(region) => self.initialized == region.len(),
            None => false,
        };
        if !complete {
            return Err(SecretMemoryError::IncompleteInitialization);
        }
        match self.region.take() {
            Some(region) => Ok(OwnedSecretRegion {
                region: Some(region),
            }),
            None => Err(SecretMemoryError::IncompleteInitialization),
        }
    }
}

impl Drop for SecretRegionInitialization<'_> {
    fn drop(&mut self) {
        if let Some(region) = self.region.as_deref_mut() {
            zeroize_region_volatile(region);
        }
    }
}

/// Readable affine ownership of one completely initialized secret region.
///
/// The owner is neither cloneable, copyable, formattable, nor serializable.
/// It exposes only a shared byte borrow. Explicit clear and `Drop` overwrite
/// the complete region through the isolated volatile-store primitive.
///
/// ```compile_fail
/// let mut bytes = [0_u8; 1];
/// let mut initialization =
///     brynja_core::SecretRegionInitialization::begin(&mut bytes).unwrap();
/// initialization.write(&[7]).unwrap();
/// let owner = initialization.finish().unwrap();
/// let _copy = owner.clone();
/// ```
///
/// ```compile_fail
/// let mut bytes = [0_u8; 1];
/// let mut initialization =
///     brynja_core::SecretRegionInitialization::begin(&mut bytes).unwrap();
/// initialization.write(&[7]).unwrap();
/// let owner = initialization.finish().unwrap();
/// println!("{owner:?}");
/// ```
#[must_use = "owned secret memory must remain live or be explicitly cleared"]
pub struct OwnedSecretRegion<'region> {
    region: Option<&'region mut [u8]>,
}

impl OwnedSecretRegion<'_> {
    /// Borrows the completely initialized secret bytes.
    ///
    /// Any caller-created register value or copy is outside this owner's
    /// clearing guarantee and must have its own destruction policy.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.region.as_deref().unwrap_or_default()
    }

    /// Immediately clears the complete region and consumes readable ownership.
    pub fn clear(mut self) -> OwnedRegionClearComplete {
        if let Some(region) = self.region.take() {
            zeroize_region_volatile(region);
        }
        OwnedRegionClearComplete { _private: () }
    }
}

impl Drop for OwnedSecretRegion<'_> {
    fn drop(&mut self) {
        if let Some(region) = self.region.as_deref_mut() {
            zeroize_region_volatile(region);
        }
    }
}

fn checked_write_end(
    initialized: usize,
    input_len: usize,
    region_len: usize,
) -> Result<usize, SecretMemoryError> {
    let end = match initialized.checked_add(input_len) {
        Some(end) => end,
        None => return Err(SecretMemoryError::LengthOverflow),
    };
    if end > region_len {
        Err(SecretMemoryError::InsufficientCapacity)
    } else {
        Ok(end)
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretMemoryError, checked_write_end};

    #[test]
    fn checked_boundaries_reject_overflow_and_capacity() {
        assert_eq!(checked_write_end(2, 2, 4), Ok(4));
        assert_eq!(
            checked_write_end(3, 2, 4),
            Err(SecretMemoryError::InsufficientCapacity)
        );
        assert_eq!(
            checked_write_end(usize::MAX, 1, usize::MAX),
            Err(SecretMemoryError::LengthOverflow)
        );
    }
}
