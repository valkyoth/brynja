//! Exact, possibly empty, FIPS-aware service-classification sets.
//!
//! Frozen sets cannot be fabricated from raw bits:
//!
//! ```compile_fail
//! use brynja_core::FipsServiceSet;
//! let _ = FipsServiceSet { bits: u32::MAX };
//! ```

use crate::ProviderOperation;

/// A closed service-set construction failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FipsServiceSetError {
    /// The same exact operation was declared more than once.
    Duplicate(ProviderOperation),
}

/// Single-assignment builder for one FIPS-aware service set.
///
/// Unlike an installed provider's capability set, a classification set may be
/// empty. A module can intentionally expose only approved services or only
/// non-approved services while still classifying its complete provider surface.
#[must_use = "the FIPS-aware service set must be frozen"]
pub struct FipsServiceSetBuilder {
    bits: u32,
}

impl FipsServiceSetBuilder {
    pub(crate) const EMPTY: Self = Self { bits: 0 };

    /// Declares one exact operation without implying its opposite direction.
    pub const fn enable(
        mut self,
        operation: ProviderOperation,
    ) -> Result<Self, FipsServiceSetError> {
        let mask = operation.mask();
        if self.bits & mask != 0 {
            Err(FipsServiceSetError::Duplicate(operation))
        } else {
            self.bits |= mask;
            Ok(self)
        }
    }

    /// Freezes this set, including an intentionally empty set.
    #[must_use]
    pub const fn freeze(self) -> FipsServiceSet {
        FipsServiceSet { bits: self.bits }
    }
}

/// Frozen exact-operation classification set.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FipsServiceSet {
    bits: u32,
}

impl FipsServiceSet {
    /// Starts an empty, named builder.
    pub const fn builder() -> FipsServiceSetBuilder {
        FipsServiceSetBuilder::EMPTY
    }

    /// Returns an intentionally empty frozen set.
    #[must_use]
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Reports whether the exact operation was declared.
    #[must_use]
    pub const fn contains(self, operation: ProviderOperation) -> bool {
        self.bits & operation.mask() != 0
    }

    /// Returns the number of exact operations in the set.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.bits.count_ones()
    }

    /// Reports whether this classification set is intentionally empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }
}
