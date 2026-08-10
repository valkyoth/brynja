//! Immutable exact-operation provider capability snapshots.

use crate::ProviderOperation;

/// A closed capability-set construction failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderCapabilityError {
    /// The same exact operation was declared more than once.
    Duplicate(ProviderOperation),
    /// No operation was declared.
    Empty,
}

/// A named single-assignment capability builder.
///
/// Each operation is independent. Declaring `AeadSeal`, for example, never
/// implies `AeadOpen`.
#[must_use = "the capability builder must be frozen"]
pub struct ProviderCapabilitiesBuilder {
    bits: u32,
}

impl ProviderCapabilitiesBuilder {
    pub(crate) const EMPTY: Self = Self { bits: 0 };

    /// Declares one exact operation.
    pub const fn enable(
        mut self,
        operation: ProviderOperation,
    ) -> Result<Self, ProviderCapabilityError> {
        let mask = operation.mask();
        if self.bits & mask != 0 {
            Err(ProviderCapabilityError::Duplicate(operation))
        } else {
            self.bits |= mask;
            Ok(self)
        }
    }

    /// Freezes the declared set, rejecting an empty provider.
    pub const fn freeze(self) -> Result<ProviderCapabilities, ProviderCapabilityError> {
        if self.bits == 0 {
            Err(ProviderCapabilityError::Empty)
        } else {
            Ok(ProviderCapabilities { bits: self.bits })
        }
    }
}

/// A frozen exact-operation capability snapshot.
///
/// The snapshot has no mutable setters and contains no algorithm choice,
/// protocol version, backend identity, or fallback order.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ProviderCapabilities {
    bits: u32,
}

impl ProviderCapabilities {
    /// Starts an empty named capability builder.
    pub const fn builder() -> ProviderCapabilitiesBuilder {
        ProviderCapabilitiesBuilder::EMPTY
    }

    /// Reports whether the exact operation was declared.
    #[must_use]
    pub const fn contains(self, operation: ProviderOperation) -> bool {
        self.bits & operation.mask() != 0
    }

    /// Returns the number of exact operations in the snapshot.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.bits.count_ones()
    }
}
