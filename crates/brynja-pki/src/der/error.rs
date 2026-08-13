//! Closed DER framing failures.

/// A payload-free reason that bounded DER framing failed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DerError {
    /// The caller supplied an unusable limit or stack capacity.
    InvalidLimits,
    /// The complete input exceeds its caller-selected byte ceiling.
    InputLimit,
    /// An identifier, length, or value ends before its declared boundary.
    Truncated,
    /// An identifier uses more octets than the caller permits.
    IdentifierOctetsLimit,
    /// A high tag number has a forbidden leading zero group or low-tag value.
    NonMinimalTag,
    /// A tag number cannot be represented without overflow.
    TagOverflow,
    /// An end-of-contents identifier appeared in definite-length DER.
    EndOfContents,
    /// DER's forbidden indefinite-length form appeared.
    IndefiniteLength,
    /// A long-form length is not the shortest possible representation.
    NonMinimalLength,
    /// A length uses more octets than the caller or platform permits.
    LengthOctetsLimit,
    /// A decoded length or boundary cannot be represented.
    LengthOverflow,
    /// A value exceeds its caller-selected per-value byte ceiling.
    ValueLimit,
    /// A child encoding crosses its enclosing constructed boundary.
    BoundaryViolation,
    /// Constructed nesting exceeds the selected depth ceiling.
    DepthLimit,
    /// Parsed values exceed the selected node ceiling.
    NodeLimit,
    /// Direct children exceed the selected per-container ceiling.
    ChildLimit,
    /// Deterministic parser work exceeds the selected ceiling.
    WorkLimit,
}
