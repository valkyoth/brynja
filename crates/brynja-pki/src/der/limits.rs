//! Named immutable DER resource limits.

/// One required DER limit dimension.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DerLimit {
    /// Complete input bytes.
    InputBytes,
    /// Constructed nesting depth.
    Depth,
    /// Total values.
    Nodes,
    /// Direct children per constructed value and top-level values.
    Children,
    /// Identifier octets per value.
    IdentifierOctets,
    /// Length octets per value.
    LengthOctets,
    /// Contents octets per value.
    ValueBytes,
    /// Deterministic total parser work units.
    Work,
}

/// A closed failure while building [`DerLimits`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DerLimitBuildError {
    /// One named limit was assigned twice.
    Duplicate(DerLimit),
    /// One required named limit was not assigned.
    Incomplete(DerLimit),
}

/// Immutable caller-selected bounds for one DER traversal.
///
/// Positional construction, defaults, mutation, and diagnostic formatting are
/// intentionally unavailable.
///
/// ```compile_fail
/// let _ = brynja_pki::DerLimits::new(1, 2, 3, 4, 5, 6, 7, 8);
/// ```
///
/// ```compile_fail
/// let _: brynja_pki::DerLimits = Default::default();
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct DerLimits {
    input_bytes: usize,
    depth: usize,
    nodes: usize,
    children: usize,
    identifier_octets: usize,
    length_octets: usize,
    value_bytes: usize,
    work: usize,
}

/// Named single-assignment builder for [`DerLimits`].
#[must_use = "every DER limit must be assigned and the builder completed"]
pub struct DerLimitsBuilder {
    values: [Option<usize>; 8],
}

impl DerLimits {
    /// Starts an empty named limit builder.
    pub const fn builder() -> DerLimitsBuilder {
        DerLimitsBuilder { values: [None; 8] }
    }

    pub(crate) const fn input_bytes(self) -> usize {
        self.input_bytes
    }
    pub(crate) const fn depth(self) -> usize {
        self.depth
    }
    pub(crate) const fn nodes(self) -> usize {
        self.nodes
    }
    pub(crate) const fn children(self) -> usize {
        self.children
    }
    pub(crate) const fn identifier_octets(self) -> usize {
        self.identifier_octets
    }
    pub(crate) const fn length_octets(self) -> usize {
        self.length_octets
    }
    pub(crate) const fn value_bytes(self) -> usize {
        self.value_bytes
    }
    pub(crate) const fn work(self) -> usize {
        self.work
    }
}

impl DerLimitsBuilder {
    fn set(
        mut self,
        index: usize,
        limit: DerLimit,
        value: usize,
    ) -> Result<Self, DerLimitBuildError> {
        match self.values.get(index) {
            Some(None) => {}
            _ => return Err(DerLimitBuildError::Duplicate(limit)),
        }
        match self.values.get_mut(index) {
            Some(slot) => *slot = Some(value),
            None => return Err(DerLimitBuildError::Duplicate(limit)),
        }
        Ok(self)
    }

    /// Sets the complete input-byte ceiling.
    pub fn input_bytes(self, value: usize) -> Result<Self, DerLimitBuildError> {
        self.set(0, DerLimit::InputBytes, value)
    }
    /// Sets the constructed-depth ceiling.
    pub fn depth(self, value: usize) -> Result<Self, DerLimitBuildError> {
        self.set(1, DerLimit::Depth, value)
    }
    /// Sets the total-node ceiling.
    pub fn nodes(self, value: usize) -> Result<Self, DerLimitBuildError> {
        self.set(2, DerLimit::Nodes, value)
    }
    /// Sets the direct-child ceiling.
    pub fn children(self, value: usize) -> Result<Self, DerLimitBuildError> {
        self.set(3, DerLimit::Children, value)
    }
    /// Sets the identifier-octet ceiling.
    pub fn identifier_octets(self, value: usize) -> Result<Self, DerLimitBuildError> {
        self.set(4, DerLimit::IdentifierOctets, value)
    }
    /// Sets the length-octet ceiling.
    pub fn length_octets(self, value: usize) -> Result<Self, DerLimitBuildError> {
        self.set(5, DerLimit::LengthOctets, value)
    }
    /// Sets the per-value contents ceiling.
    pub fn value_bytes(self, value: usize) -> Result<Self, DerLimitBuildError> {
        self.set(6, DerLimit::ValueBytes, value)
    }
    /// Sets the total deterministic-work ceiling.
    pub fn work(self, value: usize) -> Result<Self, DerLimitBuildError> {
        self.set(7, DerLimit::Work, value)
    }

    /// Completes the limits only after every dimension was named.
    pub fn build(self) -> Result<DerLimits, DerLimitBuildError> {
        let input_bytes = value(self.values, 0, DerLimit::InputBytes)?;
        let depth = value(self.values, 1, DerLimit::Depth)?;
        let nodes = value(self.values, 2, DerLimit::Nodes)?;
        let children = value(self.values, 3, DerLimit::Children)?;
        let identifier_octets = value(self.values, 4, DerLimit::IdentifierOctets)?;
        let length_octets = value(self.values, 5, DerLimit::LengthOctets)?;
        let value_bytes = value(self.values, 6, DerLimit::ValueBytes)?;
        let work = value(self.values, 7, DerLimit::Work)?;
        Ok(DerLimits {
            input_bytes,
            depth,
            nodes,
            children,
            identifier_octets,
            length_octets,
            value_bytes,
            work,
        })
    }
}

fn value(
    values: [Option<usize>; 8],
    index: usize,
    limit: DerLimit,
) -> Result<usize, DerLimitBuildError> {
    match values.get(index) {
        Some(Some(value)) => Ok(*value),
        _ => Err(DerLimitBuildError::Incomplete(limit)),
    }
}
