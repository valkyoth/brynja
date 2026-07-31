//! Typed resource-exhaustion failures without numeric policy.

/// The resource domain that reached a caller-owned bound.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ResourceKind {
    /// Input bytes or fragments.
    Input,
    /// Output capacity.
    Output,
    /// Caller-provided workspace.
    Workspace,
    /// Retained protocol state.
    State,
    /// A bounded queue.
    Queue,
    /// A certificate or trust-path bound.
    Certificate,
    /// A provider-owned resource.
    Provider,
    /// A bounded work allowance.
    Work,
}

/// The operation phase in which exhaustion occurred.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ExhaustionPhase {
    /// Reading or decoding input.
    Input,
    /// Building or encoding output.
    Output,
    /// Advancing a handshake.
    Handshake,
    /// Processing protected records.
    Record,
    /// Validating credentials.
    Validation,
    /// Waiting for or invoking a provider.
    Provider,
}

/// A non-secret, limit-value-free resource exhaustion result.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ResourceExhaustion {
    resource: ResourceKind,
    phase: ExhaustionPhase,
}

impl ResourceExhaustion {
    /// Constructs a typed exhaustion result.
    #[must_use]
    pub const fn new(resource: ResourceKind, phase: ExhaustionPhase) -> Self {
        Self { resource, phase }
    }

    /// Returns the exhausted resource class.
    #[must_use]
    pub const fn resource(self) -> ResourceKind {
        self.resource
    }

    /// Returns the bounded operation phase.
    #[must_use]
    pub const fn phase(self) -> ExhaustionPhase {
        self.phase
    }
}
