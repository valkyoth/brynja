//! Version-neutral bounded provider-request metadata.

use crate::{
    ExhaustionPhase, ProviderFailureKind, ProviderOperation, ResourceBudget, ResourceDomain,
    ResourceExhaustion, WorkBudget,
};

/// A borrowed version-neutral provider frame.
///
/// The two byte regions are immutable. Their interpretation belongs to the
/// exact authorized operation; this type carries no TLS, DTLS, QUIC, cipher,
/// algorithm, key, nonce, or provider-native identifier.
pub struct ProviderFrame<'data> {
    primary: &'data [u8],
    context: &'data [u8],
    output_capacity: usize,
}

impl<'data> ProviderFrame<'data> {
    /// Describes immutable primary and contextual input plus required output
    /// capacity. Construction performs no provider or platform effect.
    #[must_use]
    pub const fn new(primary: &'data [u8], context: &'data [u8], output_capacity: usize) -> Self {
        Self {
            primary,
            context,
            output_capacity,
        }
    }

    /// Returns the primary input bytes.
    #[must_use]
    pub const fn primary(&self) -> &'data [u8] {
        self.primary
    }

    /// Returns the operation-specific contextual bytes.
    #[must_use]
    pub const fn context(&self) -> &'data [u8] {
        self.context
    }

    /// Returns the required caller-owned output capacity.
    #[must_use]
    pub const fn output_capacity(&self) -> usize {
        self.output_capacity
    }

    pub(crate) const fn input_bytes(&self) -> Option<usize> {
        self.primary.len().checked_add(self.context.len())
    }
}

/// A closed request-preparation failure.
#[non_exhaustive]
pub enum ProviderRequestError {
    /// Aggregate input length overflowed `usize`.
    InputLengthOverflow,
    /// A caller-selected resource limit rejected the request.
    ResourceExhausted(ResourceExhaustion),
    /// The caller-selected work limit rejected the request.
    WorkExhausted(ResourceExhaustion),
}

/// A bounded request token tied to one installed provider and exact operation.
///
/// This non-cloneable, non-formattable value is metadata only. It authorizes no
/// other operation and contains no output-completion or secret-destruction
/// claim.
///
/// ```compile_fail
/// use brynja_core::ProviderRequest;
///
/// fn duplicate(request: ProviderRequest<'_, '_>) {
///     let _first = request.clone();
/// }
/// ```
#[must_use = "a prepared provider request must be consumed by its exact provider boundary"]
pub struct ProviderRequest<'provider, 'data> {
    operation: ProviderOperation,
    frame: ProviderFrame<'data>,
    work_units: u64,
    resources: &'provider ResourceBudget,
}

impl<'provider, 'data> ProviderRequest<'provider, 'data> {
    pub(crate) const fn prepare(
        operation: ProviderOperation,
        frame: ProviderFrame<'data>,
        work_units: u64,
        resources: &'provider ResourceBudget,
        work: &WorkBudget,
    ) -> Result<Self, ProviderRequestError> {
        let input_bytes = match frame.input_bytes() {
            Some(value) => value,
            None => return Err(ProviderRequestError::InputLengthOverflow),
        };
        if let Err(error) = resources.check(
            ResourceDomain::InputBytes,
            input_bytes,
            ExhaustionPhase::Provider,
        ) {
            return Err(ProviderRequestError::ResourceExhausted(error));
        }
        if let Err(error) = resources.check(
            ResourceDomain::OutputBytes,
            frame.output_capacity(),
            ExhaustionPhase::Provider,
        ) {
            return Err(ProviderRequestError::ResourceExhausted(error));
        }
        if let Err(error) = resources.check(
            ResourceDomain::ProviderOperations,
            1,
            ExhaustionPhase::Provider,
        ) {
            return Err(ProviderRequestError::ResourceExhausted(error));
        }
        if let Err(error) = work.check(work_units, ExhaustionPhase::Provider) {
            return Err(ProviderRequestError::WorkExhausted(error));
        }
        Ok(Self {
            operation,
            frame,
            work_units,
            resources,
        })
    }

    /// Returns the only operation authorized by this request.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        self.operation
    }

    /// Returns the immutable version-neutral frame.
    #[must_use]
    pub const fn frame(&self) -> &ProviderFrame<'data> {
        &self.frame
    }

    /// Returns the admitted public work-unit claim.
    #[must_use]
    pub const fn work_units(&self) -> u64 {
        self.work_units
    }

    /// Returns the frozen caller-selected resource limits.
    #[must_use]
    pub const fn resources(&self) -> &ResourceBudget {
        self.resources
    }

    /// Consumes the exact request into a synchronous completion token.
    ///
    /// Calling this is a provider security assertion that the complete
    /// operation-specific effect and output commit succeeded.
    pub const fn complete(self) -> ProviderRequestOutcome {
        ProviderRequestOutcome::Complete(ProviderRequestComplete {
            operation: self.operation,
        })
    }

    /// Consumes the exact request into a closed failure bound to its operation.
    pub const fn fail(self, kind: ProviderFailureKind) -> ProviderRequestOutcome {
        ProviderRequestOutcome::Failed(ProviderRequestFailure {
            operation: self.operation,
            kind,
        })
    }
}

/// A non-forgeable synchronous completion bound to one exact operation.
pub struct ProviderRequestComplete {
    operation: ProviderOperation,
}

impl ProviderRequestComplete {
    /// Returns the exact operation that completed.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        self.operation
    }
}

/// A non-forgeable synchronous failure bound to one exact operation.
pub struct ProviderRequestFailure {
    operation: ProviderOperation,
    kind: ProviderFailureKind,
}

impl ProviderRequestFailure {
    /// Returns the exact operation that failed.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        self.operation
    }

    /// Returns the closed, secret-free failure category.
    #[must_use]
    pub const fn kind(&self) -> ProviderFailureKind {
        self.kind
    }
}

/// Mandatory terminal result of an exact synchronous provider request.
///
/// Pending-operation lifecycle is intentionally not represented as success;
/// it is owned by a later milestone.
#[must_use = "provider completion or failure must govern the engine transition"]
pub enum ProviderRequestOutcome {
    /// The exact request completed synchronously and committed its output.
    Complete(ProviderRequestComplete),
    /// The exact request failed with a closed, secret-free category.
    Failed(ProviderRequestFailure),
}
