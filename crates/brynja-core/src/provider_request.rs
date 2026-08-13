//! Version-neutral bounded provider-request metadata.

use crate::{
    ExhaustionPhase, InstalledProvider, ProviderHandle, ProviderOperation, ResourceBudget,
    ResourceDomain, ResourceExhaustion, ResourceKind,
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
    /// A typed verification operation requested an output byte buffer.
    OutputNotPermitted(ProviderOperation),
    /// A caller-selected resource limit rejected the request.
    ResourceExhausted(ResourceExhaustion),
    /// The caller-selected work limit rejected the request.
    WorkExhausted(ResourceExhaustion),
}

/// A bounded request token tied to one installed provider and exact operation.
///
/// This non-cloneable, non-formattable value is metadata only. It authorizes no
/// other operation and cannot create an output-completion, failure, or
/// secret-destruction claim. It retains the exact installed provider that
/// authorized it and a monotonic meter initialized from that provider's frozen
/// work budget.
///
/// ```compile_fail
/// use brynja_core::ProviderRequest;
///
/// fn duplicate(request: ProviderRequest<'_, '_>) {
///     let _first = request.clone();
/// }
/// ```
///
/// Request holders cannot assert success:
///
/// ```compile_fail
/// use brynja_core::ProviderRequest;
///
/// fn forge_success(request: ProviderRequest<'_, '_>) {
///     let _ = request.complete();
/// }
/// ```
///
/// Request holders cannot manufacture provider failure receipts either:
///
/// ```compile_fail
/// use brynja_core::{ProviderFailureKind, ProviderRequest};
///
/// fn forge_failure(request: ProviderRequest<'_, '_>) {
///     let _ = request.fail(ProviderFailureKind::Unavailable);
/// }
/// ```
#[must_use = "a prepared provider request must be consumed by its exact provider boundary"]
pub struct ProviderRequest<'provider, 'data> {
    operation: ProviderOperation,
    frame: ProviderFrame<'data>,
    provider: &'provider InstalledProvider,
    remaining_work: u64,
}

impl<'provider, 'data> ProviderRequest<'provider, 'data> {
    pub(crate) const fn prepare(
        operation: ProviderOperation,
        frame: ProviderFrame<'data>,
        provider: &'provider InstalledProvider,
    ) -> Result<Self, ProviderRequestError> {
        let resources = provider.resources();
        if operation.forbids_byte_output() && frame.output_capacity() != 0 {
            return Err(ProviderRequestError::OutputNotPermitted(operation));
        }
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
        Ok(Self {
            operation,
            frame,
            provider,
            remaining_work: provider.work().limit(),
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

    /// Returns whether this request belongs to the exact opaque provider handle.
    ///
    /// No native identifier or address is exposed.
    #[must_use]
    pub fn is_bound_to(&self, handle: &ProviderHandle<'_>) -> bool {
        handle.references(self.provider)
    }

    /// Returns the frozen caller-selected resource limits.
    #[must_use]
    pub const fn resources(&self) -> ResourceBudget {
        self.provider.resources()
    }

    /// Returns the remaining provider-owned work allowance.
    ///
    /// This is accounting state, never proof that work occurred or completed.
    #[must_use]
    pub const fn remaining_work(&self) -> u64 {
        self.remaining_work
    }

    pub(crate) const fn charge_work(&mut self, units: u64) -> Result<(), ProviderRequestError> {
        match self.remaining_work.checked_sub(units) {
            Some(remaining) => {
                self.remaining_work = remaining;
                Ok(())
            }
            None => Err(ProviderRequestError::WorkExhausted(
                ResourceExhaustion::new(ResourceKind::Work, ExhaustionPhase::Provider),
            )),
        }
    }

    pub(crate) const fn provider(&self) -> &'provider InstalledProvider {
        self.provider
    }
}
