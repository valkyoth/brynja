//! Immutable caller-selected resource and work budgets.

use crate::{ExhaustionPhase, ResourceExhaustion, ResourceKind};

/// A resource dimension governed by [`ResourceBudget`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ResourceDomain {
    /// Bytes accepted as input.
    InputBytes,
    /// Bytes produced as output.
    OutputBytes,
    /// Bytes required from caller-owned workspace.
    WorkspaceBytes,
    /// Retained protocol-state items.
    StateItems,
    /// Items retained in a queue.
    QueueItems,
    /// Certificate and trust-path bytes.
    CertificateBytes,
    /// Provider operations admitted for one bounded action.
    ProviderOperations,
}

impl ResourceDomain {
    /// Returns the corresponding limit-value-free exhaustion domain.
    pub const fn resource_kind(self) -> ResourceKind {
        match self {
            Self::InputBytes => ResourceKind::Input,
            Self::OutputBytes => ResourceKind::Output,
            Self::WorkspaceBytes => ResourceKind::Workspace,
            Self::StateItems => ResourceKind::State,
            Self::QueueItems => ResourceKind::Queue,
            Self::CertificateBytes => ResourceKind::Certificate,
            Self::ProviderOperations => ResourceKind::Provider,
        }
    }
}

/// Immutable maximums for caller-owned resource domains.
///
/// This value is policy, not a mutable accounting state. A check returns a
/// typed exhaustion result and never changes the budget or requested amount.
/// Numeric limits remain available only through explicit accessors and never
/// enter the returned error.
///
/// ```compile_fail
/// let limits = brynja_core::ResourceBudget::new(1, 1, 1, 1, 1, 1, 1);
/// println!("{limits:?}");
/// ```
///
/// ```compile_fail
/// let _: brynja_core::ResourceBudget = Default::default();
/// ```
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ResourceBudget {
    input_bytes: usize,
    output_bytes: usize,
    workspace_bytes: usize,
    state_items: usize,
    queue_items: usize,
    certificate_bytes: usize,
    provider_operations: usize,
}

impl ResourceBudget {
    /// Constructs an immutable resource budget without hidden defaults.
    #[must_use]
    pub const fn new(
        input_bytes: usize,
        output_bytes: usize,
        workspace_bytes: usize,
        state_items: usize,
        queue_items: usize,
        certificate_bytes: usize,
        provider_operations: usize,
    ) -> Self {
        Self {
            input_bytes,
            output_bytes,
            workspace_bytes,
            state_items,
            queue_items,
            certificate_bytes,
            provider_operations,
        }
    }

    /// Returns the configured maximum for one resource domain.
    pub const fn limit(self, domain: ResourceDomain) -> usize {
        match domain {
            ResourceDomain::InputBytes => self.input_bytes,
            ResourceDomain::OutputBytes => self.output_bytes,
            ResourceDomain::WorkspaceBytes => self.workspace_bytes,
            ResourceDomain::StateItems => self.state_items,
            ResourceDomain::QueueItems => self.queue_items,
            ResourceDomain::CertificateBytes => self.certificate_bytes,
            ResourceDomain::ProviderOperations => self.provider_operations,
        }
    }

    /// Checks a measured amount without mutating accounting state.
    pub const fn check(
        self,
        domain: ResourceDomain,
        amount: usize,
        phase: ExhaustionPhase,
    ) -> Result<(), ResourceExhaustion> {
        if amount <= self.limit(domain) {
            Ok(())
        } else {
            Err(ResourceExhaustion::new(domain.resource_kind(), phase))
        }
    }
}

/// An immutable maximum number of work units for one bounded action.
///
/// A work unit receives its exact meaning from the operation that owns the
/// budget. The budget deliberately does not provide a universal default.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct WorkBudget {
    units: u64,
}

impl WorkBudget {
    /// Constructs an explicit work-unit limit.
    #[must_use]
    pub const fn new(units: u64) -> Self {
        Self { units }
    }

    /// Returns the configured work-unit limit.
    pub const fn limit(self) -> u64 {
        self.units
    }

    /// Checks measured work without changing the budget.
    pub const fn check(self, units: u64, phase: ExhaustionPhase) -> Result<(), ResourceExhaustion> {
        if units <= self.units {
            Ok(())
        } else {
            Err(ResourceExhaustion::new(ResourceKind::Work, phase))
        }
    }
}
