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

/// A named, fail-closed builder for [`ResourceBudget`].
///
/// Each limit has a distinct setter so call sites cannot silently transpose
/// positional arguments. [`Self::build`] returns `None` until every domain has
/// an explicit limit.
#[must_use = "the builder must be completed with ResourceBudgetBuilder::build"]
pub struct ResourceBudgetBuilder {
    input_bytes: Option<usize>,
    output_bytes: Option<usize>,
    workspace_bytes: Option<usize>,
    state_items: Option<usize>,
    queue_items: Option<usize>,
    certificate_bytes: Option<usize>,
    provider_operations: Option<usize>,
}

impl ResourceBudgetBuilder {
    const EMPTY: Self = Self {
        input_bytes: None,
        output_bytes: None,
        workspace_bytes: None,
        state_items: None,
        queue_items: None,
        certificate_bytes: None,
        provider_operations: None,
    };

    /// Sets the input-byte limit.
    pub const fn input_bytes(mut self, limit: usize) -> Self {
        self.input_bytes = Some(limit);
        self
    }

    /// Sets the output-byte limit.
    pub const fn output_bytes(mut self, limit: usize) -> Self {
        self.output_bytes = Some(limit);
        self
    }

    /// Sets the caller-owned workspace-byte limit.
    pub const fn workspace_bytes(mut self, limit: usize) -> Self {
        self.workspace_bytes = Some(limit);
        self
    }

    /// Sets the retained-state-item limit.
    pub const fn state_items(mut self, limit: usize) -> Self {
        self.state_items = Some(limit);
        self
    }

    /// Sets the queued-item limit.
    pub const fn queue_items(mut self, limit: usize) -> Self {
        self.queue_items = Some(limit);
        self
    }

    /// Sets the certificate-byte limit.
    pub const fn certificate_bytes(mut self, limit: usize) -> Self {
        self.certificate_bytes = Some(limit);
        self
    }

    /// Sets the provider-operation limit.
    pub const fn provider_operations(mut self, limit: usize) -> Self {
        self.provider_operations = Some(limit);
        self
    }

    /// Builds a budget only when every resource domain was named explicitly.
    pub const fn build(self) -> Option<ResourceBudget> {
        match (
            self.input_bytes,
            self.output_bytes,
            self.workspace_bytes,
            self.state_items,
            self.queue_items,
            self.certificate_bytes,
            self.provider_operations,
        ) {
            (
                Some(input_bytes),
                Some(output_bytes),
                Some(workspace_bytes),
                Some(state_items),
                Some(queue_items),
                Some(certificate_bytes),
                Some(provider_operations),
            ) => Some(ResourceBudget {
                input_bytes,
                output_bytes,
                workspace_bytes,
                state_items,
                queue_items,
                certificate_bytes,
                provider_operations,
            }),
            _ => None,
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
/// let budget = brynja_core::ResourceBudget::builder()
///     .input_bytes(1)
///     .output_bytes(1)
///     .workspace_bytes(1)
///     .state_items(1)
///     .queue_items(1)
///     .certificate_bytes(1)
///     .provider_operations(1)
///     .build();
/// if let Some(budget) = budget {
///     println!("{budget:?}");
/// }
/// ```
///
/// ```compile_fail
/// let _: brynja_core::ResourceBudget = Default::default();
/// ```
///
/// Positional construction is intentionally unavailable:
///
/// ```compile_fail
/// let _ = brynja_core::ResourceBudget::new(1, 2, 3, 4, 5, 6, 7);
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
    /// Starts named construction without hidden defaults.
    pub const fn builder() -> ResourceBudgetBuilder {
        ResourceBudgetBuilder::EMPTY
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
