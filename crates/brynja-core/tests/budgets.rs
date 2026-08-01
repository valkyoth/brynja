//! Construction and enforcement tests for the v0.6 budget domains.

use core::mem::size_of;

use brynja_core::{
    BudgetBuildError, ExhaustionPhase, ResourceBudget, ResourceBudgetBuilder, ResourceDomain,
    ResourceKind, WorkBudget,
};

const LIMITS: [(ResourceDomain, usize); 7] = [
    (ResourceDomain::InputBytes, 1),
    (ResourceDomain::OutputBytes, 2),
    (ResourceDomain::WorkspaceBytes, 3),
    (ResourceDomain::StateItems, 4),
    (ResourceDomain::QueueItems, 5),
    (ResourceDomain::CertificateBytes, 6),
    (ResourceDomain::ProviderOperations, 7),
];

fn assign(
    builder: ResourceBudgetBuilder,
    domain: ResourceDomain,
    limit: usize,
) -> Result<ResourceBudgetBuilder, BudgetBuildError> {
    match domain {
        ResourceDomain::InputBytes => builder.input_bytes(limit),
        ResourceDomain::OutputBytes => builder.output_bytes(limit),
        ResourceDomain::WorkspaceBytes => builder.workspace_bytes(limit),
        ResourceDomain::StateItems => builder.state_items(limit),
        ResourceDomain::QueueItems => builder.queue_items(limit),
        ResourceDomain::CertificateBytes => builder.certificate_bytes(limit),
        ResourceDomain::ProviderOperations => builder.provider_operations(limit),
        _ => Err(BudgetBuildError::Incomplete(domain)),
    }
}

fn complete_builder() -> Result<ResourceBudgetBuilder, BudgetBuildError> {
    let mut builder = ResourceBudget::builder();
    for (domain, limit) in LIMITS {
        builder = assign(builder, domain, limit)?;
    }
    Ok(builder)
}

fn builder_without(skipped: ResourceDomain) -> Result<ResourceBudgetBuilder, BudgetBuildError> {
    let mut builder = ResourceBudget::builder();
    for (domain, limit) in LIMITS {
        if domain != skipped {
            builder = assign(builder, domain, limit)?;
        }
    }
    Ok(builder)
}

#[test]
fn every_resource_budget_dimension_is_exact_and_immutable() {
    let builder = complete_builder();
    assert!(builder.is_ok());
    let Ok(builder) = builder else {
        return;
    };
    let budget = builder.build();
    assert!(budget.is_ok());
    let Ok(budget) = budget else {
        return;
    };
    let cases = [
        (ResourceDomain::InputBytes, ResourceKind::Input, 1),
        (ResourceDomain::OutputBytes, ResourceKind::Output, 2),
        (ResourceDomain::WorkspaceBytes, ResourceKind::Workspace, 3),
        (ResourceDomain::StateItems, ResourceKind::State, 4),
        (ResourceDomain::QueueItems, ResourceKind::Queue, 5),
        (
            ResourceDomain::CertificateBytes,
            ResourceKind::Certificate,
            6,
        ),
        (
            ResourceDomain::ProviderOperations,
            ResourceKind::Provider,
            7,
        ),
    ];

    for (domain, expected_kind, limit) in cases {
        assert_eq!(budget.limit(domain), limit);
        assert!(
            budget
                .check(domain, limit, ExhaustionPhase::Handshake)
                .is_ok()
        );
        let exhausted = budget.check(domain, limit.saturating_add(1), ExhaustionPhase::Handshake);
        assert!(exhausted.is_err());
        if let Err(exhausted) = exhausted {
            assert_eq!(exhausted.resource(), expected_kind);
            assert_eq!(exhausted.phase(), ExhaustionPhase::Handshake);
        }
    }
}

#[test]
fn duplicate_assignments_are_rejected_for_every_domain() {
    for (domain, limit) in LIMITS {
        let first = assign(ResourceBudget::builder(), domain, limit);
        assert!(first.is_ok());
        if let Ok(builder) = first {
            let duplicate = assign(builder, domain, limit.saturating_add(100));
            assert!(matches!(
                duplicate,
                Err(BudgetBuildError::Duplicate(rejected)) if rejected == domain
            ));
        }
    }
}

#[test]
fn incomplete_builds_identify_every_missing_domain() {
    for (domain, _) in LIMITS {
        let builder = builder_without(domain);
        assert!(builder.is_ok());
        if let Ok(builder) = builder {
            assert!(matches!(
                builder.build(),
                Err(BudgetBuildError::Incomplete(missing)) if missing == domain
            ));
        }
    }
}

#[test]
fn work_budget_is_exact_limit_value_free_and_immutable() {
    let budget = WorkBudget::new(10);
    assert_eq!(budget.limit(), 10);
    assert!(budget.check(0, ExhaustionPhase::Validation).is_ok());
    assert!(budget.check(10, ExhaustionPhase::Validation).is_ok());

    let exhausted = budget.check(11, ExhaustionPhase::Validation);
    assert!(exhausted.is_err());
    if let Err(exhausted) = exhausted {
        assert_eq!(exhausted.resource(), ResourceKind::Work);
        assert_eq!(exhausted.phase(), ExhaustionPhase::Validation);
    }
    assert_eq!(budget.limit(), 10);
}

#[test]
fn zero_budgets_admit_only_zero() {
    let mut builder = ResourceBudget::builder();
    for (domain, _) in LIMITS {
        let assigned = assign(builder, domain, 0);
        assert!(assigned.is_ok());
        let Ok(next) = assigned else {
            return;
        };
        builder = next;
    }
    let resources = builder.build();
    assert!(resources.is_ok());
    let Ok(resources) = resources else {
        return;
    };
    for (domain, _) in LIMITS {
        assert!(resources.check(domain, 0, ExhaustionPhase::Input).is_ok());
        assert!(resources.check(domain, 1, ExhaustionPhase::Input).is_err());
    }

    let work = WorkBudget::new(0);
    assert!(work.check(0, ExhaustionPhase::Input).is_ok());
    assert!(work.check(1, ExhaustionPhase::Input).is_err());
}

#[test]
fn budget_domains_have_no_hidden_storage() {
    assert_eq!(size_of::<ResourceBudget>(), size_of::<[usize; 7]>());
    assert_eq!(size_of::<WorkBudget>(), size_of::<u64>());
}
