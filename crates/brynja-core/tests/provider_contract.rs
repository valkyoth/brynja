//! Provider-capability, installation, handle, and request-boundary tests.

use brynja_core::{
    DestructionTargets, ExhaustionPhase, ProviderAuthorizationError, ProviderCapabilities,
    ProviderCapabilityError, ProviderFrame, ProviderInstallation, ProviderInstallationError,
    ProviderInstallationField, ProviderOperation, ProviderRequest, ProviderRequestError,
    ResourceBudget, ResourceBudgetBuilder, ResourceDomain, ResourceKind, WorkBudget,
};

fn capabilities(operations: &[ProviderOperation]) -> ProviderCapabilities {
    let mut builder = ProviderCapabilities::builder();
    for operation in operations {
        let result = builder.enable(*operation);
        assert!(result.is_ok());
        let Ok(next) = result else {
            loop {
                core::hint::spin_loop();
            }
        };
        builder = next;
    }
    let frozen = builder.freeze();
    assert!(frozen.is_ok());
    let Ok(frozen) = frozen else {
        loop {
            core::hint::spin_loop();
        }
    };
    frozen
}

fn resource_builder() -> Result<ResourceBudgetBuilder, ()> {
    let builder = ResourceBudget::builder().input_bytes(16).map_err(|_| ())?;
    let builder = builder.output_bytes(8).map_err(|_| ())?;
    let builder = builder.workspace_bytes(32).map_err(|_| ())?;
    let builder = builder.state_items(4).map_err(|_| ())?;
    let builder = builder.queue_items(2).map_err(|_| ())?;
    let builder = builder.certificate_bytes(16).map_err(|_| ())?;
    builder.provider_operations(1).map_err(|_| ())
}

fn resources() -> ResourceBudget {
    let builder = resource_builder();
    assert!(builder.is_ok());
    let Ok(builder) = builder else {
        loop {
            core::hint::spin_loop();
        }
    };
    let result = builder.build();
    assert!(result.is_ok());
    let Ok(result) = result else {
        loop {
            core::hint::spin_loop();
        }
    };
    result
}

fn installation(
    operations: &[ProviderOperation],
) -> Result<brynja_core::InstalledProvider, ProviderInstallationError> {
    ProviderInstallation::begin()
        .capabilities(capabilities(operations))?
        .resources(resources())?
        .work(WorkBudget::new(12))?
        .destruction_targets(DestructionTargets::all())?
        .install()
}

fn prepare<'provider, 'data>(
    provider: &'provider brynja_core::InstalledProvider,
    operation: ProviderOperation,
    primary: &'data [u8],
    context: &'data [u8],
    output_capacity: usize,
) -> Result<ProviderRequest<'provider, 'data>, ProviderRequestError> {
    let authorization = provider.handle().authorize(operation);
    assert!(authorization.is_ok());
    let Ok(authorization) = authorization else {
        return Err(ProviderRequestError::InputLengthOverflow);
    };
    authorization.prepare(ProviderFrame::new(primary, context, output_capacity))
}

#[test]
fn every_capability_is_independent_and_single_assignment() {
    let all = capabilities(&ProviderOperation::ALL);
    assert_eq!(all.count(), 19);
    for operation in ProviderOperation::ALL {
        assert!(all.contains(operation));
        let duplicate = ProviderCapabilities::builder()
            .enable(operation)
            .and_then(|builder| builder.enable(operation));
        assert!(matches!(
            duplicate,
            Err(ProviderCapabilityError::Duplicate(rejected)) if rejected == operation
        ));
    }
    assert!(matches!(
        ProviderCapabilities::builder().freeze(),
        Err(ProviderCapabilityError::Empty)
    ));
}

#[test]
fn installation_is_named_single_assignment_and_transactional() {
    let caps = capabilities(&[ProviderOperation::Hash]);
    let duplicate = ProviderInstallation::begin()
        .capabilities(caps)
        .and_then(|builder| builder.capabilities(caps));
    assert!(matches!(
        duplicate,
        Err(ProviderInstallationError::Duplicate(
            ProviderInstallationField::Capabilities
        ))
    ));

    let missing = ProviderInstallation::begin().install();
    assert!(matches!(
        missing,
        Err(ProviderInstallationError::Incomplete(
            ProviderInstallationField::Capabilities
        ))
    ));

    let empty_targets = ProviderInstallation::begin()
        .capabilities(caps)
        .and_then(|builder| builder.resources(resources()))
        .and_then(|builder| builder.work(WorkBudget::new(1)))
        .and_then(|builder| {
            builder.destruction_targets(DestructionTargets::new(false, false, false, false, false))
        })
        .and_then(ProviderInstallation::install);
    assert!(matches!(
        empty_targets,
        Err(ProviderInstallationError::EmptyDestructionTargets)
    ));
}

#[test]
fn exact_direction_is_required_and_no_provider_fallback_occurs() {
    let seal = installation(&[ProviderOperation::AeadSeal]);
    let open = installation(&[ProviderOperation::AeadOpen]);
    assert!(seal.is_ok());
    assert!(open.is_ok());
    let Ok(seal) = seal else {
        return;
    };
    let Ok(open) = open else {
        return;
    };

    let rejected = seal.handle().authorize(ProviderOperation::AeadOpen);
    assert!(matches!(
        rejected,
        Err(ProviderAuthorizationError::Unsupported(
            ProviderOperation::AeadOpen
        ))
    ));
    assert!(open.handle().authorize(ProviderOperation::AeadOpen).is_ok());
    assert!(seal.handle().authorize(ProviderOperation::AeadSeal).is_ok());

    let mac_verify = installation(&[ProviderOperation::MacVerify]);
    assert!(mac_verify.is_ok());
    let Ok(mac_verify) = mac_verify else {
        return;
    };
    assert!(matches!(
        mac_verify
            .handle()
            .authorize(ProviderOperation::MacGenerate),
        Err(ProviderAuthorizationError::Unsupported(
            ProviderOperation::MacGenerate
        ))
    ));
    assert!(
        mac_verify
            .handle()
            .authorize(ProviderOperation::MacVerify)
            .is_ok()
    );
    assert!(matches!(
        prepare(&mac_verify, ProviderOperation::MacVerify, b"m", b"tag", 1,),
        Err(ProviderRequestError::OutputNotPermitted(
            ProviderOperation::MacVerify
        ))
    ));
    assert!(prepare(&mac_verify, ProviderOperation::MacVerify, b"m", b"tag", 0,).is_ok());
}

#[test]
fn every_operation_round_trips_through_an_exact_token() {
    let provider = installation(&ProviderOperation::ALL);
    assert!(provider.is_ok());
    let Ok(provider) = provider else {
        return;
    };
    for operation in ProviderOperation::ALL {
        let authorization = provider.handle().authorize(operation);
        assert!(authorization.is_ok());
        if let Ok(authorization) = authorization {
            assert_eq!(authorization.operation(), operation);
            let request = authorization.prepare(ProviderFrame::new(&[], &[], 0));
            assert!(request.is_ok());
            if let Ok(request) = request {
                assert_eq!(request.operation(), operation);
            }
        }
    }
}

#[test]
fn request_limits_are_exact_and_fail_before_any_effect() {
    let provider = installation(&[ProviderOperation::Hash]);
    assert!(provider.is_ok());
    let Ok(provider) = provider else {
        return;
    };
    let primary = [0x5a; 12];
    let context = [0xa5; 4];
    let exact = prepare(&provider, ProviderOperation::Hash, &primary, &context, 8);
    assert!(exact.is_ok());
    if let Ok(request) = exact {
        assert_eq!(request.frame().primary(), primary);
        assert_eq!(request.frame().context(), context);
        assert_eq!(request.frame().output_capacity(), 8);
        assert_eq!(request.remaining_work(), 12);
        assert_eq!(request.resources().limit(ResourceDomain::InputBytes), 16);
    }
    assert_eq!(primary, [0x5a; 12]);
    assert_eq!(context, [0xa5; 4]);

    let input = prepare(&provider, ProviderOperation::Hash, &[0; 13], &[0; 4], 0);
    match input {
        Err(ProviderRequestError::ResourceExhausted(error)) => {
            assert_eq!(error.resource(), ResourceKind::Input);
            assert_eq!(error.phase(), ExhaustionPhase::Provider);
        }
        Ok(_) | Err(_) => assert!(core::hint::black_box(false)),
    }

    let output = prepare(&provider, ProviderOperation::Hash, &[], &[], 9);
    match output {
        Err(ProviderRequestError::ResourceExhausted(error)) => {
            assert_eq!(error.resource(), ResourceKind::Output);
        }
        Ok(_) | Err(_) => assert!(core::hint::black_box(false)),
    }
}

#[test]
fn secret_destruction_duties_are_frozen_and_complete() {
    let provider = installation(&[ProviderOperation::KemDecapsulate]);
    assert!(provider.is_ok());
    let Ok(provider) = provider else {
        return;
    };
    let targets = provider.destruction_targets();
    for target in [
        brynja_core::DestructionTarget::LocalMemory,
        brynja_core::DestructionTarget::ExternalStore,
        brynja_core::DestructionTarget::Accelerator,
        brynja_core::DestructionTarget::Cache,
        brynja_core::DestructionTarget::Dma,
    ] {
        assert!(targets.contains(target));
    }
}

#[test]
fn deterministic_metadata_retains_exact_provider_identity() {
    let first = installation(&[ProviderOperation::StorageRead]);
    let second = installation(&[ProviderOperation::StorageRead]);
    assert!(first.is_ok());
    assert!(second.is_ok());
    let (Ok(first), Ok(second)) = (first, second) else {
        return;
    };
    let left = prepare(
        &first,
        ProviderOperation::StorageRead,
        b"object",
        b"namespace",
        8,
    );
    let right = prepare(
        &second,
        ProviderOperation::StorageRead,
        b"object",
        b"namespace",
        8,
    );
    assert!(left.is_ok());
    assert!(right.is_ok());
    let (Ok(left), Ok(right)) = (left, right) else {
        return;
    };
    assert_eq!(left.operation(), right.operation());
    assert_eq!(left.frame().primary(), right.frame().primary());
    assert_eq!(left.frame().context(), right.frame().context());
    assert_eq!(
        left.frame().output_capacity(),
        right.frame().output_capacity()
    );
    assert_eq!(left.remaining_work(), right.remaining_work());
    assert!(left.is_bound_to(&first.handle()));
    assert!(!left.is_bound_to(&second.handle()));
    assert!(right.is_bound_to(&second.handle()));
    assert!(!right.is_bound_to(&first.handle()));
}

#[test]
fn cancellation_direction_cannot_create_terminal_results() {
    let provider = installation(&[
        ProviderOperation::PendingPoll,
        ProviderOperation::PendingCancel,
    ]);
    assert!(provider.is_ok());
    let Ok(provider) = provider else {
        return;
    };
    let canceled = prepare(
        &provider,
        ProviderOperation::PendingCancel,
        b"pending-token",
        &[],
        0,
    );
    assert!(canceled.is_ok());
    let Ok(canceled) = canceled else {
        return;
    };
    assert_eq!(canceled.operation(), ProviderOperation::PendingCancel);
    assert!(canceled.is_bound_to(&provider.handle()));

    let polled = prepare(
        &provider,
        ProviderOperation::PendingPoll,
        b"pending-token",
        &[],
        0,
    );
    assert!(polled.is_ok());
    let Ok(polled) = polled else {
        return;
    };
    assert_eq!(polled.operation(), ProviderOperation::PendingPoll);
    assert!(polled.is_bound_to(&provider.handle()));
}

#[test]
fn immutable_frame_overlap_cannot_create_partial_mutation() {
    let provider = installation(&[ProviderOperation::MacGenerate]);
    assert!(provider.is_ok());
    let Ok(provider) = provider else {
        return;
    };
    let bytes = [0x3c; 8];
    let request = prepare(&provider, ProviderOperation::MacGenerate, &bytes, &bytes, 8);
    assert!(request.is_ok());
    if let Ok(request) = request {
        assert_eq!(request.frame().primary().as_ptr(), bytes.as_ptr());
        assert_eq!(request.frame().context().as_ptr(), bytes.as_ptr());
    }
    assert_eq!(bytes, [0x3c; 8]);
}
