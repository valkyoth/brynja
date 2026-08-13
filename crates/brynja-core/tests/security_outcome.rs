//! Mandatory security-outcome authority tests.

use brynja_core::{
    AmplificationDecision, AntiReplayDecision, AuthenticationDecision, DestructionTarget,
    EarlyDataDecision, EchDecision, ExhaustionDecision, ExternalKeyDestruction,
    ExternalKeyDestructionError, KeyLifecycleDecision, PolicyDecision, ProfileSelectionDecision,
    ProtocolSelectionDecision, ProviderDecision, ProviderFailureKind, PskDecision,
    ResumptionDecision, SecurityAuthority, SecurityAuthorityError, SecurityAuthorityState,
    SecurityDecision, SecurityDecisionKind, SecurityFailureKind, SecurityOutcome,
    SecurityRejection, SecurityResolution, SecurityTerminal, SelfTestDecision,
    ServiceApprovalDecision, TerminalTransitionDecision, TicketDecision,
};

fn assert_accepts<D: SecurityDecision>(expected: SecurityDecisionKind) {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<D>() else {
        unreachable!();
    };
    assert_eq!(pending.decision(), expected);
    assert_eq!(
        authority.snapshot().state(),
        SecurityAuthorityState::Pending(expected)
    );
    let outcome = pending.resolve(SecurityResolution::Accepted);
    let SecurityOutcome::Accepted(receipt) = outcome else {
        unreachable!();
    };
    assert_eq!(receipt.decision(), expected);
    assert!(receipt.belongs_to(&authority));
    assert_eq!(authority.snapshot().state(), SecurityAuthorityState::Ready);
}

#[test]
fn every_non_approval_domain_is_exact_and_typed() {
    assert_accepts::<SelfTestDecision>(SecurityDecisionKind::SelfTest);
    assert_accepts::<ProtocolSelectionDecision>(SecurityDecisionKind::ProtocolSelection);
    assert_accepts::<ProfileSelectionDecision>(SecurityDecisionKind::ProfileSelection);
    assert_accepts::<AuthenticationDecision>(SecurityDecisionKind::Authentication);
    assert_accepts::<TicketDecision>(SecurityDecisionKind::Ticket);
    assert_accepts::<ResumptionDecision>(SecurityDecisionKind::Resumption);
    assert_accepts::<PskDecision>(SecurityDecisionKind::Psk);
    assert_accepts::<EarlyDataDecision>(SecurityDecisionKind::EarlyData);
    assert_accepts::<AntiReplayDecision>(SecurityDecisionKind::AntiReplay);
    assert_accepts::<AmplificationDecision>(SecurityDecisionKind::Amplification);
    assert_accepts::<ExhaustionDecision>(SecurityDecisionKind::Exhaustion);
    assert_accepts::<ProviderDecision>(SecurityDecisionKind::Provider);
    assert_accepts::<KeyLifecycleDecision>(SecurityDecisionKind::KeyLifecycle);
    assert_accepts::<EchDecision>(SecurityDecisionKind::Ech);
    assert_accepts::<PolicyDecision>(SecurityDecisionKind::Policy);
}

#[test]
fn approval_is_explicit_and_confined_to_its_domain() {
    for resolution in [
        SecurityResolution::Approved,
        SecurityResolution::NonApproved,
    ] {
        let authority = SecurityAuthority::new();
        let Ok(pending) = authority.begin::<ServiceApprovalDecision>() else {
            unreachable!();
        };
        let outcome = pending.resolve(resolution);
        match (resolution, outcome) {
            (SecurityResolution::Approved, SecurityOutcome::Approved(receipt))
            | (SecurityResolution::NonApproved, SecurityOutcome::NonApproved(receipt)) => {
                assert_eq!(receipt.decision(), SecurityDecisionKind::ServiceApproval);
            }
            _ => unreachable!(),
        }
        assert_eq!(authority.snapshot().state(), SecurityAuthorityState::Ready);
    }

    let ordinary = SecurityAuthority::new();
    let Ok(pending) = ordinary.begin::<AuthenticationDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Approved),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(
        ordinary.snapshot().terminal(),
        Some(SecurityTerminal::ContractInvariant)
    );

    let approval = SecurityAuthority::new();
    let Ok(pending) = approval.begin::<ServiceApprovalDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Accepted),
        SecurityOutcome::Terminal(_)
    ));
}

#[test]
fn every_mandatory_outcome_preserves_unambiguous_state() {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<AuthenticationDecision>() else {
        unreachable!();
    };
    let generation = pending.generation();
    let outcome = pending.resolve(SecurityResolution::Pending);
    let SecurityOutcome::Pending(pending) = outcome else {
        unreachable!();
    };
    assert_eq!(pending.generation(), generation);
    assert!(matches!(
        pending.resolve(SecurityResolution::Rejected(
            SecurityRejection::Authentication
        )),
        SecurityOutcome::Rejected(_, SecurityRejection::Authentication)
    ));
    assert_eq!(authority.snapshot().state(), SecurityAuthorityState::Ready);

    let canceled = SecurityAuthority::new();
    let Ok(pending) = canceled.begin::<TicketDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Canceled),
        SecurityOutcome::Canceled(_)
    ));

    let failed = SecurityAuthority::new();
    let Ok(pending) = failed.begin::<ProviderDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Failed(SecurityFailureKind::Provider(
            ProviderFailureKind::InvalidOutput
        ))),
        SecurityOutcome::Failed(
            _,
            SecurityFailureKind::Provider(ProviderFailureKind::InvalidOutput)
        )
    ));
    assert_eq!(failed.snapshot().state(), SecurityAuthorityState::Ready);
}

fn assert_rejects<D: SecurityDecision>(reason: SecurityRejection) {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<D>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Rejected(reason)),
        SecurityOutcome::Rejected(_, observed) if observed == reason
    ));
    assert_eq!(authority.snapshot().state(), SecurityAuthorityState::Ready);
}

fn assert_fails<D: SecurityDecision>(reason: SecurityFailureKind) {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<D>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Failed(reason)),
        SecurityOutcome::Failed(_, observed) if observed == reason
    ));
    assert_eq!(authority.snapshot().state(), SecurityAuthorityState::Ready);
}

#[test]
fn closed_rejection_and_failure_classes_are_exercised() {
    assert_rejects::<ProtocolSelectionDecision>(SecurityRejection::Unsupported);
    assert_rejects::<PolicyDecision>(SecurityRejection::Policy);
    assert_rejects::<AuthenticationDecision>(SecurityRejection::Authentication);
    assert_rejects::<AntiReplayDecision>(SecurityRejection::Replay);
    assert_rejects::<AmplificationDecision>(SecurityRejection::Amplification);
    assert_rejects::<TicketDecision>(SecurityRejection::Ticket);
    assert_rejects::<PskDecision>(SecurityRejection::Psk);
    assert_rejects::<EarlyDataDecision>(SecurityRejection::EarlyData);
    assert_rejects::<EchDecision>(SecurityRejection::Ech);

    assert_fails::<SelfTestDecision>(SecurityFailureKind::SelfTest);
    assert_fails::<ProviderDecision>(SecurityFailureKind::Provider(
        ProviderFailureKind::Unavailable,
    ));
    assert_fails::<ExhaustionDecision>(SecurityFailureKind::Exhaustion);
    assert_fails::<AuthenticationDecision>(SecurityFailureKind::Authentication);
    assert_fails::<KeyLifecycleDecision>(SecurityFailureKind::KeyLifecycle);
    assert_fails::<PolicyDecision>(SecurityFailureKind::Policy);
}

#[test]
fn rejection_and_failure_reasons_cannot_cross_typed_domains() {
    let rejection = SecurityAuthority::new();
    let Ok(pending) = rejection.begin::<AuthenticationDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Rejected(SecurityRejection::Ticket)),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(
        rejection.snapshot().terminal(),
        Some(SecurityTerminal::ContractInvariant)
    );

    let failure = SecurityAuthority::new();
    let Ok(pending) = failure.begin::<ProviderDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Failed(
            SecurityFailureKind::Authentication
        )),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(
        failure.snapshot().terminal(),
        Some(SecurityTerminal::ContractInvariant)
    );
}

#[test]
fn busy_and_terminal_state_fail_closed() {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<EarlyDataDecision>() else {
        unreachable!();
    };
    assert_eq!(
        authority.begin::<AntiReplayDecision>().err(),
        Some(SecurityAuthorityError::Busy(
            SecurityDecisionKind::EarlyData
        ))
    );
    assert!(matches!(
        pending.resolve(SecurityResolution::Terminal(SecurityTerminal::Integrity)),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(
        authority.snapshot().state(),
        SecurityAuthorityState::Terminal
    );
    assert_eq!(
        authority.snapshot().terminal(),
        Some(SecurityTerminal::Integrity)
    );
    assert_eq!(
        authority.begin::<PolicyDecision>().err(),
        Some(SecurityAuthorityError::Terminal(
            SecurityTerminal::Integrity
        ))
    );
}

#[test]
fn explicit_terminal_domain_cannot_report_non_terminal_success() {
    let invalid = SecurityAuthority::new();
    let Ok(pending) = invalid.begin::<TerminalTransitionDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Accepted),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(
        invalid.snapshot().terminal(),
        Some(SecurityTerminal::ContractInvariant)
    );

    let valid = SecurityAuthority::new();
    let Ok(pending) = valid.begin::<TerminalTransitionDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Terminal(SecurityTerminal::Policy)),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(valid.snapshot().terminal(), Some(SecurityTerminal::Policy));
}

#[test]
fn external_key_success_requires_the_single_consumption_token() {
    let authority = SecurityAuthority::new();
    let Ok(mut destruction) = ExternalKeyDestruction::begin(&authority) else {
        unreachable!();
    };
    let Ok(token) = destruction.destruction_token() else {
        unreachable!();
    };
    assert_eq!(token.target(), DestructionTarget::ExternalStore);
    assert_eq!(
        destruction.destruction_token().err(),
        Some(ExternalKeyDestructionError::TokenAlreadyIssued)
    );
    assert!(matches!(
        destruction.finish(token.complete()),
        SecurityOutcome::Accepted(_)
    ));
    assert_eq!(authority.snapshot().state(), SecurityAuthorityState::Ready);
}

#[test]
fn external_key_failure_abort_and_cross_binding_are_terminal() {
    let failed = SecurityAuthority::new();
    let Ok(mut destruction) = ExternalKeyDestruction::begin(&failed) else {
        unreachable!();
    };
    let Ok(token) = destruction.destruction_token() else {
        unreachable!();
    };
    assert!(matches!(
        destruction.finish(token.fail(ProviderFailureKind::Failed)),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(
        failed.snapshot().terminal(),
        Some(SecurityTerminal::ExternalKeyDestruction)
    );

    let aborted = SecurityAuthority::new();
    let Ok(destruction) = ExternalKeyDestruction::begin(&aborted) else {
        unreachable!();
    };
    assert!(matches!(destruction.abort(), SecurityOutcome::Terminal(_)));

    let first = SecurityAuthority::new();
    let second = SecurityAuthority::new();
    let Ok(mut first_flow) = ExternalKeyDestruction::begin(&first) else {
        unreachable!();
    };
    let Ok(token) = first_flow.destruction_token() else {
        unreachable!();
    };
    let Ok(second_flow) = ExternalKeyDestruction::begin(&second) else {
        unreachable!();
    };
    assert!(matches!(
        second_flow.finish(token.complete()),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(
        second.snapshot().terminal(),
        Some(SecurityTerminal::ContractInvariant)
    );
    let _ = first_flow.abort();

    let dropped = SecurityAuthority::new();
    {
        let Ok(_destruction) = ExternalKeyDestruction::begin(&dropped) else {
            unreachable!();
        };
    }
    assert_eq!(
        dropped.snapshot().terminal(),
        Some(SecurityTerminal::ExternalKeyDestruction)
    );
}

#[test]
fn informational_snapshots_cannot_authorize_or_complete_work() {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<PolicyDecision>() else {
        unreachable!();
    };
    let _ = authority.snapshot();
    let _ = authority.snapshot();
    assert_eq!(
        authority.snapshot().state(),
        SecurityAuthorityState::Pending(SecurityDecisionKind::Policy)
    );
    assert!(matches!(
        pending.resolve(SecurityResolution::Rejected(SecurityRejection::Policy)),
        SecurityOutcome::Rejected(_, SecurityRejection::Policy)
    ));
}
