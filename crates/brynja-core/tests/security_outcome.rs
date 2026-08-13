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
fn assert_domain_cancels<D: SecurityDecision>(expected: SecurityDecisionKind) {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<D>() else {
        unreachable!();
    };
    assert_eq!(pending.decision(), expected);
    assert_eq!(
        authority.snapshot().state(),
        SecurityAuthorityState::Pending(expected)
    );
    let outcome = pending.resolve(SecurityResolution::Canceled);
    let SecurityOutcome::Canceled(completion) = outcome else {
        unreachable!();
    };
    assert_eq!(completion.decision(), expected);
    assert_eq!(
        authority.snapshot().state(),
        SecurityAuthorityState::AwaitingCommit(expected)
    );
    let receipt = completion.commit();
    assert_eq!(receipt.decision(), expected);
    assert!(receipt.belongs_to(&authority));
    assert_eq!(authority.snapshot().state(), SecurityAuthorityState::Ready);
}

#[test]
fn every_non_approval_domain_is_exact_and_typed() {
    assert_domain_cancels::<SelfTestDecision>(SecurityDecisionKind::SelfTest);
    assert_domain_cancels::<ProtocolSelectionDecision>(SecurityDecisionKind::ProtocolSelection);
    assert_domain_cancels::<ProfileSelectionDecision>(SecurityDecisionKind::ProfileSelection);
    assert_domain_cancels::<AuthenticationDecision>(SecurityDecisionKind::Authentication);
    assert_domain_cancels::<TicketDecision>(SecurityDecisionKind::Ticket);
    assert_domain_cancels::<ResumptionDecision>(SecurityDecisionKind::Resumption);
    assert_domain_cancels::<PskDecision>(SecurityDecisionKind::Psk);
    assert_domain_cancels::<EarlyDataDecision>(SecurityDecisionKind::EarlyData);
    assert_domain_cancels::<AntiReplayDecision>(SecurityDecisionKind::AntiReplay);
    assert_domain_cancels::<AmplificationDecision>(SecurityDecisionKind::Amplification);
    assert_domain_cancels::<ExhaustionDecision>(SecurityDecisionKind::Exhaustion);
    assert_domain_cancels::<ProviderDecision>(SecurityDecisionKind::Provider);
    assert_domain_cancels::<KeyLifecycleDecision>(SecurityDecisionKind::KeyLifecycle);
    assert_domain_cancels::<EchDecision>(SecurityDecisionKind::Ech);
    assert_domain_cancels::<PolicyDecision>(SecurityDecisionKind::Policy);
}

#[test]
fn positive_authority_is_unreachable_without_subject_bound_evidence() {
    let approved = SecurityAuthority::new();
    let Ok(pending) = approved.begin::<ServiceApprovalDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Approved),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(
        approved.snapshot().terminal(),
        Some(SecurityTerminal::ContractInvariant)
    );

    let accepted = SecurityAuthority::new();
    let Ok(pending) = accepted.begin::<AuthenticationDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Accepted),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(
        accepted.snapshot().terminal(),
        Some(SecurityTerminal::ContractInvariant)
    );

    let non_approved = SecurityAuthority::new();
    let Ok(pending) = non_approved.begin::<ServiceApprovalDecision>() else {
        unreachable!();
    };
    let SecurityOutcome::NonApproved(completion) = pending.resolve(SecurityResolution::NonApproved)
    else {
        unreachable!();
    };
    let receipt = completion.commit();
    assert_eq!(receipt.decision(), SecurityDecisionKind::ServiceApproval);
    assert_eq!(
        non_approved.snapshot().state(),
        SecurityAuthorityState::Ready
    );

    let ordinary = SecurityAuthority::new();
    let Ok(pending) = ordinary.begin::<AuthenticationDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::NonApproved),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(
        ordinary.snapshot().terminal(),
        Some(SecurityTerminal::ContractInvariant)
    );

    let accepted_approval = SecurityAuthority::new();
    let Ok(pending) = accepted_approval.begin::<ServiceApprovalDecision>() else {
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
    let outcome = pending.resolve(SecurityResolution::Rejected(
        SecurityRejection::Authentication,
    ));
    let SecurityOutcome::Rejected(completion, SecurityRejection::Authentication) = outcome else {
        unreachable!();
    };
    assert_eq!(
        authority.snapshot().state(),
        SecurityAuthorityState::AwaitingCommit(SecurityDecisionKind::Authentication)
    );
    let _receipt = completion.commit();
    assert_eq!(authority.snapshot().state(), SecurityAuthorityState::Ready);

    let canceled = SecurityAuthority::new();
    let Ok(pending) = canceled.begin::<TicketDecision>() else {
        unreachable!();
    };
    let SecurityOutcome::Canceled(completion) = pending.resolve(SecurityResolution::Canceled)
    else {
        unreachable!();
    };
    let _receipt = completion.commit();

    let failed = SecurityAuthority::new();
    let Ok(pending) = failed.begin::<ProviderDecision>() else {
        unreachable!();
    };
    let outcome = pending.resolve(SecurityResolution::Failed(SecurityFailureKind::Provider(
        ProviderFailureKind::InvalidOutput,
    )));
    let SecurityOutcome::Failed(
        completion,
        SecurityFailureKind::Provider(ProviderFailureKind::InvalidOutput),
    ) = outcome
    else {
        unreachable!();
    };
    let _receipt = completion.commit();
    assert_eq!(failed.snapshot().state(), SecurityAuthorityState::Ready);
}

fn assert_rejects<D: SecurityDecision>(reason: SecurityRejection) {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<D>() else {
        unreachable!();
    };
    let outcome = pending.resolve(SecurityResolution::Rejected(reason));
    let SecurityOutcome::Rejected(completion, observed) = outcome else {
        unreachable!();
    };
    assert_eq!(observed, reason);
    let _receipt = completion.commit();
    assert_eq!(authority.snapshot().state(), SecurityAuthorityState::Ready);
}

fn assert_fails<D: SecurityDecision>(reason: SecurityFailureKind) {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<D>() else {
        unreachable!();
    };
    let outcome = pending.resolve(SecurityResolution::Failed(reason));
    let SecurityOutcome::Failed(completion, observed) = outcome else {
        unreachable!();
    };
    assert_eq!(observed, reason);
    let _receipt = completion.commit();
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

    assert_fails::<ProviderDecision>(SecurityFailureKind::Provider(
        ProviderFailureKind::Unavailable,
    ));
    assert_fails::<ExhaustionDecision>(SecurityFailureKind::Exhaustion);
    assert_fails::<AuthenticationDecision>(SecurityFailureKind::Authentication);
    assert_fails::<KeyLifecycleDecision>(SecurityFailureKind::KeyLifecycle);
    assert_fails::<PolicyDecision>(SecurityFailureKind::Policy);
}

#[test]
fn mandatory_self_test_failure_permanently_latches_integrity() {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<SelfTestDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Failed(SecurityFailureKind::SelfTest)),
        SecurityOutcome::Terminal(_)
    ));
    assert_eq!(
        authority.snapshot().terminal(),
        Some(SecurityTerminal::Integrity)
    );
    assert_eq!(
        authority.begin::<ProviderDecision>().err(),
        Some(SecurityAuthorityError::Terminal(
            SecurityTerminal::Integrity
        ))
    );
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
    let SecurityOutcome::Accepted(completion) = destruction.finish(token.complete()) else {
        unreachable!();
    };
    assert_eq!(
        authority.snapshot().state(),
        SecurityAuthorityState::AwaitingCommit(SecurityDecisionKind::KeyLifecycle)
    );
    let receipt = completion.commit();
    assert!(receipt.belongs_to(&authority));
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
    let outcome = pending.resolve(SecurityResolution::Rejected(SecurityRejection::Policy));
    let SecurityOutcome::Rejected(completion, SecurityRejection::Policy) = outcome else {
        unreachable!();
    };
    let _receipt = completion.commit();
}

#[test]
fn abandoned_pending_decision_permanently_fails_authority() {
    let authority = SecurityAuthority::new();
    {
        let Ok(_pending) = authority.begin::<AuthenticationDecision>() else {
            unreachable!();
        };
    }
    assert_eq!(
        authority.snapshot().terminal(),
        Some(SecurityTerminal::DecisionAbandoned)
    );
    assert!(matches!(
        authority.begin::<PolicyDecision>(),
        Err(SecurityAuthorityError::Terminal(
            SecurityTerminal::DecisionAbandoned
        ))
    ));
}

#[test]
fn discarded_outcome_permanently_fails_authority() {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<AuthenticationDecision>() else {
        unreachable!();
    };
    let outcome = pending.resolve(SecurityResolution::Rejected(
        SecurityRejection::Authentication,
    ));
    assert_eq!(
        authority.snapshot().state(),
        SecurityAuthorityState::AwaitingCommit(SecurityDecisionKind::Authentication)
    );
    drop(outcome);
    assert_eq!(
        authority.snapshot().terminal(),
        Some(SecurityTerminal::OutcomeAbandoned)
    );
}

#[test]
fn awaiting_commit_blocks_new_work_until_exact_completion_is_consumed() {
    let authority = SecurityAuthority::new();
    let Ok(pending) = authority.begin::<TicketDecision>() else {
        unreachable!();
    };
    let SecurityOutcome::Canceled(completion) = pending.resolve(SecurityResolution::Canceled)
    else {
        unreachable!();
    };
    assert_eq!(
        authority.begin::<PolicyDecision>().err(),
        Some(SecurityAuthorityError::Busy(SecurityDecisionKind::Ticket))
    );
    let receipt = completion.commit();
    assert!(receipt.belongs_to(&authority));
    let Ok(pending) = authority.begin::<PolicyDecision>() else {
        unreachable!();
    };
    assert!(matches!(
        pending.resolve(SecurityResolution::Terminal(SecurityTerminal::Policy)),
        SecurityOutcome::Terminal(_)
    ));
}
