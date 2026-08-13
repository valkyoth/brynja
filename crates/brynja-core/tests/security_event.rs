//! Bounded observational security-event behavior.

use brynja_core::{
    AmplificationDecision, AntiReplayDecision, AuthenticationDecision, EarlyDataDecision,
    EchDecision, ExhaustionDecision, ExternalKeyDestruction, KeyLifecycleDecision, MonotonicClock,
    MonotonicClockSource, PolicyDecision, ProfileSelectionDecision, ProtocolSelectionDecision,
    ProviderDecision, ProviderFailureKind, PskDecision, ResumptionDecision, SecurityAuthority,
    SecurityAuthorityState, SecurityDecision, SecurityDecisionKind, SecurityDisposition,
    SecurityEvent, SecurityEventKind, SecurityEventPush, SecurityEventQueue, SecurityEventRecord,
    SecurityEventTimestamp, SecurityEventTimestampError, SecurityFailureKind, SecurityOutcome,
    SecurityPending, SecurityRejection, SecurityResolution, SecurityTerminal, SelfTestDecision,
    ServiceApprovalDecision, TerminalTransitionDecision, TicketDecision, WallTime,
};

fn cancel<D: SecurityDecision>(pending: SecurityPending<'_, D>) {
    let SecurityOutcome::Canceled(canceled) = pending.resolve(SecurityResolution::Canceled) else {
        unreachable!();
    };
    let _receipt = canceled.commit();
}

fn begin<'authority, D: SecurityDecision>(
    authority: &'authority SecurityAuthority,
) -> SecurityPending<'authority, D> {
    let Ok(pending) = authority.begin::<D>() else {
        unreachable!();
    };
    pending
}

fn snapshot_event(authority: &SecurityAuthority) -> SecurityEvent {
    let Some(event) = SecurityEvent::from_snapshot(authority.snapshot()) else {
        unreachable!();
    };
    event
}

fn assert_pending_domain<D: SecurityDecision>(expected: SecurityDecisionKind) {
    let authority = SecurityAuthority::new();
    let pending = begin::<D>(&authority);
    let before = authority.snapshot();
    let event = SecurityEvent::from_pending(&pending);
    assert_eq!(event.kind(), SecurityEventKind::Pending);
    assert_eq!(event.decision(), Some(expected));
    assert_eq!(event.disposition(), None);
    assert_eq!(event.terminal(), None);
    assert_eq!(authority.snapshot(), before);
    let SecurityOutcome::Canceled(canceled) = pending.resolve(SecurityResolution::Canceled) else {
        unreachable!();
    };
    let _receipt = canceled.commit();
}

#[test]
fn every_authoritative_decision_domain_is_observable_without_mutation() {
    assert_pending_domain::<SelfTestDecision>(SecurityDecisionKind::SelfTest);
    assert_pending_domain::<ServiceApprovalDecision>(SecurityDecisionKind::ServiceApproval);
    assert_pending_domain::<ProtocolSelectionDecision>(SecurityDecisionKind::ProtocolSelection);
    assert_pending_domain::<ProfileSelectionDecision>(SecurityDecisionKind::ProfileSelection);
    assert_pending_domain::<AuthenticationDecision>(SecurityDecisionKind::Authentication);
    assert_pending_domain::<TicketDecision>(SecurityDecisionKind::Ticket);
    assert_pending_domain::<ResumptionDecision>(SecurityDecisionKind::Resumption);
    assert_pending_domain::<PskDecision>(SecurityDecisionKind::Psk);
    assert_pending_domain::<EarlyDataDecision>(SecurityDecisionKind::EarlyData);
    assert_pending_domain::<AntiReplayDecision>(SecurityDecisionKind::AntiReplay);
    assert_pending_domain::<AmplificationDecision>(SecurityDecisionKind::Amplification);
    assert_pending_domain::<ExhaustionDecision>(SecurityDecisionKind::Exhaustion);
    assert_pending_domain::<ProviderDecision>(SecurityDecisionKind::Provider);
    assert_pending_domain::<KeyLifecycleDecision>(SecurityDecisionKind::KeyLifecycle);
    assert_pending_domain::<EchDecision>(SecurityDecisionKind::Ech);
    assert_pending_domain::<PolicyDecision>(SecurityDecisionKind::Policy);

    let terminal = SecurityAuthority::new();
    let pending = begin::<TerminalTransitionDecision>(&terminal);
    assert_eq!(
        SecurityEvent::from_pending(&pending).decision(),
        Some(SecurityDecisionKind::TerminalTransition)
    );
    assert!(matches!(
        pending.resolve(SecurityResolution::Terminal(SecurityTerminal::Policy)),
        SecurityOutcome::Terminal(_)
    ));
}

#[test]
fn exact_negative_outcomes_remain_authoritative_and_unmodified() {
    let rejected_authority = SecurityAuthority::new();
    let pending = begin::<AuthenticationDecision>(&rejected_authority);
    let SecurityOutcome::Rejected(rejected) = pending.resolve(SecurityResolution::Rejected(
        SecurityRejection::Authentication,
    )) else {
        unreachable!();
    };
    let before = rejected_authority.snapshot();
    let event = SecurityEvent::from_rejected(&rejected);
    assert_eq!(event.kind(), SecurityEventKind::Rejected);
    assert_eq!(event.decision(), Some(SecurityDecisionKind::Authentication));
    assert_eq!(
        event.disposition(),
        Some(SecurityDisposition::Rejected(
            SecurityRejection::Authentication
        ))
    );
    assert_eq!(rejected_authority.snapshot(), before);
    let _receipt = rejected.commit();

    let non_approved_authority = SecurityAuthority::new();
    let pending = begin::<ServiceApprovalDecision>(&non_approved_authority);
    let SecurityOutcome::NonApproved(non_approved) =
        pending.resolve(SecurityResolution::NonApproved)
    else {
        unreachable!();
    };
    assert_eq!(
        SecurityEvent::from_non_approved(&non_approved).kind(),
        SecurityEventKind::NonApproved
    );
    let _receipt = non_approved.commit();

    let canceled_authority = SecurityAuthority::new();
    let pending = begin::<TicketDecision>(&canceled_authority);
    let SecurityOutcome::Canceled(canceled) = pending.resolve(SecurityResolution::Canceled) else {
        unreachable!();
    };
    assert_eq!(
        SecurityEvent::from_canceled(&canceled).kind(),
        SecurityEventKind::Canceled
    );
    let _receipt = canceled.commit();

    let failed_authority = SecurityAuthority::new();
    let pending = begin::<ProviderDecision>(&failed_authority);
    let SecurityOutcome::Failed(failed) = pending.resolve(SecurityResolution::Failed(
        SecurityFailureKind::Provider(ProviderFailureKind::InvalidOutput),
    )) else {
        unreachable!();
    };
    let event = SecurityEvent::from_failed(&failed);
    assert_eq!(event.kind(), SecurityEventKind::Failed);
    assert_eq!(
        event.disposition(),
        Some(SecurityDisposition::Failed(SecurityFailureKind::Provider(
            ProviderFailureKind::InvalidOutput
        )))
    );
    let _receipt = failed.commit();
}

#[test]
fn verified_acceptance_is_only_duplicated_from_opaque_authority() {
    let authority = SecurityAuthority::new();
    let Ok(mut destruction) = ExternalKeyDestruction::begin(&authority) else {
        unreachable!();
    };
    let Ok(token) = destruction.destruction_token() else {
        unreachable!();
    };
    let SecurityOutcome::Accepted(accepted) = destruction.finish(token.complete()) else {
        unreachable!();
    };
    let before = authority.snapshot();
    let event = SecurityEvent::from_accepted(&accepted);
    assert_eq!(event.kind(), SecurityEventKind::Accepted);
    assert_eq!(event.decision(), Some(SecurityDecisionKind::KeyLifecycle));
    assert_eq!(event.disposition(), Some(SecurityDisposition::Accepted));
    assert_eq!(authority.snapshot(), before);
    let _receipt = accepted.commit();
}

#[test]
fn snapshots_duplicate_only_non_ready_authoritative_state() {
    let authority = SecurityAuthority::new();
    assert_eq!(SecurityEvent::from_snapshot(authority.snapshot()), None);

    let pending = begin::<PolicyDecision>(&authority);
    let event = snapshot_event(&authority);
    assert_eq!(event.kind(), SecurityEventKind::Pending);
    assert_eq!(event.decision(), Some(SecurityDecisionKind::Policy));

    let SecurityOutcome::Rejected(rejected) =
        pending.resolve(SecurityResolution::Rejected(SecurityRejection::Policy))
    else {
        unreachable!();
    };
    let event = snapshot_event(&authority);
    assert_eq!(event.kind(), SecurityEventKind::Rejected);
    assert_eq!(
        event.disposition(),
        Some(SecurityDisposition::Rejected(SecurityRejection::Policy))
    );
    let _receipt = rejected.commit();

    let terminal = SecurityAuthority::new();
    let pending = begin::<TerminalTransitionDecision>(&terminal);
    let SecurityOutcome::Terminal(_receipt) =
        pending.resolve(SecurityResolution::Terminal(SecurityTerminal::Integrity))
    else {
        unreachable!();
    };
    let event = snapshot_event(&terminal);
    assert_eq!(event.kind(), SecurityEventKind::Terminal);
    assert_eq!(event.decision(), None);
    assert_eq!(event.terminal(), Some(SecurityTerminal::Integrity));
}

#[test]
fn timestamp_free_boot_and_later_enrichment_are_explicit() {
    let authority = SecurityAuthority::new();
    let pending = begin::<PolicyDecision>(&authority);
    let mut record = SecurityEventRecord::untimestamped(SecurityEvent::from_pending(&pending));
    assert_eq!(record.timestamp(), SecurityEventTimestamp::Untimestamped);
    assert_eq!(
        record.enrich(SecurityEventTimestamp::Untimestamped),
        Err(SecurityEventTimestampError::UntimestampedInput)
    );
    let Ok(wall) = WallTime::from_unix_parts(123, 456) else {
        unreachable!();
    };
    assert_eq!(record.enrich(SecurityEventTimestamp::Wall(wall)), Ok(()));
    assert_eq!(record.timestamp(), SecurityEventTimestamp::Wall(wall));
    assert_eq!(
        record.enrich(SecurityEventTimestamp::Wall(wall)),
        Err(SecurityEventTimestampError::AlreadyTimestamped)
    );
    assert_eq!(
        authority.snapshot().state(),
        SecurityAuthorityState::Pending(SecurityDecisionKind::Policy)
    );
    let SecurityOutcome::Canceled(canceled) = pending.resolve(SecurityResolution::Canceled) else {
        unreachable!();
    };
    let _receipt = canceled.commit();
}

struct OneTick;

impl MonotonicClockSource for OneTick {
    fn read_monotonic_ticks(&mut self) -> Result<u64, brynja_core::ClockUnavailable> {
        Ok(7)
    }
}

#[test]
fn caller_monotonic_timestamp_is_supported_without_a_clock_dependency() {
    let authority = SecurityAuthority::new();
    let pending = begin::<PolicyDecision>(&authority);
    let Ok(generation) = brynja_core::ClockGeneration::new(1) else {
        unreachable!();
    };
    let Ok(instant) = MonotonicClock::new(OneTick, generation).read() else {
        unreachable!();
    };
    let mut record = SecurityEventRecord::untimestamped(SecurityEvent::from_pending(&pending));
    assert_eq!(
        record.enrich(SecurityEventTimestamp::Monotonic(instant)),
        Ok(())
    );
    assert_eq!(
        record.timestamp(),
        SecurityEventTimestamp::Monotonic(instant)
    );
    cancel(pending);
}

#[test]
fn events_do_not_embed_authority_generation_or_cross_connection_identity() {
    let authority = SecurityAuthority::new();
    let first = begin::<AuthenticationDecision>(&authority);
    let first_event = SecurityEvent::from_pending(&first);
    cancel(first);
    let second = begin::<AuthenticationDecision>(&authority);
    let second_event = SecurityEvent::from_pending(&second);
    assert_eq!(first_event, second_event);
    cancel(second);
}

#[test]
fn queue_is_fifo_bounded_non_blocking_and_loss_visible() {
    let first_authority = SecurityAuthority::new();
    let first = begin::<AuthenticationDecision>(&first_authority);
    let first_record = SecurityEventRecord::untimestamped(SecurityEvent::from_pending(&first));

    let second_authority = SecurityAuthority::new();
    let second = begin::<TicketDecision>(&second_authority);
    let second_record = SecurityEventRecord::untimestamped(SecurityEvent::from_pending(&second));

    let third_authority = SecurityAuthority::new();
    let third = begin::<PolicyDecision>(&third_authority);
    let third_record = SecurityEventRecord::untimestamped(SecurityEvent::from_pending(&third));

    let mut queue = SecurityEventQueue::<2>::new();
    assert_eq!(queue.push(first_record), SecurityEventPush::Stored);
    assert_eq!(queue.push(second_record), SecurityEventPush::Stored);
    assert_eq!(queue.push(third_record), SecurityEventPush::Dropped);
    let snapshot = queue.snapshot();
    assert_eq!(snapshot.capacity(), 2);
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot.dropped().count(), 1);
    assert!(!snapshot.dropped().is_saturated());
    assert_eq!(queue.pop(), Some(first_record));
    assert_eq!(queue.push(third_record), SecurityEventPush::Stored);
    assert_eq!(queue.pop(), Some(second_record));
    assert_eq!(queue.pop(), Some(third_record));
    assert_eq!(queue.pop(), None);

    cancel(first);
    cancel(second);
    cancel(third);
}

#[test]
fn absent_drain_and_zero_capacity_cannot_change_authority() {
    let authority = SecurityAuthority::new();
    let pending = begin::<AuthenticationDecision>(&authority);
    let SecurityOutcome::Rejected(rejected) = pending.resolve(SecurityResolution::Rejected(
        SecurityRejection::Authentication,
    )) else {
        unreachable!();
    };
    let before = authority.snapshot();
    let record = SecurityEventRecord::untimestamped(SecurityEvent::from_rejected(&rejected));
    let mut queue = SecurityEventQueue::<0>::new();
    assert_eq!(queue.push(record), SecurityEventPush::Dropped);
    assert_eq!(queue.snapshot().dropped().count(), 1);
    assert_eq!(authority.snapshot(), before);
    let _queue = queue;
    assert_eq!(authority.snapshot(), before);
    let _receipt = rejected.commit();
    assert_eq!(authority.snapshot().state(), SecurityAuthorityState::Ready);
}

#[test]
fn event_storage_is_fixed_and_contains_no_dynamic_payload() {
    fn require_copy<T: Copy>() {}
    require_copy::<SecurityEvent>();
    require_copy::<SecurityEventRecord>();
    assert!(core::mem::size_of::<SecurityEvent>() <= 32);
    assert!(core::mem::size_of::<SecurityEventRecord>() <= 64);
    let entries = 4 * core::mem::size_of::<Option<SecurityEventRecord>>();
    assert!(core::mem::size_of::<SecurityEventQueue<4>>() >= entries);
    assert!(
        core::mem::size_of::<SecurityEventQueue<4>>()
            <= entries + 4 * core::mem::size_of::<usize>()
    );
}
