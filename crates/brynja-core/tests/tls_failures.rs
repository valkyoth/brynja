//! Failure-domain separation and secrecy tests.

use brynja_core::{
    Alert, AlertDescription, AlertFailure, AlertOrigin, Cancellation, CloseOutcome,
    ExhaustionPhase, FailureKind, LocalFailure, ProtocolVersion, ProviderFailure,
    ProviderFailureKind, ProviderOperation, ResourceExhaustion, ResourceKind, TlsFailure,
};

fn admitted(description: AlertDescription) -> Option<Alert> {
    Alert::new(ProtocolVersion::Tls13, AlertOrigin::Peer, description)
}

#[test]
fn typed_outcomes() {
    let alerts = (
        admitted(AlertDescription::DecodeError),
        admitted(AlertDescription::CloseNotify),
        admitted(AlertDescription::UserCanceled),
    );
    assert!(matches!(alerts, (Some(_), Some(_), Some(_))));

    if let (Some(failure_alert), Some(close_alert), Some(cancel_alert)) = alerts {
        let alert_failure = AlertFailure::from_alert(failure_alert);
        assert!(alert_failure.is_some());
        if let Some(failure) = alert_failure {
            let tls_failure = TlsFailure::alert(failure);
            assert_eq!(tls_failure.version(), ProtocolVersion::Tls13);
            assert!(matches!(tls_failure.kind(), FailureKind::Alert(_)));
        }
        assert!(AlertFailure::from_alert(close_alert).is_none());
        assert!(AlertFailure::from_alert(cancel_alert).is_none());
        assert!(CloseOutcome::from_alert(close_alert).is_some());
        assert!(CloseOutcome::from_alert(failure_alert).is_none());
        assert!(Cancellation::from_alert(cancel_alert).is_some());
        assert!(Cancellation::from_alert(close_alert).is_none());
    }
}

#[test]
fn reject_secret_and_ambiguous_errors() {
    let local = TlsFailure::local(ProtocolVersion::Tls13, LocalFailure::InvalidInput);
    let provider = TlsFailure::provider(
        ProtocolVersion::Tls13,
        ProviderFailure::new(ProviderOperation::Aead, ProviderFailureKind::InvalidOutput),
    );
    let exhausted = TlsFailure::exhausted(
        ProtocolVersion::Tls13,
        ResourceExhaustion::new(ResourceKind::Workspace, ExhaustionPhase::Handshake),
    );

    assert!(matches!(local.kind(), FailureKind::Local(_)));
    assert!(matches!(provider.kind(), FailureKind::Provider(_)));
    assert!(matches!(exhausted.kind(), FailureKind::Exhausted(_)));
    assert_eq!(local.version(), ProtocolVersion::Tls13);
    assert!(::core::mem::size_of::<TlsFailure>() <= 4);
}

#[test]
fn provider_failures_are_deterministic_categories() {
    let first = ProviderFailure::new(ProviderOperation::Entropy, ProviderFailureKind::Unavailable);
    let second = ProviderFailure::new(ProviderOperation::Entropy, ProviderFailureKind::Unavailable);

    assert!(first == second);
    assert_eq!(first.operation(), ProviderOperation::Entropy);
    assert_eq!(first.kind(), ProviderFailureKind::Unavailable);
}

#[test]
fn exhaustion_does_not_expose_limit_values() {
    let failure = ResourceExhaustion::new(ResourceKind::Work, ExhaustionPhase::Validation);

    assert_eq!(failure.resource(), ResourceKind::Work);
    assert_eq!(failure.phase(), ExhaustionPhase::Validation);
    assert_eq!(::core::mem::size_of_val(&failure), 2);
}
