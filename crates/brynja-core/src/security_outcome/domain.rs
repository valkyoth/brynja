//! Exact type-level domains for mandatory security decisions.

mod sealed {
    pub trait Sealed {}
}

/// Exact security decision represented by an authoritative transition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityDecisionKind {
    /// Module or algorithm self-test status.
    SelfTest,
    /// Per-service approved or non-approved status.
    ServiceApproval,
    /// Protocol-version selection.
    ProtocolSelection,
    /// Security-profile selection.
    ProfileSelection,
    /// Peer or credential authentication.
    Authentication,
    /// Ticket issuance or acceptance.
    Ticket,
    /// Session resumption.
    Resumption,
    /// Pre-shared-key selection or acceptance.
    Psk,
    /// Early-data acceptance.
    EarlyData,
    /// Anti-replay admission.
    AntiReplay,
    /// Amplification-limit admission.
    Amplification,
    /// Resource or sequence exhaustion handling.
    Exhaustion,
    /// Provider transition result.
    Provider,
    /// Key creation, use, replacement, or destruction.
    KeyLifecycle,
    /// Encrypted ClientHello policy and acceptance.
    Ech,
    /// Local mandatory policy decision.
    Policy,
    /// An explicit terminal engine transition.
    TerminalTransition,
}

/// Sealed marker implemented by every exact security-decision domain.
pub trait SecurityDecision: sealed::Sealed {
    /// The runtime discriminant corresponding to this type-level domain.
    const KIND: SecurityDecisionKind;
}

macro_rules! decision_domain {
    ($name:ident, $kind:ident, $docs:literal) => {
        #[doc = $docs]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl SecurityDecision for $name {
            const KIND: SecurityDecisionKind = SecurityDecisionKind::$kind;
        }
    };
}

decision_domain!(SelfTestDecision, SelfTest, "Self-test result domain.");
decision_domain!(
    ServiceApprovalDecision,
    ServiceApproval,
    "Per-service approval domain."
);
decision_domain!(
    ProtocolSelectionDecision,
    ProtocolSelection,
    "Protocol selection domain."
);
decision_domain!(
    ProfileSelectionDecision,
    ProfileSelection,
    "Security-profile selection domain."
);
decision_domain!(
    AuthenticationDecision,
    Authentication,
    "Authentication domain."
);
decision_domain!(TicketDecision, Ticket, "Ticket lifecycle domain.");
decision_domain!(ResumptionDecision, Resumption, "Resumption domain.");
decision_domain!(PskDecision, Psk, "Pre-shared-key domain.");
decision_domain!(EarlyDataDecision, EarlyData, "Early-data domain.");
decision_domain!(AntiReplayDecision, AntiReplay, "Anti-replay domain.");
decision_domain!(
    AmplificationDecision,
    Amplification,
    "Amplification-limit domain."
);
decision_domain!(ExhaustionDecision, Exhaustion, "Exhaustion domain.");
decision_domain!(ProviderDecision, Provider, "Provider result domain.");
decision_domain!(KeyLifecycleDecision, KeyLifecycle, "Key-lifecycle domain.");
decision_domain!(EchDecision, Ech, "Encrypted ClientHello domain.");
decision_domain!(PolicyDecision, Policy, "Mandatory policy domain.");
decision_domain!(
    TerminalTransitionDecision,
    TerminalTransition,
    "Explicit terminal-transition domain."
);
