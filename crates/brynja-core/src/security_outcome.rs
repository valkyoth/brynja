//! Mandatory authoritative security outcomes.
//!
//! This module defines protocol-neutral state and result contracts. It does
//! not authenticate peers, select protocols, execute providers, destroy keys,
//! or emit audit events.

mod domain;
mod external_key;
mod outcome;
mod resolution;
mod state;

pub use domain::{
    AmplificationDecision, AntiReplayDecision, AuthenticationDecision, EarlyDataDecision,
    EchDecision, ExhaustionDecision, KeyLifecycleDecision, PolicyDecision,
    ProfileSelectionDecision, ProtocolSelectionDecision, ProviderDecision, PskDecision,
    ResumptionDecision, SecurityDecision, SecurityDecisionKind, SelfTestDecision,
    ServiceApprovalDecision, TerminalTransitionDecision, TicketDecision,
};
pub use external_key::{
    ExternalKeyDestroyed, ExternalKeyDestruction, ExternalKeyDestructionError,
    ExternalKeyDestructionFailure, ExternalKeyDestructionOutcome, ExternalKeyDestructionToken,
};
pub use outcome::{
    SecurityAccepted, SecurityApproved, SecurityCanceled, SecurityFailed, SecurityFailure,
    SecurityNonApproved, SecurityOutcome, SecurityRejected,
};
pub use resolution::{
    SecurityDisposition, SecurityFailureKind, SecurityRejection, SecurityResolution,
    SecurityTerminal,
};
pub use state::{
    SecurityAuthority, SecurityAuthorityError, SecurityAuthoritySnapshot, SecurityAuthorityState,
    SecurityPending, SecurityReceipt,
};
