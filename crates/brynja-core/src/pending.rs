//! Affine pending-provider operation contracts.
//!
//! Pending work is deliberately separated from protocol engines and platform
//! effects. The types in this module own continuation state, bound retry and
//! backpressure transitions, and make cleanup an authoritative transition.

mod effect;
mod lifecycle;
mod outcome;
mod request;

pub use effect::{
    PendingBackpressure, PendingBegin, PendingCancelStep, PendingDestructionCause,
    PendingDestructionComplete, PendingDestructionFailure, PendingDestructionFailureKind,
    PendingDestructionOutcome, PendingDestructionToken, PendingEffectRequest, PendingProvider,
    PendingRetryReason, PendingStep, PendingWorkPermit,
};
pub use lifecycle::PendingOperation;
pub use outcome::{
    PendingCancellation, PendingCompletion, PendingFailure, PendingFailureKind, PendingStart,
    PendingTransition,
};
pub use request::{
    PendingLimitError, PendingLimits, PendingRequest, PendingRequestError, PendingRequestKind,
    PendingResource,
};
