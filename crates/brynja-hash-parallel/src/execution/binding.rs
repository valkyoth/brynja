use super::{Error, Identity, Plan, WorkerPolicy};

// Configuration is public; completed counts and sponge state live in the
// clearing owner, never here. Streaming roots cannot accept scheduled leaves.
pub(super) enum Binding<'plan, 'input> {
    Scheduled(&'plan Plan<'input>),
    Streaming {
        identity: Identity,
        block: usize,
        limit: u128,
        workers: WorkerPolicy,
    },
}
impl<'plan, 'input> Binding<'plan, 'input> {
    pub(super) fn scheduled(&self) -> Result<&'plan Plan<'input>, Error> {
        match self {
            Self::Scheduled(plan) => Ok(plan),
            Self::Streaming { .. } => Err(Error::State),
        }
    }
    pub(super) fn identity(&self) -> Identity {
        match self {
            Self::Scheduled(plan) => plan.identity,
            Self::Streaming { identity, .. } => *identity,
        }
    }
    pub(super) fn block(&self) -> usize {
        match self {
            Self::Scheduled(plan) => plan.block_size,
            Self::Streaming { block, .. } => *block,
        }
    }
    pub(super) fn limit(&self) -> u128 {
        match self {
            Self::Scheduled(plan) => plan.leaves,
            Self::Streaming { limit, .. } => *limit,
        }
    }
    pub(super) fn workers(&self) -> WorkerPolicy {
        match self {
            Self::Scheduled(plan) => plan.workers,
            Self::Streaming { workers, .. } => *workers,
        }
    }
    pub(super) fn complete(&self, merged: u128) -> bool {
        match self {
            Self::Scheduled(plan) => merged == plan.leaves,
            Self::Streaming { limit, .. } => merged <= *limit,
        }
    }
}
