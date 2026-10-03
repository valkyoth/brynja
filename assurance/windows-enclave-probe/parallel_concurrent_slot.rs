//! Exclusive leaf storage; no transferable authority or public CV accessor.
use super::{Authority, Bits, Error, Plan, State, check_authority};
use brynja_core::clear_owned_region;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Pending,
    Complete,
    Dead,
}
pub struct Slot<'plan> {
    plan: &'plan Plan,
    index: usize,
    cv: [u8; 64],
    phase: Phase,
    #[cfg(test)]
    pub(super) before_publish: Option<fn()>,
}
struct Operation<'a, 'plan> {
    slot: &'a mut Slot<'plan>,
    complete: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.slot.clear();
        }
    }
}
impl<'plan> Slot<'plan> {
    pub(super) fn new(plan: &'plan Plan, index: usize) -> Self {
        Self {
            plan,
            index,
            cv: [0; 64],
            phase: Phase::Pending,
            #[cfg(test)]
            before_publish: None,
        }
    }
    pub(super) fn clear(&mut self) {
        let _ = clear_owned_region(&mut self.cv);
        self.phase = Phase::Dead;
    }
    pub(super) fn unused(&self) -> bool {
        self.phase == Phase::Pending && self.cv == [0; 64]
    }
    /// Call on the worker owning this exclusive slot. The authority must be
    /// constructed there. Input length is exactly the plan's indexed leaf.
    pub fn run(&mut self, authority: &Authority, input: Bits<'_>) -> Result<(), Error> {
        let mut op = Operation {
            slot: self,
            complete: false,
        };
        if op.slot.phase != Phase::Pending {
            return Err(Error::State);
        }
        let plan = op.slot.plan;
        plan.check()?;
        check_authority(authority)?;
        if input.bit_len() != plan.leaf_bits(op.slot.index)? {
            return Err(Error::Bits);
        }
        let mut state = State::leaf(authority, plan.identity)?;
        state.finish(input)?;
        state.squeeze(
            op.slot.cv.get_mut(..plan.width()).ok_or(Error::Length)?,
            8,
            true,
        )?;
        drop(state);
        #[cfg(test)]
        if let Some(hook) = op.slot.before_publish {
            hook();
        }
        plan.check()?;
        check_authority(authority)?;
        op.slot.phase = Phase::Complete;
        op.complete = true;
        Ok(())
    }
    pub(super) fn absorb(
        &mut self,
        root: &mut State<'_>,
        plan: &Plan,
        index: usize,
    ) -> Result<(), Error> {
        if self.phase != Phase::Complete || !core::ptr::eq(self.plan, plan) || self.index != index {
            return Err(Error::State);
        }
        let result = root.update(self.cv.get(..plan.width()).ok_or(Error::Length)?);
        self.clear();
        result
    }
    #[cfg(test)]
    pub(super) fn cleared(&self) -> bool {
        self.phase == Phase::Dead && self.cv == [0; 64]
    }
}
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}
