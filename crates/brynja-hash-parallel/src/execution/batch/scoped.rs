//! Multibuffer leaf jobs for exact typed plans and scoped collectors.
//!
//! A worker borrows its local clearing workspace and executor, then transfers
//! completed CVs into caller-owned clearing storage. Only the completed loan
//! may cross threads; no authority or unfinished sponge state does. Shapes and
//! reports are public metadata. Caller input, abort, registers and spills are
//! outside the owned-memory clearing guarantee. No threads are started here.
//!
//! ```
//! use brynja_hash_parallel::{ParallelHash128Plan, ParallelHashPublicDeclassification,
//!     hardened_in_place::ParallelHash128CollectorWorkspace, execution::in_place::batch};
//! # fn main() -> Result<(), batch::Error> {
//! # fn check<T>(r:Result<T,brynja_hash_parallel::ParallelHashError>)->Result<T,batch::Error> { r.map_err(|e|batch::Error::Root(e.into())) }
//! let plan = check(ParallelHash128Plan::new(b"message", 2))?;
//! let mut root = ParallelHash128CollectorWorkspace::new();
//! let mut worker = batch::Workspace::new();
//! let mut slots = [[0;64];4];
//! let mut cancel = || false;
//! let leaves = plan.batch(0,4)?.execute_into(&batch::Executor::portable(),
//!     &mut worker, &mut slots, &mut batch::Control::new(64,&mut cancel))?;
//! check(check(root.with(&plan,b"",|mut collector| {
//!     collector.merge_batch(leaves)?;
//!     collector.finalize_public(&mut [0;32],ParallelHashPublicDeclassification::acknowledge())
//! }))?)?;
//! assert_eq!(slots,[[0;64];4]);
//! # Ok(()) }
//! ```

pub use super::{CAPACITY, Control, Error, Executor, KernelReport, Workspace};
use super::{RootError, hash};
use crate::ParallelHashError;
use brynja_core::clear_owned_region;
use core::{cell::Cell, marker::PhantomData};

fn plan_error(error: ParallelHashError) -> Error {
    Error::Root(error.into())
}

// The output guard exists before any fallible selection/input work. It is moved
// only as a loan; populated arrays remain in their caller's original storage.
struct Output<'out>(&'out mut [[u8; 64]; CAPACITY]);
impl Drop for Output<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0.as_flattened_mut());
    }
}
struct Scratch<'a>(&'a mut Workspace);
impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

macro_rules! group {
    ($plan:ident, $job:ident, $leaves:ident, $algorithm:ident, $width:expr) => {
        impl<'input> crate::$plan<'input> {
            /// Selects exactly 1..=4 consecutive leaves without shortening.
            /// Require mode rejects ineligible groups; Prefer permits scalar tails.
            pub fn batch(&self, start: u128, count: usize) -> Result<$job<'_, 'input>, Error> {
                let end = start.checked_add(count as u128).ok_or(RootError::State)?;
                if count == 0 || count > CAPACITY || end > self.leaf_count() {
                    return Err(RootError::State.into());
                }
                Ok($job { plan: self, start, count })
            }
        }
        /// Affine contiguous job borrowing one exact typed plan.
        pub struct $job<'plan, 'input> {
            plan: &'plan crate::$plan<'input>, start: u128, count: usize,
        }
        impl<'plan, 'input> $job<'plan, 'input> {
            /// Computes and transfers secret CVs; every error/unwind clears all
            /// supplied output and workspace bytes. Success clears workspace
            /// originals before return. Drop/merge clears the entire output array,
            /// including inactive slots and unused short-CV tails. A forgotten
            /// result cannot run Drop; thread adapters must retain a parent guard.
            pub fn execute_into<'out>(self, executor: &Executor<'_>, workspace: &mut Workspace,
                output: &'out mut [[u8;64];CAPACITY], control: &mut Control<'_>)
                -> Result<$leaves<'plan, 'input, 'out>, Error> {
                let output = Output(output);
                let _ = clear_owned_region(output.0.as_flattened_mut());
                workspace.clear();
                let scratch = Scratch(workspace);
                let kernel = executor.kernel()?;
                let mut inputs = core::array::from_fn(|_| None);
                for (offset, slot) in inputs.iter_mut().enumerate().take(self.count) {
                    let index = self.start.checked_add(offset as u128).ok_or(RootError::State)?;
                    *slot = Some(hash::Input::new(hash::Algorithm::$algorithm,
                        self.plan.job(index).map_err(plan_error)?.batch_input(), $width * 8)?);
                }
                let mut destinations = core::array::from_fn(|_| None);
                for (slot, bytes) in destinations.iter_mut().zip(&mut scratch.0.values).take(self.count) {
                    *slot = Some(bytes.get_mut(..$width).ok_or(RootError::State)?);
                }
                let (values, report) = executor.digest_secret(&inputs, destinations,
                    &mut scratch.0.hash, &mut scratch.0.staging, control)?;
                let active = (1u8.checked_shl(u32::try_from(self.count).map_err(|_| RootError::State)?).ok_or(RootError::State)?)
                    .checked_sub(1).ok_or(RootError::State)?;
                if report.accelerated_slots & !active != 0
                    || (report.accelerated_slots != 0) != (report.vector_calls != 0)
                    || (report.accelerated_slots != 0 && report.kernel != kernel) {
                    executor.quarantine();
                    return Err(RootError::State.into());
                }
                for (index, destination) in output.0.iter_mut().enumerate().take(self.count) {
                    let source = values.expose(index).ok_or(RootError::State)?;
                    let destination = destination.get_mut(..$width).ok_or(RootError::State)?;
                    if source.len() != destination.len() { return Err(RootError::State.into()); }
                    destination.copy_from_slice(source);
                }
                Ok($leaves { plan: self.plan, start: self.start, count: self.count,
                    report, output, exclusive: PhantomData })
            }
        }
        /// Completed exact-plan secret CV loan; Send, but not Sync/Copy/Clone/Debug.
        /// No byte importer or live authority lease. The root still checks its own
        /// authority on every merge. Independent leaf revocation after completion
        /// does not revoke the computed values.
        #[doc = concat!("```\nfn bound<T: Send>() {}\nbound::<brynja_hash_parallel::execution::in_place::batch::", stringify!($leaves), "<'static,'static,'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_hash_parallel::execution::in_place::batch::", stringify!($leaves), "<'static,'static,'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_hash_parallel::execution::in_place::batch::", stringify!($leaves), "<'static,'static,'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_hash_parallel::execution::in_place::batch::", stringify!($leaves), "<'static,'static,'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_hash_parallel::execution::in_place::batch::", stringify!($leaves), "<'static,'static,'static>>();\n```")]
        #[doc = concat!("```compile_fail\nfn import(bytes: &mut [[u8;64];4]) -> brynja_hash_parallel::execution::in_place::batch::", stringify!($leaves), "<'static,'static,'_> { bytes.into() }\n```")]
        #[doc = concat!("```compile_fail\nfn reuse(plan: &brynja_hash_parallel::", stringify!($plan), "<'_>, workspace: &mut brynja_hash_parallel::execution::in_place::batch::Workspace, slots: &mut [[u8;64];4]) { use brynja_hash_parallel::execution::in_place::batch::*; let mut no=||false; let leaves=plan.batch(0,1).unwrap().execute_into(&Executor::portable(),workspace,slots,&mut Control::new(32,&mut no)).unwrap(); slots[0][0]=1; core::hint::black_box(leaves); }\n```")]
        #[must_use = "merge or drop completed leaves to clear caller output storage"]
        pub struct $leaves<'plan, 'input, 'out> {
            plan: &'plan crate::$plan<'input>, start: u128, count: usize,
            report: KernelReport, output: Output<'out>, exclusive: PhantomData<Cell<()>>,
        }
        impl $leaves<'_, '_, '_> {
            /// Actual performed work, not certification or a live authority token.
            #[must_use]
            pub const fn report(&self) -> KernelReport { self.report }
            pub(crate) fn merge(self, plan: &crate::$plan<'_>,
                mut merge: impl FnMut(Result<u128, ParallelHashError>, &[u8]) -> Result<(), ParallelHashError>)
                -> Result<(), ParallelHashError> {
                if !core::ptr::eq(plan, self.plan) {
                    return merge(Err(ParallelHashError::LeafIdentity), &[]);
                }
                for (offset, bytes) in self.output.0.iter().enumerate().take(self.count) {
                    let index = self.start.checked_add(offset as u128).ok_or(ParallelHashError::LeafOrder);
                    merge(index, &bytes[..$width])?;
                }
                Ok(())
            }
        }
    };
}
group!(ParallelHash128Plan, Batch128, Leaves128, Shake128, 32);
group!(ParallelHash256Plan, Batch256, Leaves256, Shake256, 64);

#[cfg(test)]
mod tests;
