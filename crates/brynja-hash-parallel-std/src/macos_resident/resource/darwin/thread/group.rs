//! Bounded scoped Darwin workers. Never detach borrowed work or clear live stacks.
#![allow(unsafe_code)]
use super::{Attributes, Error, Job, Mapping, enter, pthread_create, pthread_join};
use core::{
    cell::{Cell, UnsafeCell},
    ffi::c_void,
};
#[cfg(test)]
mod tests;

struct Slot<'a, 'b, F> {
    mapping: &'a mut Mapping,
    attributes: Attributes,
    job: UnsafeCell<Job<&'b mut F>>,
    worker: Cell<Option<*mut c_void>>,
}
struct Group<'a, 'b, F> {
    slots: Vec<Slot<'a, 'b, F>>,
}
impl<F> Group<'_, '_, F> {
    fn join_all(&mut self) {
        for slot in &self.slots {
            if let Some(worker) = slot.worker.get() {
                #[cfg(test)]
                if tests::fail_join() {
                    std::process::abort();
                }
                // SAFETY: this is the sole owner/joiner of the successful Darwin
                // create handle. Failure cannot return while borrowed jobs live.
                if unsafe { pthread_join(worker, core::ptr::null_mut()) } != 0 {
                    std::process::abort();
                }
                slot.worker.set(None);
                #[cfg(test)]
                tests::joined();
            }
        }
        // Recreate exclusive mapping/slot borrows only after ALL workers and
        // their TLS destructors have terminated. Clear complete padded stacks.
        for slot in &mut self.slots {
            slot.mapping.clear();
        }
    }
}
impl<F> Drop for Group<'_, '_, F> {
    fn drop(&mut self) {
        self.join_all();
    }
}

pub(in super::super) fn run<F: FnMut() + Send>(
    mappings: &mut [Mapping],
    work: &mut [F],
) -> Result<(), Error> {
    if mappings.is_empty() || mappings.len() != work.len() {
        return Err(Error::InvalidSize);
    }
    if mappings.len() > 64 {
        return Err(Error::ResourceLimit);
    }
    let mut group = Group { slots: Vec::new() };
    group
        .slots
        .try_reserve_exact(mappings.len())
        .map_err(|_| Error::ResourceLimit)?;
    // Complete all allocation/attribute setup before the first launch. No
    // reallocation is possible once addresses are handed to native workers.
    for (mapping, work) in mappings.iter_mut().zip(work) {
        if mapping.foreign()
            || !mapping.admitted
            || mapping.base.is_none()
            || mapping.layout.payload < 65536
        {
            return Err(Error::ThreadAttributes);
        }
        #[cfg(test)]
        tests::prepare()?;
        let attributes = Attributes::new(mapping)?;
        group.slots.push(Slot {
            mapping,
            attributes,
            job: UnsafeCell::new(Job {
                work: Some(work),
                completed: false,
                panicked: false,
            }),
            worker: Cell::new(None),
        });
    }
    for slot in &group.slots {
        #[cfg(test)]
        tests::before_launch()?;
        let mut worker = core::ptr::null_mut();
        // SAFETY: stable preallocated slots, Darwin attributes and stack remain
        // alive until join. UnsafeCell permits writes to this unique Job while
        // coordinator only holds shared slot references. F is Send and borrowed
        // exclusively until all joins; Group Drop covers partial-launch/unwind.
        let code = unsafe {
            pthread_create(
                &mut worker,
                &*slot.attributes.0,
                enter::<&mut F>,
                slot.job.get().cast(),
            )
        };
        if code != 0 {
            return Err(Error::ThreadStart);
        }
        // No allocation, destructor or fallible hook before ownership is recorded.
        slot.worker.set(Some(worker));
        #[cfg(test)]
        tests::after_launch();
    }
    group.join_all();
    for slot in &group.slots {
        // SAFETY: every worker joined, so no native writer remains. Only public
        // completion flags are inspected; no populated hash state is moved.
        let job = unsafe { &*slot.job.get() };
        if job.panicked {
            return Err(Error::WorkerPanicked);
        }
        if !job.completed {
            return Err(Error::WorkerProtocol);
        }
    }
    Ok(())
}
