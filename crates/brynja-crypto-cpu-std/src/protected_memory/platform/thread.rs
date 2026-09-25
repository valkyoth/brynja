//! Synchronous scoped pthread ownership for the Linux GNU adapter only.
#![allow(unsafe_code)]
use super::{Error, Mapping};
use core::ffi::{c_int, c_ulong, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[cfg(test)]
mod group_tests;
#[cfg(test)]
mod tests;

// GNU libc's public pthread_attr_t union has long alignment and the following
// architecture-specific sizes. This module is not compiled for other ABIs.
#[cfg(target_arch = "x86_64")]
const ATTR_WORDS: usize = 7;
#[cfg(target_arch = "aarch64")]
const ATTR_WORDS: usize = 8;
#[repr(C)]
struct Attr {
    words: [c_ulong; ATTR_WORDS],
}
const _: () = assert!(core::mem::align_of::<Attr>() == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Attr>() == 56);
#[cfg(target_arch = "aarch64")]
const _: () = assert!(core::mem::size_of::<Attr>() == 64);

struct Attributes(Attr);
impl Attributes {
    fn new(mapping: &Mapping) -> Result<Self, Error> {
        let mut raw = Attr {
            words: [0; ATTR_WORDS],
        };
        let initialized = call(Step::Init, || {
            // SAFETY: raw has GNU libc's exact size/alignment and is exclusively
            // writable. Only success initializes a destroyable pthread attribute.
            unsafe { pthread_attr_init(&mut raw) }
        });
        if initialized != 0 {
            return Err(Error::ThreadAttributes);
        }
        let mut owner = Self(raw);
        let configured = call(Step::Stack, || {
            // SAFETY: the mapping is live, guarded, resident, read/write and page
            // aligned. It outlives this attribute and every worker using it. The
            // runtime ignores its default guard size for a caller-supplied stack.
            unsafe {
                pthread_attr_setstack(
                    &mut owner.0,
                    mapping.data.as_ptr().cast(),
                    mapping.layout.payload,
                )
            }
        });
        if configured != 0 {
            return Err(Error::ThreadAttributes);
        }
        Ok(owner)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        let result = call(Step::Destroy, || {
            // SAFETY: initialization succeeded; no operation can alias these
            // attributes. pthread_create copies attributes rather than retaining
            // this address. Unexpected destruction failure cannot claim success.
            unsafe { pthread_attr_destroy(&mut self.0) }
        });
        if result != 0 {
            std::process::abort();
        }
        #[cfg(test)]
        tests::destroyed();
    }
}

struct Job<F> {
    work: Option<F>,
    completed: bool,
    panicked: bool,
}

extern "C" fn enter<F: FnOnce() + Send>(argument: *mut c_void) -> *mut c_void {
    // SAFETY: run/run_group create one worker with this live, stable Job<F>.
    // F is Send, and the caller neither accesses nor drops it before join.
    // No callback/Job reference escapes this synchronous invocation.
    let job = unsafe { &mut *argument.cast::<Job<F>>() };
    let result = catch_unwind(AssertUnwindSafe(|| {
        if let Some(work) = job.work.take() {
            work();
            job.completed = true;
        }
    }));
    if let Err(payload) = result {
        job.panicked = true;
        // Destroy the payload on the worker, not the caller's ordinary stack.
        // A panicking payload destructor hits this non-unwinding ABI and aborts.
        drop(payload);
    }
    core::ptr::null_mut()
}

pub(super) fn run<F: FnOnce() + Send>(mapping: &mut Mapping, work: F) -> Result<(), Error> {
    if !mapping.admitted || mapping.base.is_none() || mapping.layout.payload < 65536 {
        return Err(Error::ThreadAttributes);
    }
    let attributes = Attributes::new(mapping)?;
    let mut job = Job {
        work: Some(work),
        completed: false,
        panicked: false,
    };
    let mut worker: c_ulong = 0;
    let created = call(Step::Create, || {
        // SAFETY: the attribute owns a valid preacquired stack; argument points at
        // this live exclusive Job<F>, with Send captures. After successful creation
        // the only next fallible native action is join; failure aborts, never returns
        // with borrowed work live. The worker does not retain attributes or worker.
        unsafe {
            pthread_create(
                &mut worker,
                &attributes.0,
                enter::<F>,
                core::ptr::from_mut(&mut job).cast(),
            )
        }
    });
    if created != 0 {
        mapping.clear();
        return Err(Error::ThreadStart);
    }
    // No allocation, callback, assertion, destructor or unwinding hook between
    // successful create and join. The cfg-test failure is exercised in a child.
    if join(worker) != 0 {
        std::process::abort();
    }
    #[cfg(test)]
    tests::joined();
    // Native join establishes termination (including thread-local destructors)
    // and synchronizes access to job. Clearing occurs on the caller's stack.
    mapping.clear();
    if job.panicked {
        Err(Error::WorkerPanicked)
    } else if !job.completed {
        Err(Error::WorkerProtocol)
    } else {
        Ok(())
    }
}

// Native workers mutate only their own UnsafeCell<Job>. The coordinator accesses
// handles/attributes through shared slot references until *all* joins complete.
// Vec capacity is finalized before any job address is passed to pthread_create.
struct Slot<'mapping, 'work, F> {
    mapping: &'mapping mut Mapping,
    attributes: Attributes,
    job: core::cell::UnsafeCell<Job<&'work mut F>>,
    worker: core::cell::Cell<Option<c_ulong>>,
}
struct Group<'mapping, 'work, F> {
    slots: Vec<Slot<'mapping, 'work, F>>,
}
impl<F> Group<'_, '_, F> {
    fn join_all(&mut self) {
        for slot in &self.slots {
            if let Some(worker) = slot.worker.get() {
                if join(worker) != 0 {
                    std::process::abort();
                }
                slot.worker.set(None);
                #[cfg(test)]
                tests::joined();
            }
        }
        // Only now may exclusive slot/mapping borrows be recreated. Native TLS
        // destructors have finished; no worker can access Job or stack storage.
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

pub(super) fn run_group<'a, F: FnMut() + Send>(
    mappings: impl ExactSizeIterator<Item = &'a mut Mapping>,
    work: &mut [F],
) -> Result<(), Error> {
    let count = mappings.len();
    if count == 0 || count != work.len() {
        return Err(Error::InvalidSize);
    }
    if count > 64 {
        return Err(Error::ResourceLimit);
    }
    let mut group = Group { slots: Vec::new() };
    group
        .slots
        .try_reserve_exact(count)
        .map_err(|_| Error::ResourceLimit)?;
    // Prepare every attribute before starting anything; failure unwinds only
    // inactive mappings and callbacks. No vector resize/allocation after launch.
    for (mapping, work) in mappings.zip(work) {
        if !mapping.admitted || mapping.base.is_none() || mapping.layout.payload < 65536 {
            return Err(Error::ThreadAttributes);
        }
        let attributes = Attributes::new(mapping)?;
        group.slots.push(Slot {
            mapping,
            attributes,
            job: core::cell::UnsafeCell::new(Job {
                work: Some(work),
                completed: false,
                panicked: false,
            }),
            worker: core::cell::Cell::new(None),
        });
    }
    for slot in &group.slots {
        let mut worker: c_ulong = 0;
        let created = call(Step::Create, || {
            // SAFETY: all slots are stable in a preallocated vector. This pointer
            // derives from UnsafeCell, allowing worker writes while the coordinator
            // holds shared slots. The unique callback borrow is Send and is never
            // read again until join. Group Drop joins on every returning/unwinding
            // path; no user-visible handle can detach or forget that obligation.
            unsafe {
                pthread_create(
                    &mut worker,
                    &slot.attributes.0,
                    enter::<&mut F>,
                    slot.job.get().cast(),
                )
            }
        });
        if created != 0 {
            return Err(Error::ThreadStart);
        }
        // No fallible action between successful creation and recording ownership.
        slot.worker.set(Some(worker));
        #[cfg(test)]
        group_tests::launched();
    }
    group.join_all();
    for slot in &group.slots {
        // SAFETY: every started worker joined; no native access remains. Reading
        // public completion flags does not expose or move callback/secret results.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Init,
    Stack,
    Create,
    Destroy,
}
fn call(step: Step, operation: impl FnOnce() -> c_int) -> c_int {
    #[cfg(test)]
    if tests::fail(step) || group_tests::fail(step) {
        return 11;
    }
    let _ = step;
    operation()
}

fn join(worker: c_ulong) -> c_int {
    #[cfg(test)]
    if tests::fail_join() || group_tests::fail_join() {
        return 22;
    }
    // SAFETY: run is the sole joiner for this successfully created joinable
    // worker. Its private ID is never exposed or detached. Null retval discards
    // the constant null return, not any secret-bearing Rust result.
    unsafe { pthread_join(worker, core::ptr::null_mut()) }
}

unsafe extern "C" {
    fn pthread_attr_init(attr: *mut Attr) -> c_int;
    fn pthread_attr_destroy(attr: *mut Attr) -> c_int;
    fn pthread_attr_setstack(attr: *mut Attr, address: *mut c_void, bytes: usize) -> c_int;
    fn pthread_create(
        thread: *mut c_ulong,
        attr: *const Attr,
        start: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> c_int;
    fn pthread_join(thread: c_ulong, result: *mut *mut c_void) -> c_int;
}
