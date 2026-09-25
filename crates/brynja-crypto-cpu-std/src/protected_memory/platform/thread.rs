//! Synchronous scoped pthread ownership for the Linux GNU adapter only.
#![allow(unsafe_code)]
use super::{Error, Mapping};
use core::ffi::{c_int, c_ulong, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

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
    // SAFETY: run creates exactly one worker with this pointer to a live Job<F>.
    // F is Send, and run neither touches nor drops it before successful join.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Init,
    Stack,
    Create,
    Destroy,
}
fn call(step: Step, operation: impl FnOnce() -> c_int) -> c_int {
    #[cfg(test)]
    if tests::fail(step) {
        return 11;
    }
    let _ = step;
    operation()
}

fn join(worker: c_ulong) -> c_int {
    #[cfg(test)]
    if tests::fail_join() {
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
