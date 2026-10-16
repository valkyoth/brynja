//! Synchronous Darwin pthread ownership; library-only borrowed worker captures.
#![allow(unsafe_code)]
use super::{Error, Mapping, Step, fault};
use core::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};

mod group;
pub(super) use group::run as run_group;

// Darwin _opaque_pthread_attr_t: long signature, 56 opaque bytes on LP64.
// Not GNU's union. Native SDK ABI fixture verifies size and alignment.
#[repr(C)]
struct Attr {
    signature: i64,
    opaque: [u8; 56],
}
const _: () = assert!(core::mem::size_of::<Attr>() == 64);
const _: () = assert!(core::mem::align_of::<Attr>() == 8);
// Allocate public attribute metadata before initialization. Moving this owner
// (including into a group Vec) never copies/moves an initialized pthread_attr_t.
struct Attributes(Box<Attr>);
impl Attributes {
    fn new(mapping: &Mapping) -> Result<Self, Error> {
        let mut raw = Box::new(Attr {
            signature: 0,
            opaque: [0; 56],
        });
        fault(Step::Init, Error::ThreadAttributes)?;
        super::check(
            // SAFETY: exclusive correctly sized/aligned Darwin pthread attribute.
            unsafe { pthread_attr_init(&mut *raw) },
            Error::ThreadAttributes,
        )?;
        let mut attr = Self(raw);
        fault(Step::Stack, Error::ThreadAttributes)?;
        super::check(
            // SAFETY: admitted, guarded, page-aligned RW stack outlives worker join.
            // pthread uses the supplied payload; guard pages remain outside it.
            unsafe {
                pthread_attr_setstack(
                    &mut *attr.0,
                    mapping.data.as_ptr().cast(),
                    mapping.layout.payload,
                )
            },
            Error::ThreadAttributes,
        )?;
        Ok(attr)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if fault(Step::Destroy, Error::ThreadAttributes).is_err() {
            std::process::abort();
        }
        // SAFETY: initialized exclusive attribute; create copies its contents.
        if unsafe { pthread_attr_destroy(&mut *self.0) } != 0 {
            std::process::abort();
        }
    }
}
struct Job<F> {
    work: Option<F>,
    completed: bool,
    panicked: bool,
}
extern "C" fn enter<F: FnOnce() + Send>(argument: *mut c_void) -> *mut c_void {
    // SAFETY: run holds this stable Job and its Send closure until successful
    // join; caller does not access it while the worker owns the borrow.
    let job = unsafe { &mut *argument.cast::<Job<F>>() };
    let result = catch_unwind(AssertUnwindSafe(|| {
        if let Some(work) = job.work.take() {
            work();
            job.completed = true;
        }
    }));
    if let Err(payload) = result {
        job.panicked = true;
        // The payload is destroyed on the worker; destructor panic aborts at
        // this non-unwinding ABI. OS/panic-hook allocations are not owned here.
        drop(payload);
    }
    core::ptr::null_mut()
}
pub(super) fn run<F: FnOnce() + Send>(mapping: &mut Mapping, work: F) -> Result<(), Error> {
    if mapping.foreign()
        || !mapping.admitted
        || mapping.base.is_none()
        || mapping.layout.payload < 65536
    {
        return Err(Error::ThreadAttributes);
    }
    let attr = Attributes::new(mapping)?;
    let mut job = Job {
        work: Some(work),
        completed: false,
        panicked: false,
    };
    let mut worker = core::ptr::null_mut();
    if fault(Step::Create, Error::ThreadStart).is_err() {
        mapping.clear();
        return Err(Error::ThreadStart);
    }
    // SAFETY: attr references live owned stack; Job remains stable until join.
    // Successful creation is followed by join with no fallible allocation/hook.
    let code = unsafe {
        pthread_create(
            &mut worker,
            &*attr.0,
            enter::<F>,
            core::ptr::from_mut(&mut job).cast(),
        )
    };
    if code != 0 {
        mapping.clear();
        return Err(Error::ThreadStart);
    }
    // Test instrumentation uses a pre-created TLS cell, without recording Vec
    // events between create and join. A simulated failure aborts in a child.
    #[cfg(test)]
    if super::tests::join_fails() {
        std::process::abort();
    }
    // SAFETY: worker is the successful pthread_create handle, joined exactly
    // once. A join error cannot return/drop borrowed state while it is active.
    if unsafe { pthread_join(worker, core::ptr::null_mut()) } != 0 {
        std::process::abort();
    }
    #[cfg(test)]
    let _ = fault(Step::Join, Error::WorkerProtocol);
    mapping.clear();
    if job.panicked {
        Err(Error::WorkerPanicked)
    } else if !job.completed {
        Err(Error::WorkerProtocol)
    } else {
        Ok(())
    }
}
unsafe extern "C" {
    fn pthread_attr_init(attr: *mut Attr) -> i32;
    fn pthread_attr_destroy(attr: *mut Attr) -> i32;
    fn pthread_attr_setstack(attr: *mut Attr, address: *mut c_void, bytes: usize) -> i32;
    fn pthread_create(
        thread: *mut *mut c_void,
        attr: *const Attr,
        start: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> i32;
    fn pthread_join(thread: *mut c_void, result: *mut *mut c_void) -> i32;
}

#[test]
fn initialized_attribute_address_survives_owner_moves() -> Result<(), Error> {
    let mapping = Mapping::new(262144, 1048576)?;
    let attributes = Attributes::new(&mapping)?;
    let address = core::ptr::from_ref(&*attributes.0);
    let mut owners = Vec::new();
    owners.push(attributes);
    let moved = owners.pop().ok_or(Error::Invariant)?;
    assert_eq!(address, core::ptr::from_ref(&*moved.0));
    Ok(())
}
