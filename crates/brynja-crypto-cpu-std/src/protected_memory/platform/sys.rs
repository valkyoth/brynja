//! Only accepts mapping geometry owned by the parent module.
#![allow(unsafe_code)]
use super::super::Error;
use core::ptr::NonNull;

pub(super) const DONTDUMP: i32 = 16;
pub(super) const DONTFORK: i32 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Step {
    Map,
    Dump,
    Fork,
    Access,
    Lock,
    Unmap,
}

pub(super) fn page_size() -> i32 {
    super::getpagesize()
}

pub(super) fn map(len: usize) -> Result<NonNull<u8>, Error> {
    fault(Step::Map, Error::Mapping)?;
    // SAFETY: no existing address is replaced (no MAP_FIXED); the positive
    // checked length creates a dedicated anonymous PROT_NONE mapping. fd=-1
    // and offset=0 are the anonymous-map arguments for Linux GNU 64-bit.
    let raw = unsafe { super::mmap(core::ptr::null_mut(), len, 0, 0x02 | 0x20, -1, 0) };
    if raw as usize == usize::MAX {
        return Err(Error::Mapping);
    }
    if let Some(base) = NonNull::new(raw.cast::<u8>()) {
        return Ok(base);
    }
    // SAFETY: address zero was returned as a successful mapping, but cannot
    // back a Rust reference. Release it without constructing a NonNull/slice.
    let _ = unsafe { super::munmap(raw, len) };
    Err(Error::Mapping)
}

pub(super) fn advise(
    base: NonNull<u8>,
    len: usize,
    advice: i32,
    error: Error,
) -> Result<(), Error> {
    fault(
        if advice == DONTDUMP {
            Step::Dump
        } else {
            Step::Fork
        },
        error,
    )?;
    // SAFETY: parent supplies the complete live mapping and one of the two
    // non-discarding Linux advice values. Both require page-aligned addresses.
    result(
        unsafe { super::madvise(base.as_ptr().cast(), len, advice) },
        error,
    )
}

pub(super) fn access(base: NonNull<u8>, len: usize) -> Result<(), Error> {
    fault(Step::Access, Error::Access)?;
    // SAFETY: parent supplies exactly the page-aligned payload of its mapping;
    // PROT_READ|PROT_WRITE (3) excludes both guard pages and executable access.
    result(
        unsafe { super::mprotect(base.as_ptr().cast(), len, 3) },
        Error::Access,
    )
}

pub(super) fn lock(base: NonNull<u8>, len: usize) -> Result<(), Error> {
    fault(Step::Lock, Error::Lock)?;
    // SAFETY: this is the parent's live readable/writable payload. mlock only
    // changes page residency and does not access Rust values through aliases.
    result(
        unsafe { super::mlock(base.as_ptr().cast(), len) },
        Error::Lock,
    )
}

pub(super) fn unmap(base: NonNull<u8>, len: usize) -> Result<(), Error> {
    fault(Step::Unmap, Error::Release)?;
    // SAFETY: parent has cleared payload, holds no live loans and passes the
    // complete dedicated mapping. On success parent discards its pointer.
    result(
        unsafe { super::munmap(base.as_ptr().cast(), len) },
        Error::Release,
    )
}

fn result(code: i32, error: Error) -> Result<(), Error> {
    if code == 0 { Ok(()) } else { Err(error) }
}

fn fault(step: Step, error: Error) -> Result<(), Error> {
    #[cfg(test)]
    if hooks::hit(step) {
        return Err(error);
    }
    let _ = (step, error);
    Ok(())
}

#[cfg(test)]
pub(super) use hooks::observe_clear;
#[cfg(test)]
pub(super) mod hooks {
    use super::Step;
    use std::cell::RefCell;
    #[derive(Default)]
    struct State {
        fail: Option<Step>,
        events: Vec<Event>,
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(in super::super) enum Event {
        Call(Step),
        Clear(bool),
    }
    thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
    pub(in super::super) fn reset(fail: Option<Step>) {
        STATE.with(|s| {
            *s.borrow_mut() = State {
                fail,
                events: Vec::new(),
            }
        });
    }
    pub(in super::super) fn events() -> Vec<Event> {
        STATE.with(|s| s.borrow().events.clone())
    }
    pub(super) fn hit(step: Step) -> bool {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.events.push(Event::Call(step));
            if s.fail == Some(step) {
                s.fail = None;
                true
            } else {
                false
            }
        })
    }
    pub(in super::super) fn observe_clear(zero: bool) {
        STATE.with(|s| s.borrow_mut().events.push(Event::Clear(zero)));
    }
}
