//! Safe internal host callback routing. No pointer dereference or host secret copy.
#![allow(unsafe_code)]
use super::super::sys;
use super::{Error, scheduler::Scheduler};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

#[derive(Default, Clone, Copy)]
struct Frame {
    low: usize,
    phase: u8,
    locked: bool,
    admitted: bool,
    verified: bool,
}
#[derive(Default)]
pub(super) struct Frames {
    slots: [Frame; 5],
    pub(super) failed: bool,
}
pub(super) struct Shared {
    pub(super) base: usize,
    pub(super) root: usize,
    pub(super) leaf: usize,
    pub(super) query: usize,
    pub(super) state: usize,
    pub(super) register: usize,
    pub(super) output: usize,
    pub(super) frames: Mutex<Frames>,
}
pub(super) struct Context {
    pub(super) shared: Arc<Shared>,
    pub(super) lane: usize,
    pub(super) scheduler: Option<Scheduler>,
    pub(super) generation: usize,
}
std::thread_local! { static CURRENT: RefCell<Option<Context>> = const { RefCell::new(None) }; }
// Dropping this guard on another thread would clear the wrong TLS slot.
pub(super) struct Installed(core::marker::PhantomData<*mut ()>);
impl Installed {
    pub(super) fn new(context: Context) -> Result<Self, Error> {
        CURRENT
            .try_with(|cell| {
                let mut slot = cell.try_borrow_mut().map_err(|_| Error::Busy)?;
                if slot.is_some() {
                    return Err(Error::Busy);
                }
                *slot = Some(context);
                Ok(Self(core::marker::PhantomData))
            })
            .map_err(|_| Error::Platform)?
    }
    pub(super) fn take(self) -> Result<Context, Error> {
        CURRENT
            .try_with(|cell| {
                cell.try_borrow_mut()
                    .map_err(|_| Error::Busy)?
                    .take()
                    .ok_or(Error::Protocol)
            })
            .map_err(|_| Error::Platform)?
    }
}
impl Drop for Installed {
    fn drop(&mut self) {
        let result = CURRENT.try_with(|cell| {
            cell.try_borrow_mut().map(|mut slot| {
                *slot = None;
            })
        });
        if !matches!(result, Ok(Ok(()))) {
            std::process::abort();
        }
    }
}
pub(super) fn address() -> usize {
    callback as *const () as usize
}
extern "system" fn callback(word: usize) -> usize {
    // Unwinding must not cross CallEnclave. Frame cleanup notifications remain
    // processable after dispatch/admission failure; failure is latched separately.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CURRENT
            .try_with(|cell| {
                let mut current = cell.try_borrow_mut().map_err(|_| Error::Busy)?;
                let context = current.as_mut().ok_or(Error::Protocol)?;
                let result = context.process(word);
                if result.is_err() {
                    context
                        .shared
                        .frames
                        .lock()
                        .map_err(|_| Error::Protocol)?
                        .failed = true;
                }
                result
            })
            .map_err(|_| Error::Platform)?
    }));
    if matches!(result, Ok(Ok(()))) { 1 } else { 0 }
}

impl Shared {
    pub(super) fn settled(&self) -> Result<(), Error> {
        let frames = self.frames.lock().map_err(|_| Error::Protocol)?;
        if frames
            .slots
            .iter()
            .any(|f| f.locked || (f.phase != 0 && (f.phase != 2 || !f.verified)))
        {
            return Err(Error::Release);
        }
        Ok(())
    }
    fn window(&self, lane: usize, low: usize, event: usize) -> Result<(), Error> {
        let mut frames = self.frames.lock().map_err(|_| Error::Protocol)?;
        let guard = low.checked_sub(4096).ok_or(Error::Bounds)?;
        if low & 4095 != 0 || !super::super::protocol::inside(self.base, 0x10000000, guard, 73728) {
            return Err(Error::Bounds);
        }
        if event == 0 {
            if frames.slots.iter().enumerate().any(|(i, f)| {
                i != lane
                    && f.phase != 0
                    && !super::super::protocol::disjoint(
                        guard,
                        73728,
                        f.low.saturating_sub(4096),
                        73728,
                    )
            }) {
                return Err(Error::Protocol);
            }
            let frame = frames.slots.get_mut(lane).ok_or(Error::Protocol)?;
            if frame.phase != 0 {
                return Err(Error::Protocol);
            }
            frame.low = low;
            frame.phase = 1;
            if !sys::pages(low, 16, false) || !sys::lock(low, 65536, true) {
                return Err(Error::Platform);
            }
            frame.locked = true;
            if !sys::pages(low, 16, true) {
                return Err(Error::Platform);
            }
            frame.admitted = true;
            Ok(())
        } else {
            let frame = frames.slots.get_mut(lane).ok_or(Error::Protocol)?;
            if event != 1 || frame.phase != 1 || frame.low != low {
                return Err(Error::Protocol);
            }
            if frame.locked {
                if !sys::pages(low, 16, true) || !sys::lock(low, 65536, false) {
                    return Err(Error::Release);
                }
                frame.locked = false;
            }
            if !sys::pages(low, 16, false) {
                return Err(Error::Release);
            }
            frame.phase = 2;
            Ok(())
        }
    }
    pub(super) fn verify(&self, generation: usize, lane: usize) -> Result<(), Error> {
        let mut values = [0; 8];
        for (field, value) in values.iter_mut().enumerate() {
            let index = generation
                .checked_mul(256)
                .and_then(|n| {
                    lane.checked_mul(16)
                        .and_then(|offset| n.checked_add(offset))
                })
                .and_then(|n| n.checked_add(field))
                .ok_or(Error::Bounds)?;
            *value = sys::call(self.query, index)?;
        }
        let mut frames = self.frames.lock().map_err(|_| Error::Protocol)?;
        let frame = frames.slots.get_mut(lane).ok_or(Error::Protocol)?;
        if frame.phase != 2
            || frame.locked
            || values[0] != frame.low
            || values[1] != frame.low.checked_add(65536).ok_or(Error::Bounds)?
            || values[3] != usize::from(frame.admitted)
            || values[4] != 1
            || values[5] != 1
            || values[6] != usize::from(frame.admitted)
            || values[7] != 0
            || (frame.admitted && !super::super::protocol::inside(frame.low, 65536, values[2], 16))
            || (!frame.admitted && values[2] != 0)
        {
            return Err(Error::Protocol);
        }
        frame.verified = true;
        Ok(())
    }
}
impl Context {
    fn process(&mut self, word: usize) -> Result<(), Error> {
        let low = word & !4095;
        let lane = (word & 4095) >> 4;
        let event = word & 15;
        if lane != self.lane || lane > 4 {
            return Err(Error::Protocol);
        }
        if event <= 1 {
            return self.shared.window(lane, low, event);
        }
        let root = *self
            .shared
            .frames
            .lock()
            .map_err(|_| Error::Protocol)?
            .slots
            .get(4)
            .ok_or(Error::Protocol)?;
        if lane != 4 || low != root.low || root.phase != 1 || !root.locked || !root.admitted {
            return Err(Error::Protocol);
        }
        let scheduler = self.scheduler.as_mut().ok_or(Error::Protocol)?;
        if event == 2 {
            let native = sys::call(self.shared.state, 0)? as u64;
            self.generation = usize::try_from(native >> 32).map_err(|_| Error::Bounds)?;
            {
                let mut frames = self.shared.frames.lock().map_err(|_| Error::Protocol)?;
                for frame in frames.slots.iter_mut().take(4) {
                    if frame.locked || (frame.phase != 0 && (frame.phase != 2 || !frame.verified)) {
                        return Err(Error::Protocol);
                    }
                    *frame = Frame::default();
                }
            }
            let shared = &self.shared;
            scheduler
                .dispatch(native, &|work| {
                    let word = usize::try_from(work.word())
                        .map_err(|_| super::scheduler::Error::Bounds)?;
                    let guard = Installed::new(Context {
                        shared: Arc::clone(shared),
                        lane: word % 16,
                        scheduler: None,
                        generation: word / 16,
                    })
                    .map_err(|_| super::scheduler::Error::Worker)?;
                    let result = sys::call(shared.leaf, word);
                    drop(guard);
                    if result == Ok(1) {
                        Ok(())
                    } else {
                        Err(super::scheduler::Error::Worker)
                    }
                })
                .map_err(|_| Error::Protocol)
        } else if event == 3 {
            scheduler.closed().map_err(|_| Error::Protocol)
        } else if event == 4 {
            // Validate cleanup even after failed dispatch; do not suppress unlock
            // notifications because the computation has become terminal.
            let lanes = (sys::call(self.shared.state, 0)? >> 12 & 15).count_ones() as usize;
            for lane in 0..lanes {
                self.shared.verify(self.generation, lane)?;
            }
            let native = sys::call(self.shared.state, 0)? as u64;
            scheduler.complete(native).map_err(|_| Error::Protocol)
        } else {
            Err(Error::Protocol)
        }
    }
}
