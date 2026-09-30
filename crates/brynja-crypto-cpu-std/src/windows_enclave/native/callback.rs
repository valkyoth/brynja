//! Private OS residency callback. Never receives a Rust reference from enclave.
#![allow(unsafe_code)]
use super::{
    super::{
        Error,
        protocol::{Context, disjoint, inside},
    },
    sys,
};
use std::cell::RefCell;
std::thread_local! { static CURRENT: RefCell<Option<Context>> = const { RefCell::new(None) }; }

pub(super) fn install(context: Context) -> Result<(), Error> {
    CURRENT
        .try_with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| Error::Busy)?;
            if slot.is_some() {
                return Err(Error::Busy);
            }
            *slot = Some(context);
            Ok(())
        })
        .map_err(|_| Error::Platform)?
}
pub(super) fn take() -> Result<Context, Error> {
    CURRENT
        .try_with(|slot| {
            slot.try_borrow_mut()
                .map_err(|_| Error::Protocol)?
                .take()
                .ok_or(Error::Protocol)
        })
        .map_err(|_| Error::Platform)?
}
pub(super) fn address() -> usize {
    callback as *const () as usize
}
extern "system" fn callback(parameter: usize) -> usize {
    CURRENT
        .try_with(|slot| {
            let Ok(mut current) = slot.try_borrow_mut() else {
                return 0;
            };
            let Some(call) = current.as_mut() else {
                return 0;
            };
            if call.error {
                return 0;
            }
            if process(call, parameter) {
                1
            } else {
                call.error = true;
                0
            }
        })
        .unwrap_or(0)
}
fn process(call: &mut Context, parameter: usize) -> bool {
    let event = parameter & 15;
    let address = parameter & !15;
    let Some(guard) = address.checked_sub(4096) else {
        return false;
    };
    if address & 4095 != 0 {
        return false;
    }
    if event == 0 {
        if call.phase != 0
            || !inside(call.base, 0x10000000, guard, 73728)
            || !sys::pages(address, 16, false)
        {
            return false;
        }
        call.low = address;
        if !sys::lock(address, 65536, true) {
            return false;
        }
        call.locked = true;
        if !sys::pages(address, 16, true) {
            return false;
        }
        call.phase = 1;
        return true;
    }
    if call.phase != 1 || !call.locked {
        return false;
    }
    if event == 1 {
        if address != call.low
            || !sys::pages(address, 16, true)
            || !sys::lock(address, 65536, false)
        {
            return false;
        }
        call.locked = false;
        call.phase = 2;
        return true;
    }
    let Some(stack_guard) = call.low.checked_sub(4096) else {
        return false;
    };
    if !inside(call.base, 0x10000000, guard, 12288) || !disjoint(guard, 12288, stack_guard, 73728) {
        return false;
    }
    if event == 8 {
        if call.operation != 0
            || call.slot_phase != 0
            || call.slot_locked
            || !sys::pages(address, 1, false)
        {
            return false;
        }
        call.slot = address;
        if !sys::lock(address, 4096, true) {
            return false;
        }
        call.slot_locked = true;
        if !sys::pages(address, 1, true) {
            return false;
        }
        call.slot_phase = 1;
        return true;
    }
    if address != call.slot || !call.slot_locked || !sys::pages(address, 1, true) {
        return false;
    }
    if event == 9 && call.operation != 0 && call.slot_phase == 0 {
        call.slot_phase = 1;
        return true;
    }
    if event == 10 && call.operation == 3 && call.slot_phase == 1 {
        if !sys::lock(address, 4096, false) {
            return false;
        }
        call.slot_locked = false;
        call.slot_phase = 2;
        return true;
    }
    false
}
