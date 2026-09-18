//! Observe the public session boundary; not complete public-hash qualification.
#![no_std]
#![forbid(unsafe_code)]

use brynja_crypto_cpu::hardened_execution::KeccakSession;

/// Only pointers enter and a public success/failure status leaves this wrapper.
#[inline(never)]
pub extern "C" fn invoke(session: &mut KeccakSession<'_>, state: &mut [u8; 200]) -> u8 {
    u8::from(session.permute(state).is_err())
}
