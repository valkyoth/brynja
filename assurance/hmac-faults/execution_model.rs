//! Private-copy witness for the real accelerated HMAC composition.
//! Not a CPU implementation, hash oracle, or compiler-erasure proof.
extern crate std;

use super::{
    Hmac, Kernel,
    adapter::Adapter,
    backends::{Backend, Source},
};
use crate::{Algorithm, Error, Sha2BitString, algorithms::sealed};
use std::{
    cell::RefCell,
    panic::{AssertUnwindSafe, catch_unwind},
    vec::Vec,
};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    None,
    Error,
    Unwind,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Event {
    Admit,
    Update,
    Finish,
    Written,
}

struct Trace {
    events: Vec<Event>,
    fault: Fault,
    fail_at: usize,
    created: usize,
    dropped: usize,
    live: usize,
    expected: usize,
    kernel: Kernel,
    invalid: bool,
}

std::thread_local! {
    static TRACE: RefCell<Trace> = const { RefCell::new(Trace {
        events: Vec::new(), fault: Fault::None, fail_at: 0, created: 0,
        dropped: 0, live: 0, expected: 0, kernel: Kernel::ArmSha256, invalid: false,
    }) };
}

fn reset(key: &[u8], kernel: Kernel, fail_at: usize, fault: Fault) {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        assert_eq!(trace.live, 0, "previous case leaked an owner");
        *trace = Trace {
            events: Vec::new(),
            fault,
            fail_at,
            created: 0,
            dropped: 0,
            live: 0,
            expected: if key.len() > 64 { 3 } else { 2 },
            kernel,
            invalid: false,
        };
    });
}

fn checkpoint(event: Event) -> Result<(), Error> {
    let fault = TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        if event != Event::Admit {
            assert_eq!(
                trace.created, trace.expected,
                "key processing before full admission"
            );
        }
        trace.events.push(event);
        if trace.events.len() == trace.fail_at {
            trace.fault
        } else {
            Fault::None
        }
    });
    assert_ne!(fault, Fault::Unwind, "injected accelerated-owner unwind");
    if fault == Fault::Error {
        Err(Error::ExecutionFailed)
    } else {
        Ok(())
    }
}

fn closed() -> Vec<Event> {
    TRACE.with(|trace| {
        let trace = trace.borrow();
        assert_eq!(trace.live, 0, "terminal operation retained a hash owner");
        assert_eq!(trace.created, trace.dropped);
        trace.events.clone()
    })
}

struct Owner {
    bytes: [u8; 32],
    kernel: Kernel,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.bytes.fill(0);
        TRACE.with(|trace| {
            let mut trace = trace.borrow_mut();
            assert!(trace.live > 0);
            trace.live -= 1;
            trace.dropped += 1;
        });
    }
}

enum Synthetic {}

impl Algorithm for Synthetic {
    const BLOCK_BYTES: usize = 64;
    const TAG_BYTES: usize = 32;
}

// The real CPU Adapter must never call an ordinary constructor or operation.
impl sealed::Hash for Synthetic {
    type State = ();
    type FinalInput<'a> = Sha2BitString<'a>;
    fn validate() -> Result<(), Error> {
        if TRACE.with(|trace| trace.borrow().invalid) {
            Err(Error::AlgorithmParameter)
        } else {
            Ok(())
        }
    }
    fn start() -> Result<(), Error> {
        panic!("portable fallback")
    }
    fn update(_: &mut (), _: &[u8]) -> Result<(), Error> {
        panic!("portable fallback")
    }
    fn finish(
        _: (),
        _: &mut [u8],
        _: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        panic!("portable fallback")
    }
    fn finish_bits(
        _: (),
        _: Sha2BitString<'_>,
        _: &mut [u8],
        _: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        panic!("portable fallback")
    }
}

impl<'a> Backend<'a> for Synthetic {
    type CpuState = Owner;
    fn create(source: Source<'a>) -> Result<Owner, Error> {
        let Source::Synthetic(kernel) = source else {
            panic!("unexpected real authority")
        };
        checkpoint(Event::Admit)?;
        TRACE.with(|trace| {
            let mut trace = trace.borrow_mut();
            assert_eq!(*kernel, trace.kernel);
            trace.created += 1;
            trace.live += 1;
        });
        Ok(Owner {
            bytes: [0xa5; 32],
            kernel: *kernel,
        })
    }
    fn update_cpu(state: &mut Owner, input: &[u8]) -> Result<(), Error> {
        checkpoint(Event::Update)?;
        TRACE.with(|trace| assert_eq!(state.kernel, trace.borrow().kernel));
        if input == b"atomic length rejection" {
            return Err(Error::MessageTooLong);
        }
        for (index, byte) in input.iter().enumerate() {
            state.bytes[index % 32] ^= byte;
        }
        Ok(())
    }
    fn finish_cpu(
        mut state: Owner,
        input: Option<Sha2BitString<'_>>,
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if let Some(bits) = input {
            Self::update_cpu(&mut state, bits.as_bytes())?;
        }
        checkpoint(Event::Finish)?;
        TRACE.with(|trace| assert_eq!(state.kernel, trace.borrow().kernel));
        output.copy_from_slice(&state.bytes);
        checkpoint(Event::Written)?;
        consume(output)
    }
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Public,
    Secret,
    Verify,
    BitPublic,
    BitSecret,
    BitVerify,
    Cancel,
}

const MODES: [Mode; 7] = [
    Mode::Public,
    Mode::Secret,
    Mode::Verify,
    Mode::BitPublic,
    Mode::BitSecret,
    Mode::BitVerify,
    Mode::Cancel,
];

fn finalize(mac: Hmac<'_, Synthetic>, mode: Mode, output: &mut [u8]) -> Result<(), Error> {
    let bits = Sha2BitString::new(&[0x80], 1).unwrap();
    match mode {
        Mode::Public => {
            let _ = mac.finalize_tag(output)?;
        }
        Mode::Secret => {
            drop(mac.finalize_secret(output)?);
        }
        Mode::Verify => {
            let _ = mac.verify(output)?;
        }
        Mode::BitPublic => {
            let _ = mac.finalize_bits_tag(bits, output)?;
        }
        Mode::BitSecret => {
            drop(mac.finalize_bits_secret(bits, output)?);
        }
        Mode::BitVerify => {
            let _ = mac.verify_bits(bits, output)?;
        }
        Mode::Cancel => mac.cancel(),
    }
    Ok(())
}

#[path = "execution_cases.rs"]
mod cases;
