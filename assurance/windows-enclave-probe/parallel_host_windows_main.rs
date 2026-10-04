//! Public-fixture native driver only; no shipping development-mode constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Bounds,
    Image,
    Signature,
    Platform,
    Busy,
    Quarantined,
    Protocol,
    Release,
}
#[allow(dead_code)]
mod policy;
use policy::ImagePolicy;
mod image;
#[allow(dead_code)]
#[path = "parallel_host_scheduler.rs"]
mod scheduler;
mod protocol {
    pub(crate) fn inside(base: usize, bytes: usize, address: usize, length: usize) -> bool {
        address
            .checked_sub(base)
            .and_then(|offset| offset.checked_add(length))
            .is_some_and(|end| end <= bytes)
    }
    pub(crate) fn disjoint(a: usize, n: usize, b: usize, m: usize) -> bool {
        if a <= b {
            b.checked_sub(a).is_some_and(|d| d >= n)
        } else {
            a.checked_sub(b).is_some_and(|d| d >= m)
        }
    }
}
mod adapter;
include!("host_policy.rs");
// All bytes in these cases are public oracle fixtures, not application secrets.
struct Case {
    identity: u64,
    block: u64,
    bits: u64,
    custom_bits: u64,
    output_bits: u64,
    message: &'static [u8],
    custom: &'static [u8],
    expected: &'static [u8],
    fault: u8,
}
include!("host_vectors.rs");

fn run() -> Result<(), Error> {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().ok_or(Error::Bounds)?;
    let index = args
        .next()
        .and_then(|v| v.to_str().and_then(|v| v.parse::<usize>().ok()))
        .ok_or(Error::Bounds)?;
    if args.next().is_some() {
        return Err(Error::Bounds);
    }
    let case = CASES.get(index).ok_or(Error::Bounds)?;
    // The development-signed file MUST reject production opening first.
    match adapter::Enclave::open(std::path::Path::new(&path), &POLICY, false) {
        Err(Error::Signature) => (),
        Err(error) => return Err(error),
        Ok(_) => return Err(Error::Signature),
    }
    let mut owner = adapter::Enclave::open(std::path::Path::new(&path), &POLICY, true)?;
    adapter::budget()?;
    let mut output = vec![0xa5; case.expected.len().max(1)];
    let header = [
        0x4252594e50485749,
        1,
        case.identity,
        case.block,
        case.bits,
        case.custom_bits,
        case.output_bits,
        if case.bits == 0 {
            0
        } else {
            case.message.as_ptr() as u64
        },
        if case.custom_bits == 0 {
            0
        } else {
            case.custom.as_ptr() as u64
        },
        1,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let result = owner.execute(&header, &mut output, case.fault);
    owner.settled()?; // failure cases must still prove cleanup, not just return Err
    if case.fault == 0 {
        result?;
        if output.get(..case.expected.len()) != Some(case.expected) {
            return Err(Error::Protocol);
        }
    } else if result.is_ok() || output.iter().any(|&b| b != 0xa5) {
        return Err(Error::Protocol);
    }
    if owner.execute(&header, &mut output, 0) != Err(Error::Quarantined) {
        return Err(Error::Protocol);
    }
    drop(owner); // confirmed OS teardown before reporting success
    println!("RUST_SCOPED_VBS: case={index}; fault={}; PASS", case.fault);
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("RUST_SCOPED_VBS: {error:?}");
        std::process::exit(1);
    }
}
