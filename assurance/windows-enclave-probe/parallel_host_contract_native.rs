//! Appended only to the private public-oracle Windows executable.
use brynja_hash_sha2::PublicDeclassification;
use contract::{Algorithm, Input, Part, Plan, Session, State};
static FAULT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn part(bytes: &[u8], bits: u64) -> Result<Part<'_>, Error> {
    if bits.is_multiple_of(8) {
        return Part::bytes(bytes);
    }
    Part::bits(
        bytes,
        if bits == 0 {
            0
        } else {
            ((bits - 1) % 8 + 1) as u8
        },
    )
}
fn run() -> Result<(), Error> {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().ok_or(Error::Bounds)?;
    let index = args
        .next()
        .and_then(|v| v.to_str().and_then(|v| v.parse::<usize>().ok()))
        .ok_or(Error::Bounds)?;
    if args.next().is_some() || index >= 30 {
        return Err(Error::Bounds);
    }
    let case = CASES
        .get(if index >= 28 { 4 } else { index })
        .ok_or(Error::Bounds)?;
    let algorithm = match case.identity {
        1 => Algorithm::ParallelHash128,
        2 => Algorithm::ParallelHash256,
        3 => Algorithm::ParallelHashXof128,
        4 => Algorithm::ParallelHashXof256,
        _ => return Err(Error::Bounds),
    };
    let plan = Plan::new(
        algorithm,
        case.block,
        usize::try_from(case.output_bits).map_err(|_| Error::Bounds)?,
    )?;
    match Session::open_avx2(std::path::Path::new(&path), &POLICY) {
        Err(Error::Signature) => (),
        Err(error) => return Err(error),
        Ok(_) => return Err(Error::Signature),
    }
    let transport = adapter::Enclave::open(std::path::Path::new(&path), &POLICY, true)?;
    adapter::budget()?;
    let mut session = Session::from_transport(transport);
    let mut message = case.message.to_vec();
    let mut custom = case.custom.to_vec();
    if index == 28 {
        *message.last_mut().ok_or(Error::Bounds)? |= 128;
    }
    if index == 29 {
        *custom.last_mut().ok_or(Error::Bounds)? |= 128;
    }
    let input = || {
        Ok(Input::new(
            part(&message, case.bits)?,
            part(&custom, case.custom_bits)?,
        ))
    };
    let mut wrong = [0x66; 1025];
    if session.digest_public(
        plan,
        input()?,
        &mut wrong,
        PublicDeclassification::acknowledge(),
    ) != Err(Error::Bounds)
        || wrong != [0x66; 1025]
        || session.state() != State::Ready
    {
        return Err(Error::Protocol);
    }
    FAULT.store(case.fault, std::sync::atomic::Ordering::Relaxed);
    let mut output = vec![0xa5; plan.output_bytes() + 2];
    let expected_failure = case.fault != 0 || index >= 28;
    let result = session.digest_public(
        plan,
        input()?,
        output
            .get_mut(1..plan.output_bytes() + 1)
            .ok_or(Error::Bounds)?,
        PublicDeclassification::acknowledge(),
    );
    if expected_failure {
        if result.is_ok()
            || output.iter().any(|&v| v != 0xa5)
            || session.state() != State::Quarantined
        {
            return Err(Error::Protocol);
        }
    } else {
        result?;
        if output.get(1..plan.output_bytes() + 1) != Some(case.expected)
            || output.first() != Some(&0xa5)
            || output.last() != Some(&0xa5)
            || session.state() != State::Complete
        {
            return Err(Error::Protocol);
        }
    }
    if session.digest_public(
        plan,
        input()?,
        &mut [],
        PublicDeclassification::acknowledge(),
    ) != Err(Error::Quarantined)
    {
        return Err(Error::Protocol);
    }
    drop(session);
    println!("TYPED_RUST_VBS: case={index}; rejection={expected_failure}; PASS");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("TYPED_RUST_VBS: {error:?}");
        std::process::exit(1);
    }
}
