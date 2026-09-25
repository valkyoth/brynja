use super::{Algorithm, Cancellation, Error, Input, Report, Route, keccak, sha256, sha512};
pub(super) struct Request<'a> {
    pub route: Route,
    pub inputs: &'a [Option<Input<'a>>; 8],
    pub max_work: u64,
    pub cancel: &'a Cancellation,
    #[cfg(test)]
    pub fault: super::tests::Fault,
}
// All entry points are called only from a preacquired protected worker stack.
pub(super) fn probe(route: Route) -> Result<(), Error> {
    macro_rules! probe {
        ($api:ident, $kernel:expr, $error:ident) => {
            if let Some(kernel) = $kernel {
                let owner = $api::Authority::for_compiled_target(kernel)
                    .map_err(|e| Error::$error($api::Error::Backend(e)))?;
                owner
                    .session()
                    .map_err(|e| Error::$error($api::Error::Backend(e)))?;
            }
        };
    }
    match route {
        Route::Sha256(k) => probe!(sha256, k, Sha256),
        Route::Sha512(k) => probe!(sha512, k, Sha512),
        Route::Keccak(k) => probe!(keccak, k, Keccak),
    }
    Ok(())
}
pub(super) fn run(
    request: Request<'_>,
    staging: &mut [u8],
    scratch: &mut [u8],
    output: &mut [u8],
) -> Result<Report, Error> {
    let Request {
        route,
        inputs,
        max_work,
        cancel,
        #[cfg(test)]
        fault,
    } = request;
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    macro_rules! execute {
        ($api:ident, $kind:ident, $kernel:expr, $capacity:literal, $convert:expr $(, $scratch:expr)?) => {{
            let mut parsed = core::array::from_fn::<_, $capacity, _>(|_| None);
            let mut destinations = core::array::from_fn::<_, $capacity, _>(|_| None);
            let mut rest = staging;
            for ((parsed, destination), raw) in parsed.iter_mut().zip(&mut destinations).zip(inputs) {
                if let Some(raw) = raw {
                    *parsed = Some($convert(raw)?);
                    let (slot, tail) = rest.split_at_mut_checked(raw.algorithm.output_bytes()).ok_or(Error::Invariant)?;
                    *destination = Some(slot); rest = tail;
                }
            }
            let authority = $kernel.map($api::Authority::for_compiled_target).transpose()
                .map_err(|e| Error::$kind($api::Error::Backend(e)))?;
            let executor = match &authority {
                Some(owner) => $api::Executor::with_session(owner.session().map_err(|e| Error::$kind($api::Error::Backend(e)))?,
                    $api::Mode::Require, 1).map_err(Error::$kind)?,
                None => $api::Executor::portable(),
            };
            let mut workspace = $api::Workspace::new();
            #[cfg(test)] super::tests::observe(&workspace, &authority, &executor, output, scratch);
            #[cfg(test)] let mut checks = 0usize;
            let mut cancelled = || {
                #[cfg(test)] {
                    super::tests::inject(fault, checks, || executor.quarantine(), cancel);
                    checks = checks.saturating_add(1);
                }
                cancel.is_cancelled()
            };
            let mut control = $api::Control::new(max_work, &mut cancelled);
            let (secret, report) = executor.digest_secret(&parsed, destinations, &mut workspace, $($scratch,)? &mut control)
                .map_err(Error::$kind)?;
            if report.kernel != $kernel || ($kernel.is_some() && report.vector_calls == 0) { return Err(Error::Invariant); }
            let mut rest = output;
            for index in 0..$capacity {
                if let Some(source) = secret.expose(index) {
                    let (slot, tail) = rest.split_at_mut_checked(source.len()).ok_or(Error::Invariant)?;
                    brynja_core::copy_secret_region(slot, source).map_err(|_| Error::Invariant)?;
                    rest = tail;
                }
            }
            #[cfg(test)] super::tests::inject(fault, usize::MAX, || executor.quarantine(), cancel);
            if let Some(owner) = &authority { owner.session().map_err(|e| Error::$kind($api::Error::Backend(e)))?; }
            if cancel.is_cancelled() { return Err(Error::Cancelled); }
            Ok(Report::$kind(report))
        }};
    }
    match route {
        Route::Sha256(kernel) => execute!(sha256, Sha256, kernel, 8, narrow),
        Route::Sha512(kernel) => execute!(sha512, Sha512, kernel, 4, wide),
        Route::Keccak(kernel) => execute!(keccak, Keccak, kernel, 4, sponge, scratch),
    }
}
fn narrow<'a>(raw: &Input<'a>) -> Result<sha256::Input<'a>, Error> {
    let Algorithm::Sha256(algorithm) = raw.algorithm else {
        return Err(Error::InvalidInput);
    };
    Ok(sha256::Input::new(
        algorithm,
        brynja_hash_sha2::BitString::new(raw.message.bytes, raw.message.valid_bits)
            .map_err(|_| Error::InvalidInput)?,
    ))
}
fn wide<'a>(raw: &Input<'a>) -> Result<sha512::Input<'a>, Error> {
    let Algorithm::Sha512(algorithm) = raw.algorithm else {
        return Err(Error::InvalidInput);
    };
    Ok(sha512::Input::new(
        algorithm,
        brynja_hash_sha2::BitString::new(raw.message.bytes, raw.message.valid_bits)
            .map_err(|_| Error::InvalidInput)?,
    ))
}
fn sponge<'a>(raw: &Input<'a>) -> Result<keccak::Input<'a>, Error> {
    let Algorithm::Keccak(algorithm, bits) = raw.algorithm else {
        return Err(Error::InvalidInput);
    };
    let canonical = |b: &super::Bits<'a>| {
        brynja_hash_sha3::Fips202BitString::new(b.bytes, b.valid_bits)
            .map_err(|_| Error::InvalidInput)
    };
    keccak::Input::with_customization(
        algorithm,
        canonical(&raw.message)?,
        canonical(&raw.name)?,
        canonical(&raw.customization)?,
        bits,
    )
    .map_err(|_| Error::InvalidInput)
}
