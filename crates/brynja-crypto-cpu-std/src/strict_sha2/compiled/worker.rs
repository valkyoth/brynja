use super::{Algorithm, Cancellation, Error, Kernel};
use brynja_crypto_cpu::static_execution::Authority;
use brynja_hash_sha2::{
    BitString,
    hardened_execution::{self as api, in_place as scoped},
};

pub(super) struct Request<'a> {
    pub algorithm: Algorithm,
    pub kernel: Kernel,
    pub chunks: &'a [&'a [u8]],
    pub tail: &'a [u8],
    pub valid_bits: u8,
    pub cancel: &'a Cancellation,
    #[cfg(test)]
    pub fault: super::tests::Fault,
}
// Both functions run exclusively on the preacquired protected stack. No
// authority or populated execution scratch is transported from/to the caller.
pub(super) fn probe(kernel: Kernel) -> Result<(), Error> {
    let owner = Authority::new(kernel).map_err(Error::Backend)?;
    let execution = api::Execution::from_static(&owner).map_err(convert)?;
    if execution.route() != api::Route::Static(kernel) {
        return Err(Error::Invariant);
    }
    Ok(())
}
pub(super) fn run(request: Request<'_>, destination: &mut [u8]) -> Result<(), Error> {
    let Request {
        algorithm,
        kernel,
        chunks,
        tail,
        valid_bits,
        cancel,
        #[cfg(test)]
        fault,
    } = request;
    cancel.check()?;
    let tail = BitString::new(tail, valid_bits).map_err(|_| Error::InvalidBits)?;
    let (complete, partial) = tail.split_borrowed();
    let last = match partial {
        Some((byte, bits)) => BitString::new(core::slice::from_ref(byte), bits),
        None => BitString::new(&[], 0),
    }
    .map_err(|_| Error::InvalidBits)?;
    let owner = Authority::new(kernel).map_err(Error::Backend)?;
    let execution = api::Execution::from_static(&owner).map_err(convert)?;
    let mut scratch = [0u8; 64];
    let staged = scratch
        .get_mut(..algorithm.output_bytes())
        .ok_or(Error::Invariant)?;
    #[cfg(test)]
    super::tests::observe(staged, destination, &owner);
    macro_rules! compute {
        ($workspace:expr, $borrow:ident) => {{
            let mut workspace = $workspace.map_err(convert)?;
            #[cfg(test)]
            super::tests::observe_workspace(&workspace);
            workspace
                .with(|mut state| {
                    for chunk in chunks.iter().copied().chain(core::iter::once(complete)) {
                        cancel.check()?;
                        for part in chunk.chunks(4096) {
                            cancel.check()?;
                            state.update(part).map_err(convert)?;
                            #[cfg(test)]
                            super::tests::inject(
                                fault,
                                super::tests::Point::Update,
                                &owner,
                                cancel,
                            );
                        }
                    }
                    cancel.check()?;
                    #[cfg(test)]
                    super::tests::inject(fault, super::tests::Point::Finalize, &owner, cancel);
                    cancel.check()?;
                    let secret = state.finalize_bits_secret(last, staged).map_err(convert)?;
                    if secret.report.route != api::Route::Static(kernel)
                        || !(1..=2).contains(&secret.report.padding_blocks)
                        || secret.report.portable_iv_blocks
                            != u128::from(matches!(algorithm, Algorithm::Sha512T(_)))
                    {
                        return Err(Error::Invariant);
                    }
                    #[cfg(test)]
                    super::tests::record(secret.report);
                    cancel.check()?;
                    brynja_core::copy_secret_region(destination, secret.digest.$borrow())
                        .map_err(|_| Error::Invariant)?;
                    #[cfg(test)]
                    super::tests::inject(fault, super::tests::Point::Output, &owner, cancel);
                    // Recheck authority after output copy as well; no revoked output
                    // may escape the outer transaction even in a test/fault scenario.
                    owner.session().map_err(Error::Backend)?;
                    cancel.check()
                })
                .map_err(convert)?
        }};
    }
    match algorithm {
        Algorithm::Sha224 => compute!(scoped::Sha224Workspace::new(execution), expose),
        Algorithm::Sha256 => compute!(scoped::Sha256Workspace::new(execution), expose),
        Algorithm::Sha384 => compute!(scoped::Sha384Workspace::new(execution), expose),
        Algorithm::Sha512 => compute!(scoped::Sha512Workspace::new(execution), expose),
        Algorithm::Sha512_224 => compute!(scoped::Sha512_224Workspace::new(execution), expose),
        Algorithm::Sha512_256 => compute!(scoped::Sha512_256Workspace::new(execution), expose),
        Algorithm::Sha512T(t) => compute!(scoped::Sha512TWorkspace::new(t, execution), as_bytes),
    }
}
fn convert(error: api::Error) -> Error {
    match error {
        api::Error::Backend(error) => Error::Backend(error),
        _ => Error::Invariant,
    }
}
