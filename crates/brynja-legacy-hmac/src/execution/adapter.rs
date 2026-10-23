use crate::{Algorithm, BitString, Error, algorithms::sealed};
use brynja_legacy_sha1::{Sha1Error, hardened_execution};
use core::marker::PhantomData;

pub(super) struct Sha1Adapter<'a>(PhantomData<&'a ()>);

pub(super) fn error(error: hardened_execution::Error) -> Error {
    match error {
        hardened_execution::Error::Hash(Sha1Error::MessageTooLong) => Error::MessageTooLong,
        _ => Error::ExecutionFailed,
    }
}

impl Algorithm for Sha1Adapter<'_> {
    const TAG_BYTES: usize = 20;
}

impl<'a> sealed::Hash for Sha1Adapter<'a> {
    type State = hardened_execution::Stream<'a>;

    // Only the explicit, pre-admitted stream factory may construct this adapter.
    fn start() -> Result<Self::State, Error> {
        Err(Error::ExecutionFailed)
    }

    fn update(state: &mut Self::State, input: &[u8]) -> Result<(), Error> {
        state.update(input).map_err(error)
    }

    fn finish(
        state: Self::State,
        tail: Option<BitString<'_>>,
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let digest = match tail {
            Some(tail) => state.finalize_bits_secret(tail, output),
            None => state.finalize_secret(output),
        }
        .map_err(error)?;
        consume(digest.expose())
    }
}
