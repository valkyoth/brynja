use super::{Algorithm, backends::Backend};
use crate::{Error, algorithms::sealed};
use core::marker::PhantomData;

pub(super) struct Adapter<'a, A>(PhantomData<(&'a (), A)>);

impl<'a, A: Algorithm<'a>> crate::Algorithm for Adapter<'a, A> {
    const BLOCK_BYTES: usize = A::BLOCK_BYTES;
    const TAG_BYTES: usize = A::TAG_BYTES;
    const TAG_BITS: usize = A::TAG_BITS;
}

impl<'a, A: Algorithm<'a>> sealed::Hash for Adapter<'a, A> {
    type State = A::CpuState;
    type FinalInput<'b> = A::FinalInput<'b>;
    fn validate() -> Result<(), Error> {
        A::validate()
    }
    // This adapter has no implicit constructor; only explicit authority can
    // supply its owner factory through the private Engine::new_with boundary.
    fn start() -> Result<Self::State, Error> {
        Err(Error::ExecutionFailed)
    }
    fn update(state: &mut Self::State, input: &[u8]) -> Result<(), Error> {
        A::update_cpu(state, input)
    }
    fn finish(
        state: Self::State,
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        A::finish_cpu(state, None, output, consume)
    }
    fn finish_bits(
        state: Self::State,
        input: Self::FinalInput<'_>,
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        A::finish_cpu(state, Some(input), output, consume)
    }
    fn finish_outer(
        state: Self::State,
        digest: &[u8],
        output: &mut [u8],
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        <A as Backend<'a>>::outer_cpu(state, digest, output, consume)
    }
}
