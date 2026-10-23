use crate::{
    Algorithm, BitString, Error, SecretTag, Tag, Verification,
    scratch::{Scratch, mask},
};
use brynja_core::{SecretRegionInitialization, copy_secret_region};

// Generic RFC 2104 construction, privately rebound to the legacy owners.
// Mirrors the modern engine's callback-owned intermediate/transaction pattern;
// does not open its sealed Algorithm trait or add legacy dependencies to it.
pub(crate) struct Engine<A: Algorithm> {
    inner: A::State,
    outer: A::State,
    tag_bytes: usize,
}

impl<A: Algorithm> Engine<A> {
    pub(crate) fn new(key: &[u8], tag_bytes: usize) -> Result<Self, Error> {
        if !(10..=A::TAG_BYTES).contains(&tag_bytes) {
            return Err(Error::TagLength);
        }
        let mut pad = Scratch::<64>::new();
        if key.len() > 64 {
            let mut digest = Scratch::<20>::new();
            let mut state = A::start();
            A::update(&mut state, key)?;
            A::finish(state, None, digest.prefix(A::TAG_BYTES)?, |bytes| {
                copy_secret_region(pad.prefix(bytes.len())?, bytes).map_err(Error::from)
            })?;
        } else if !key.is_empty() {
            copy_secret_region(pad.prefix(key.len())?, key)?;
        }
        let mut inner = A::start();
        let mut outer = A::start();
        mask(&mut pad.0, 0x36)?;
        A::update(&mut inner, &pad.0)?;
        mask(&mut pad.0, 0x36 ^ 0x5c)?;
        A::update(&mut outer, &pad.0)?;
        Ok(Self {
            inner,
            outer,
            tag_bytes,
        })
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        A::update(&mut self.inner, bytes)
    }

    fn finish(
        self,
        tail: Option<BitString<'_>>,
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut inner_digest = Scratch::<20>::new();
        let mut tag = Scratch::<20>::new();
        let mut outer = self.outer;
        A::finish(
            self.inner,
            tail,
            inner_digest.prefix(A::TAG_BYTES)?,
            |digest| {
                A::update(&mut outer, digest)?;
                A::finish(outer, None, tag.prefix(A::TAG_BYTES)?, |tag| {
                    consume(tag.get(..self.tag_bytes).ok_or(Error::SecretMemory)?)
                })
            },
        )
    }

    pub(crate) fn public<'a>(
        self,
        tail: Option<BitString<'_>>,
        output: &'a mut [u8],
    ) -> Result<Tag<'a, A>, Error> {
        if output.len() != self.tag_bytes {
            return Err(Error::TagLength);
        }
        self.finish(tail, |tag| {
            copy_secret_region(output, tag).map_err(Error::from)
        })?;
        Ok(Tag::new(output))
    }

    pub(crate) fn secret<'a>(
        self,
        tail: Option<BitString<'_>>,
        output: &'a mut [u8],
    ) -> Result<SecretTag<'a, A>, Error> {
        let length = output.len();
        if length == 0 {
            return Err(Error::TagLength);
        }
        let mut guard = SecretRegionInitialization::begin(output)?;
        if length != self.tag_bytes {
            return Err(Error::TagLength);
        }
        self.finish(tail, |tag| guard.write(tag).map_err(Error::from))?;
        Ok(SecretTag::new(guard.finish()?))
    }

    pub(crate) fn verify(
        self,
        tail: Option<BitString<'_>>,
        candidate: &[u8],
    ) -> Result<Verification, Error> {
        if candidate.len() != self.tag_bytes {
            return Err(Error::TagLength);
        }
        let mut difference = Scratch::<1>::new();
        self.finish(tail, |tag| {
            for (expected, actual) in tag.iter().zip(candidate) {
                brynja_core::accumulate_secret_byte_difference(
                    &mut difference.0[0],
                    expected,
                    actual,
                );
            }
            Ok(())
        })?;
        Ok(Verification::new(brynja_core::secret_difference_is_zero(
            &difference.0[0],
        )))
    }
}
