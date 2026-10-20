use brynja_core::{SecretRegionInitialization, copy_secret_region};

use crate::{
    Algorithm, Error,
    output::{SecretTag, Tag, Verification},
    scratch::{Scratch, mask_pad},
};

pub(crate) struct Engine<A: Algorithm> {
    inner: A::State,
    outer: A::State,
    tag_bytes: usize,
}

impl<A: Algorithm> Engine<A> {
    pub(crate) fn new(key: &[u8], tag_bytes: usize) -> Result<Self, Error> {
        if !crate::policy::valid_tag_length(A::TAG_BYTES, tag_bytes) {
            return Err(Error::TagLength);
        }
        let mut pad = Scratch::<144>::new();
        let pad = pad.prefix(A::BLOCK_BYTES)?;
        if key.len() > A::BLOCK_BYTES {
            let mut normalized = Scratch::<64>::new();
            let mut hash = A::start();
            A::update(&mut hash, key)?;
            A::finish(hash, normalized.prefix(A::TAG_BYTES)?, |digest| {
                let destination = pad.get_mut(..digest.len()).ok_or(Error::SecretMemory)?;
                copy_secret_region(destination, digest).map_err(Error::from)
            })?;
        } else {
            let destination = pad.get_mut(..key.len()).ok_or(Error::SecretMemory)?;
            if !key.is_empty() {
                copy_secret_region(destination, key)?;
            }
        }
        let mut inner = A::start();
        let mut outer = A::start();
        mask_pad(pad, 0x36)?;
        A::update(&mut inner, pad)?;
        mask_pad(pad, 0x36 ^ 0x5c)?;
        A::update(&mut outer, pad)?;
        Ok(Self {
            inner,
            outer,
            tag_bytes,
        })
    }

    pub(crate) fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        A::update(&mut self.inner, input)
    }

    fn finish(
        self,
        input: Option<A::FinalInput<'_>>,
        consume: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut inner_digest = Scratch::<64>::new();
        let mut tag = Scratch::<64>::new();
        let mut outer = self.outer;
        let destination = inner_digest.prefix(A::TAG_BYTES)?;
        let absorb_inner = |digest: &[u8]| A::update(&mut outer, digest);
        match input {
            Some(input) => A::finish_bits(self.inner, input, destination, absorb_inner)?,
            None => A::finish(self.inner, destination, absorb_inner)?,
        }
        A::finish(outer, tag.prefix(A::TAG_BYTES)?, |digest| {
            consume(digest.get(..self.tag_bytes).ok_or(Error::SecretMemory)?)
        })
    }

    pub(crate) fn public<'out>(
        self,
        input: Option<A::FinalInput<'_>>,
        destination: &'out mut [u8],
    ) -> Result<Tag<'out, A>, Error> {
        if !crate::policy::exact_output(self.tag_bytes, destination.len()) {
            return Err(Error::TagLength);
        }
        self.finish(input, |tag| {
            copy_secret_region(destination, tag).map_err(Error::from)
        })?;
        Ok(Tag::new(destination))
    }

    pub(crate) fn secret<'out>(
        self,
        input: Option<A::FinalInput<'_>>,
        destination: &'out mut [u8],
    ) -> Result<SecretTag<'out, A>, Error> {
        let length = destination.len();
        if length == 0 {
            return Err(Error::TagLength);
        }
        let mut initialization = SecretRegionInitialization::begin(destination)?;
        if !crate::policy::exact_output(self.tag_bytes, length) {
            return Err(Error::TagLength);
        }
        self.finish(input, |tag| initialization.write(tag).map_err(Error::from))?;
        Ok(SecretTag::new(initialization.finish()?))
    }

    pub(crate) fn verify(
        self,
        input: Option<A::FinalInput<'_>>,
        candidate: &[u8],
    ) -> Result<Verification, Error> {
        if !crate::policy::exact_output(self.tag_bytes, candidate.len()) {
            return Err(Error::TagLength);
        }
        let mut difference = Scratch::<1>::new();
        self.finish(input, |tag| {
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
