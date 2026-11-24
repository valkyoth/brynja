//! Deterministic senders. A range is an application allocation,
//! not proof that an external store reserved it or that the key is fresh.
use super::{Block, Buffers, Error, Forward, open_with, seal_admitted};

pub(super) struct TagPolicy<const T: usize>(());
impl<const T: usize> TagPolicy<T> {
    pub(super) fn new() -> Result<Self, Error> {
        match T {
            12..=16 => Ok(Self(())),
            _ => Err(Error::TagLength),
        }
    }
    pub(super) fn prefix<'a>(&self, full: &'a Block) -> Result<&'a [u8; T], Error> {
        full.first_chunk().ok_or(Error::Invariant)
    }
}

// Own the expanded key; the owner cannot be cloned or rewound. Decryption
// does not advance the sender. A new owner requires a disjoint allocation.
pub(super) struct Key<K, const T: usize, const N: usize = 12> {
    cipher: K,
    tag: TagPolicy<T>,
    template: [u8; N],
    numbers: Option<core::ops::RangeInclusive<u64>>,
}

impl<K: Forward, const T: usize> Key<K, T> {
    pub(super) fn from_reserved_range(
        cipher: K,
        prefix: [u8; 4],
        first: u64,
        count: u64,
    ) -> Result<Self, Error> {
        Self::reserved(cipher, &prefix, first, count, u64::MAX)
    }

    #[cfg(feature = "aes-gcm")]
    pub(super) fn for_open(cipher: K) -> Result<Self, Error> {
        Ok(Self {
            cipher,
            tag: TagPolicy::new()?,
            template: [0; 12],
            numbers: None,
        })
    }
}

impl<K: Forward, const T: usize, const N: usize> Key<K, T, N> {
    // The layout is fixed for each IV length, including when the two policies
    // both encode 96-bit IVs. Short IVs cannot silently truncate a counter.
    fn suffix_width() -> usize {
        if N == 12 { 8 } else { N.min(4) }
    }

    fn reserved(
        cipher: K,
        prefix: &[u8],
        first: u64,
        count: u64,
        limit: u64,
    ) -> Result<Self, Error> {
        let tag = TagPolicy::new()?;
        let last = first
            .checked_add(count.checked_sub(1).ok_or(Error::Length)?)
            .ok_or(Error::Length)?;
        let width = Self::suffix_width();
        let skip = 8usize.checked_sub(width).ok_or(Error::Invariant)?;
        if N == 0
            || u64::try_from(N).map_err(|_| Error::Length)? > u64::MAX / 8
            || last > limit
            || last
                .to_be_bytes()
                .get(..skip)
                .ok_or(Error::Invariant)?
                .iter()
                .any(|b| *b != 0)
        {
            return Err(Error::Length);
        }
        let mut template = [0; N];
        let split = N.checked_sub(width).ok_or(Error::Invariant)?;
        if prefix.len() != split {
            return Err(Error::Length);
        }
        template
            .get_mut(..split)
            .ok_or(Error::Invariant)?
            .copy_from_slice(prefix);
        Ok(Self {
            cipher,
            tag,
            template,
            numbers: Some(first..=last),
        })
    }

    pub(super) fn from_reserved_invocations(
        cipher: K,
        prefix: &[u8],
        first: u32,
        count: u64,
    ) -> Result<Self, Error> {
        Self::reserved(cipher, prefix, u64::from(first), count, u64::from(u32::MAX))
    }

    pub(super) fn seal_next(
        &mut self,
        aad: &[u8],
        io: Buffers<'_>,
        scratch: &mut [u8],
    ) -> Result<([u8; N], [u8; T]), Error> {
        let numbers = self
            .numbers
            .as_mut()
            .filter(|r| !r.is_empty())
            .ok_or(Error::Exhausted)?;
        let mut iv = self.template;
        let frame = io.frame(&iv, aad, scratch)?;
        // Burn before the first keyed operation. An error or unwind cannot
        // make the same IV available again; pure admission failures consume none.
        let counter = numbers.next().ok_or(Error::Invariant)?.to_be_bytes();
        let width = Self::suffix_width();
        let split = N.checked_sub(width).ok_or(Error::Invariant)?;
        let skip = counter.len().checked_sub(width).ok_or(Error::Invariant)?;
        iv.get_mut(split..)
            .ok_or(Error::Invariant)?
            .copy_from_slice(counter.get(skip..).ok_or(Error::Invariant)?);
        let tag = seal_admitted(&self.cipher, &iv, aad, io, scratch, frame, &self.tag)?;
        Ok((iv, tag))
    }

    pub(super) fn open(
        &self,
        iv: &[u8],
        aad: &[u8],
        tag: &[u8; T],
        io: Buffers<'_>,
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        open_with(&self.cipher, iv, aad, io, scratch, tag, &self.tag)
    }
}

#[cfg(test)]
mod tests;
