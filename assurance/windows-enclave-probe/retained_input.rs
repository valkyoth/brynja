//! Isolated borrowed-input descriptor. Metadata is NOT authority or authentication.
#![no_std]
#![forbid(unsafe_code)]
use core::marker::PhantomData;

pub const CAPACITY: usize = 1024;
pub const HEADER: usize = 32;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Header,
}

/// Retains the original caller borrow through a synchronous private adapter call.
/// No input bytes are copied here. Source storage is outside enclave protection.
pub struct Request<'input> {
    header: [u8; HEADER],
    input: PhantomData<&'input [u8]>,
    thread: PhantomData<*mut ()>,
}
impl<'input> Request<'input> {
    pub fn new(input: &'input [u8], sequence: u64) -> Result<Self, Error> {
        if input.len() > CAPACITY || sequence == 0 {
            return Err(Error::Bounds);
        }
        let length = u64::try_from(input.len()).map_err(|_| Error::Bounds)?;
        let source = if input.is_empty() {
            0
        } else {
            input.as_ptr() as u64
        };
        source.checked_add(length).ok_or(Error::Bounds)?;
        let mut header = [0; HEADER];
        for (word, bytes) in [4, sequence, length, source]
            .into_iter()
            .zip(header.chunks_exact_mut(8))
        {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        Ok(Self {
            header,
            input: PhantomData,
            thread: PhantomData,
        })
    }
    pub fn metadata(&self) -> &[u8; HEADER] {
        &self.header
    }
}

/// Validates a once-copied header. Sequence must come from private operation
/// state, NOT a second read of host metadata. No pointer is dereferenced here.
pub fn admit(header: &[u8; HEADER], expected: u64) -> Result<(u64, usize), Error> {
    let mut words = [0; 4];
    for (word, bytes) in words.iter_mut().zip(header.chunks_exact(8)) {
        let mut raw = [0; 8];
        raw.copy_from_slice(bytes);
        *word = u64::from_le_bytes(raw);
    }
    let [version, sequence, length, source] = words;
    if version != 4
        || expected == 0
        || sequence != expected
        || length > CAPACITY as u64
        || (source == 0) != (length == 0)
        || source.checked_add(length).is_none()
    {
        return Err(Error::Header);
    }
    let length = usize::try_from(length).map_err(|_| Error::Header)?;
    usize::try_from(source)
        .map_err(|_| Error::Header)?
        .checked_add(length)
        .ok_or(Error::Header)?;
    Ok((source, length))
}
