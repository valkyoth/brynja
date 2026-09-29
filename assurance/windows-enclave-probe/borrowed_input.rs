//! Isolated borrowed-input boundary model; not a shipping Windows secret API.
//! The source is caller-owned. Only metadata may be serialized on the host.
#![no_std]
#![forbid(unsafe_code)]

use core::marker::PhantomData;

pub const CAPACITY: usize = 1024;
pub const HEADER: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    Header,
    Copy,
}

/// Keeps caller input borrowed; contains only addresses/lengths, never payload.
/// This research descriptor is not authenticated or a capability for dereference.
pub struct Request<'input> {
    header: [u8; HEADER],
    input: PhantomData<&'input [u8]>,
    thread_bound: PhantomData<*mut ()>,
}

impl<'input> Request<'input> {
    pub fn new(input: &'input [u8], command: u64) -> Result<Self, Error> {
        if input.len() > CAPACITY || command == 0 || command.checked_add(64).is_none() {
            return Err(Error::Bounds);
        }
        let source = if input.is_empty() {
            0
        } else {
            input.as_ptr() as u64
        };
        let length = u64::try_from(input.len()).map_err(|_| Error::Bounds)?;
        source.checked_add(length).ok_or(Error::Bounds)?;
        let mut header = [0; HEADER];
        for (value, bytes) in [3, 0, length, source, command, 64, 0, 0]
            .into_iter()
            .zip(header.chunks_exact_mut(8))
        {
            bytes.copy_from_slice(&value.to_le_bytes());
        }
        Ok(Self {
            header,
            input: PhantomData,
            thread_bound: PhantomData,
        })
    }

    /// Public routing metadata only. Never treat these bytes as source authority.
    pub fn metadata(&self) -> &[u8; HEADER] {
        &self.header
    }
}

struct Admission {
    source: u64,
    length: usize,
    command: u64,
}
fn admit(header: &[u8; HEADER]) -> Result<Admission, Error> {
    let mut words = [0; 8];
    for (value, bytes) in words.iter_mut().zip(header.chunks_exact(8)) {
        let mut word = [0; 8];
        word.copy_from_slice(bytes);
        *value = u64::from_le_bytes(word);
    }
    let [
        version,
        reserved,
        length,
        source,
        command,
        width,
        flags,
        tail,
    ] = words;
    if version != 3
        || reserved != 0
        || length > CAPACITY as u64
        || width != 64
        || flags != 0
        || tail != 0
        || command == 0
        || command.checked_add(64).is_none()
        || source.checked_add(length).is_none()
        || (length == 0) != (source == 0)
        || usize::try_from(source).is_err()
        || usize::try_from(command).is_err()
    {
        return Err(Error::Header);
    }
    let length = usize::try_from(length).map_err(|_| Error::Header)?;
    usize::try_from(source)
        .map_err(|_| Error::Header)?
        .checked_add(length)
        .ok_or(Error::Header)?;
    usize::try_from(command)
        .map_err(|_| Error::Header)?
        .checked_add(64)
        .ok_or(Error::Header)?;
    Ok(Admission {
        source,
        length,
        command,
    })
}

/// Must be constructed inside preacquired protected storage before real secrets
/// are admitted. This model alone does not allocate, lock or qualify that storage.
pub struct Snapshot {
    bytes: [u8; CAPACITY],
    thread_bound: PhantomData<*mut ()>,
}
impl Snapshot {
    pub fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            thread_bound: PhantomData,
        }
    }

    /// Private-adapter shape demonstrated as an isolated research API. The read
    /// closure models the OS copy operation; no raw pointer is dereferenced here.
    /// The operation closure is trusted and must not export confidential copies.
    /// Copy success is not atomicity or authentication against a racing host.
    pub fn with<R>(
        &mut self,
        header: &[u8; HEADER],
        mut read: impl FnMut(u64, &mut [u8]) -> bool,
        operation: impl for<'scope> FnOnce(&'scope [u8], u64) -> R,
    ) -> Result<R, Error> {
        let guard = Clear(&mut self.bytes);
        // Clear before admission too, including stale bytes from a prior use.
        clear(guard.0);
        let request = admit(header)?;
        if request.length != 0 {
            let copied = read(request.source, &mut guard.0[..request.length]);
            if !copied && !cfg!(probe_borrowed_ignore_copy) {
                return Err(Error::Copy);
            }
            if cfg!(probe_borrowed_reread) {
                if !read(request.source, &mut guard.0[..request.length]) {
                    return Err(Error::Copy);
                }
            }
        }
        let width = if cfg!(probe_borrowed_full_capacity) {
            CAPACITY
        } else {
            request.length
        };
        Ok(operation(&guard.0[..width], request.command))
        // Full-capacity guard clears on success, rejection and recoverable unwind.
    }
}
fn clear(bytes: &mut [u8; CAPACITY]) {
    if !cfg!(probe_borrowed_skip_clear) {
        // Fixed nonempty capacity: EmptyRegion is the primitive's only failure.
        let _ = brynja_core::clear_owned_region(bytes);
    }
}
struct Clear<'a>(&'a mut [u8; CAPACITY]);
impl Drop for Clear<'_> {
    fn drop(&mut self) {
        clear(self.0);
    }
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        clear(&mut self.bytes);
    }
}

#[cfg(test)]
#[path = "borrowed_input_tests.rs"]
mod tests;
