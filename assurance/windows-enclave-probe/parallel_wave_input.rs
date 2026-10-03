//! Private safe ingress staging. NOT OS-copy, protected-placement or API evidence.
//! Real integration must place this owner on the admitted root frame and implement
//! CopyIn using bounded OS copy primitives, never raw host-address dereferences.
#![no_std]
#![forbid(unsafe_code)]
use brynja_core::clear_owned_region;
use brynja_hash_sha3::Fips202BitString as Bits;
use core::marker::PhantomData;
mod parallel_wave_request;
pub use parallel_wave_request::{HEADER_BYTES, MAGIC, Request};
use parallel_wave_request::{last, source, width};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    State,
    Copy,
    Bits,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Header,
    Custom,
    Wave,
}

/// Private transport seam, not a consumer callback or public host API. Addresses
/// and lengths are public metadata; neither this trait nor the header authorizes
/// pointer dereference or proves residency. Copy failure may modify a prefix.
pub trait CopyIn {
    fn copy_into(&mut self, kind: Kind, address: usize, destination: &mut [u8]) -> bool;
}
#[derive(PartialEq, Eq)]
enum Phase {
    Fresh,
    Ready,
    Dead,
}
pub struct InputFrame {
    header: [u8; HEADER_BYTES],
    custom: [u8; 1024],
    wave: [u8; 4096],
    request: Option<Request>,
    loaded_bits: usize,
    phase: Phase,
    thread_bound: PhantomData<*mut ()>,
}
pub struct Chunk<'frame> {
    bytes: &'frame [u8],
    offset: usize,
    bit_len: usize,
}
impl Chunk<'_> {
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
    pub fn offset(&self) -> usize {
        self.offset
    }
    pub fn bit_len(&self) -> usize {
        self.bit_len
    }
}
struct Operation<'frame> {
    frame: &'frame mut InputFrame,
    complete: bool,
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.frame.clear();
        }
    }
}
impl Default for InputFrame {
    fn default() -> Self {
        Self::new()
    }
}
impl InputFrame {
    pub const fn new() -> Self {
        Self {
            header: [0; HEADER_BYTES],
            custom: [0; 1024],
            wave: [0; 4096],
            request: None,
            loaded_bits: 0,
            phase: Phase::Fresh,
            thread_bound: PhantomData,
        }
    }
    fn clear(&mut self) {
        let _ = clear_owned_region(&mut self.header);
        let _ = clear_owned_region(&mut self.custom);
        let _ = clear_owned_region(&mut self.wave);
        self.request = None;
        self.loaded_bits = 0;
        self.phase = Phase::Dead;
    }
    /// Copy once, validate every field, only then request customization bytes.
    /// No message bytes are requested here. Failed/unwound copies clear all
    /// staging and make this frame terminal. No fallback or partial admission.
    pub fn begin(&mut self, address: usize, copy: &mut impl CopyIn) -> Result<Request, Error> {
        let mut guard = Operation {
            frame: self,
            complete: false,
        };
        if guard.frame.phase != Phase::Fresh {
            return Err(Error::State);
        }
        source(address, HEADER_BYTES)?;
        if !copy.copy_into(Kind::Header, address, &mut guard.frame.header) {
            return Err(Error::Copy);
        }
        let request = Request::decode(&guard.frame.header)?;
        let custom_width = width(request.custom_bits)?;
        let custom = guard
            .frame
            .custom
            .get_mut(..custom_width)
            .ok_or(Error::Bounds)?;
        if custom_width != 0 && !copy.copy_into(Kind::Custom, request.custom_source, custom) {
            return Err(Error::Copy);
        }
        Bits::new(custom, last(request.custom_bits)).map_err(|_| Error::Bits)?;
        guard.frame.request = Some(request);
        guard.frame.phase = Phase::Ready;
        guard.complete = true;
        Ok(request)
    }
    pub fn custom(&self) -> Result<Bits<'_>, Error> {
        if self.phase != Phase::Ready {
            return Err(Error::State);
        }
        let request = self.request.ok_or(Error::State)?;
        Bits::new(
            self.custom
                .get(..width(request.custom_bits)?)
                .ok_or(Error::Bounds)?,
            last(request.custom_bits),
        )
        .map_err(|_| Error::Bits)
    }
    /// Fixed storage, internally chosen offset/length. Returned bytes borrow
    /// the frame: they cannot survive its next copy, clearing or destruction.
    /// Host memory may change between copies; no atomic full-message snapshot
    /// is promised. Callers must preserve their borrowed inputs for the request.
    pub fn next_wave(&mut self, copy: &mut impl CopyIn) -> Result<Chunk<'_>, Error> {
        let (offset, bits, length) = {
            let mut guard = Operation {
                frame: self,
                complete: false,
            };
            if guard.frame.phase != Phase::Ready {
                return Err(Error::State);
            }
            let request = guard.frame.request.ok_or(Error::State)?;
            let loaded = guard.frame.loaded_bits;
            if loaded >= request.input_bits || !loaded.is_multiple_of(8) {
                return Err(Error::State);
            }
            let capacity = request.block.checked_mul(32).ok_or(Error::Bounds)?;
            let bits = request
                .input_bits
                .checked_sub(loaded)
                .ok_or(Error::Bounds)?
                .min(capacity);
            let offset = loaded / 8;
            let length = width(bits)?;
            let address = request
                .input_source
                .checked_add(offset)
                .ok_or(Error::Bounds)?;
            source(address, length)?;
            let _ = clear_owned_region(&mut guard.frame.wave);
            let destination = guard.frame.wave.get_mut(..length).ok_or(Error::Bounds)?;
            if !copy.copy_into(Kind::Wave, address, destination) {
                return Err(Error::Copy);
            }
            Bits::new(destination, last(bits)).map_err(|_| Error::Bits)?;
            guard.frame.loaded_bits = loaded.checked_add(bits).ok_or(Error::Bounds)?;
            guard.complete = true;
            (offset, bits, length)
        };
        Ok(Chunk {
            bytes: &self.wave[..length],
            offset,
            bit_len: bits,
        })
    }
    /// This proves only ingress consumption, NOT hashing completion. The typed
    /// Waves owner must separately enforce its exact processed-bit/leaf count.
    pub fn finish(&mut self) -> Result<(), Error> {
        let guard = Operation {
            frame: self,
            complete: false,
        };
        if guard.frame.phase != Phase::Ready
            || guard.frame.loaded_bits != guard.frame.request.ok_or(Error::State)?.input_bits
        {
            return Err(Error::State);
        }
        Ok(()) // Operation clears even on success.
    }
    pub fn cancel(&mut self) {
        self.clear();
    }
}
impl Drop for InputFrame {
    fn drop(&mut self) {
        self.clear();
    }
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod parallel_wave_input_tests;
