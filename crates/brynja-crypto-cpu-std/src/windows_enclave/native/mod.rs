use super::{
    Error, ImagePolicy,
    engine::Driver,
    protocol::{self, Context},
};
use lifecycle::Registration;
use std::cell::Cell;
use std::path::Path;
mod admission;
mod callback;
#[cfg(feature = "strict-sha3-acceleration")]
pub(super) mod keccak_simd;
#[cfg(feature = "strict-kmac")]
pub(super) mod kmac;
mod lifecycle;
#[cfg(feature = "strict-sha3-acceleration")]
pub(super) mod parallel_concurrent;
#[cfg(feature = "strict-sha3")]
pub(super) mod parallelhash;
mod pin;
pub(super) mod sha2;
#[cfg(feature = "strict-sha2-acceleration")]
pub(super) mod sha256_simd;
pub(super) mod sha2_batch;
#[cfg(feature = "strict-sha3")]
pub(super) mod sha3;
#[cfg(feature = "strict-sha3")]
pub(super) mod sha3_batch;
#[cfg(feature = "strict-sha2-acceleration")]
pub(super) mod sha512_simd;
mod sys;
#[cfg(feature = "strict-tuplehash")]
pub(super) mod tuplehash;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    #[cfg(feature = "strict-sha3-acceleration")]
    KeccakSimd,
    #[cfg(feature = "strict-sha2-acceleration")]
    Sha512Simd,
    #[cfg(feature = "strict-sha2-acceleration")]
    Sha256Simd,
    Sha2Batch,
    Sha2BatchShaNi,
    Legacy,
    Sha2,
    Sha2ShaNi,
    #[cfg(feature = "strict-sha3")]
    Sha3,
    #[cfg(feature = "strict-sha3")]
    Sha3Avx2,
    #[cfg(feature = "strict-sha3")]
    Sha3Batch,
    #[cfg(feature = "strict-sha3")]
    Sha3BatchAvx2,
    #[cfg(feature = "strict-sha3")]
    ParallelHash,
    #[cfg(feature = "strict-sha3")]
    ParallelHashAvx2,
    #[cfg(feature = "strict-kmac")]
    Kmac,
    #[cfg(feature = "strict-kmac")]
    KmacAvx2,
    #[cfg(feature = "strict-tuplehash")]
    TupleHash,
    #[cfg(feature = "strict-tuplehash")]
    TupleHashAvx2,
}

#[derive(Default)]
struct Entries {
    wire: usize,
    window: usize,
    registration: usize,
    control: usize,
    guard: usize,
    output: usize,
    input: usize,
    input_control: usize,
    rehash_control: usize,
    sha2_control: usize,
}
pub(super) struct Backend {
    pin: Option<pin::Pin>,
    base: usize,
    initialized: bool,
    terminated: bool,
    uncertain: bool,
    registrations_pending: Cell<bool>,
    thread: u32,
    entries: Entries,
    slot: usize,
    slot_locked: bool,
    live: bool,
    epoch: u64,
    generation: u64,
    protocol: Protocol,
}
impl Backend {
    pub(super) fn open(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Self::open_with(location, policy, |pin| pin.signature())
    }
    // Private constructor; production call above always requires trust success.
    // No application-supplied callback or runtime deployment-profile flag.
    fn open_with(
        location: &Path,
        policy: &ImagePolicy,
        verify: impl FnOnce(&pin::Pin) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        Self::open_protocol(location, policy, verify, Protocol::Legacy)
    }
    fn read<const N: usize>(routine: usize, start: usize) -> Result<[usize; N], Error> {
        let mut words = [0; N];
        for (i, word) in words.iter_mut().enumerate() {
            *word = sys::call(routine, start.checked_add(i).ok_or(Error::Protocol)?)?;
        }
        Ok(words)
    }
    fn run(
        &mut self,
        operation: usize,
        input: Option<&[u8; 32]>,
        length: usize,
        output: Option<&mut [u8; 32]>,
    ) -> Result<(), Error> {
        if self.uncertain
            || self.terminated
            || self.base == 0
            || self.thread != sys::thread()
            || !matches!(operation, 0 | 1 | 2 | 3 | 4 | 8)
            || (operation == 1) != input.is_some()
            || (operation == 2) != output.is_some()
        {
            return Err(Error::Quarantined);
        }
        let context = Context {
            base: self.base,
            operation,
            length,
            epoch: self.epoch,
            generation: self.generation,
            slot: self.slot,
            slot_locked: self.slot_locked,
            ..Context::default()
        };
        callback::install(context)?;
        let registrations = Registration::new(&self.entries, &self.registrations_pending);
        // Any failure after registration keeps this backend quarantined. The
        // guard revokes borrowed host addresses even on recoverable unwinding.
        self.uncertain = true;
        let execution = (|| {
            if sys::call(self.entries.input, input.map_or(0, |v| v.as_ptr() as usize))? != 1
                || sys::call(
                    self.entries.output,
                    output.map_or(0, |v| v.as_mut_ptr() as usize),
                )? != 1
                || sys::call(self.entries.registration, callback::address())? != 1
            {
                return Err(Error::Protocol);
            }
            let returned = sys::call(self.entries.wire, operation)?;
            Ok((
                returned,
                Self::read::<7>(self.entries.window, 2)?,
                Self::read::<13>(self.entries.guard, 16)?,
                Self::read::<10>(self.entries.control, 16)?,
                Self::read::<11>(self.entries.input_control, 16)?,
                Self::read::<9>(self.entries.rehash_control, 16)?,
            ))
        })();
        // Revocation must complete before input/output references can expire.
        registrations.revoke();
        let context = callback::take()?;
        self.slot = context.slot;
        self.slot_locked = context.slot_locked;
        let (returned, outer, guards, inner, input, rehash) = execution?;
        context.inspect(returned, outer, guards, inner, input, rehash)?;
        if operation != 3 && !sys::pages(self.slot, 1, true) {
            return Err(Error::Protocol);
        }
        match operation {
            1 => self.generation = 1,
            8 => self.generation = self.generation.checked_add(1).ok_or(Error::Exhausted)?,
            3 => self.slot = 0,
            _ => {}
        }
        self.uncertain = false;
        Ok(())
    }
    fn clear(&mut self) -> Result<(), Error> {
        if self.live {
            match self.protocol {
                Protocol::Sha2 | Protocol::Sha2ShaNi => self.run_sha2(3, None, 0, None)?,
                Protocol::Sha2Batch | Protocol::Sha2BatchShaNi => {
                    self.run_sha2_batch(3, None, 0, None)?
                }
                #[cfg(feature = "strict-sha3")]
                Protocol::Sha3 | Protocol::Sha3Avx2 => self.run_sha3(3, None, 0, None)?,
                #[cfg(feature = "strict-sha3")]
                Protocol::Sha3Batch | Protocol::Sha3BatchAvx2 => {
                    self.run_sha3_batch(3, None, 0, None)?
                }
                #[cfg(feature = "strict-kmac")]
                Protocol::Kmac | Protocol::KmacAvx2 => self.run_kmac(3, None, 0, None)?,
                #[cfg(feature = "strict-tuplehash")]
                Protocol::TupleHash | Protocol::TupleHashAvx2 => {
                    self.run_tuplehash(3, None, 0, None)?
                }
                #[cfg(feature = "strict-sha3")]
                Protocol::ParallelHash | Protocol::ParallelHashAvx2 => {
                    self.run_parallelhash(3, None, 0, None)?
                }
                #[cfg(feature = "strict-sha2-acceleration")]
                Protocol::Sha512Simd => self.run_sha512_simd(3, None, None)?,
                #[cfg(feature = "strict-sha2-acceleration")]
                Protocol::Sha256Simd => self.run_sha256_simd(3, None, None)?,
                #[cfg(feature = "strict-sha3-acceleration")]
                Protocol::KeccakSimd => self.run_keccak_simd(3, None, None, 0)?,
                Protocol::Legacy => self.run(3, None, 0, None)?,
            }
            self.live = false;
        }
        Ok(())
    }
}
impl Driver for Backend {
    fn begin(&mut self, input: &[u8], sequence: u64) -> Result<(), Error> {
        if self.live || self.epoch.checked_add(1) != Some(sequence) {
            return Err(Error::Protocol);
        }
        let header = protocol::header(input, sequence)?;
        self.epoch = sequence;
        self.generation = 0;
        self.live = true;
        self.run(0, None, 0, None)?;
        self.run(1, Some(&header), input.len(), None)
    }
    fn rehash(&mut self) -> Result<(), Error> {
        if !self.live {
            return Err(Error::Protocol);
        }
        self.run(8, None, 0, None)
    }
    fn export(&mut self, public: &mut [u8; 32]) -> Result<(), Error> {
        if !self.live {
            return Err(Error::Protocol);
        }
        self.run(2, None, 0, Some(public))?;
        self.clear()
    }
    fn cancel(&mut self) -> Result<(), Error> {
        if !self.live {
            return Err(Error::Protocol);
        }
        self.run(4, None, 0, None)?;
        self.clear()
    }
    fn close(&mut self) -> Result<(), Error> {
        if self.base == 0 {
            return Ok(());
        }
        if self.thread != sys::thread() || self.registrations_pending.get() {
            return Err(Error::Release);
        }
        self.clear().map_err(|_| Error::Release)?;
        if self.uncertain || self.slot != 0 || self.slot_locked {
            return Err(Error::Release);
        }
        sys::destroy(self.base, self.initialized, &mut self.terminated)?;
        self.base = 0;
        drop(self.pin.take());
        Ok(())
    }
}

#[cfg(test)]
mod tests;
