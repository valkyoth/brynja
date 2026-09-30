use super::{
    Error, ImagePolicy,
    engine::Driver,
    protocol::{self, Context},
};
use std::path::Path;
mod callback;
#[cfg(feature = "strict-kmac")]
pub(super) mod kmac;
mod pin;
pub(super) mod sha2;
pub(super) mod sha2_batch;
#[cfg(feature = "strict-sha3")]
pub(super) mod sha3;
mod sys;
#[cfg(feature = "strict-tuplehash")]
pub(super) mod tuplehash;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Sha2Batch,
    Legacy,
    Sha2,
    #[cfg(feature = "strict-sha3")]
    Sha3,
    #[cfg(feature = "strict-kmac")]
    Kmac,
    #[cfg(feature = "strict-tuplehash")]
    TupleHash,
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
    fn open_protocol(
        location: &Path,
        policy: &ImagePolicy,
        verify: impl FnOnce(&pin::Pin) -> Result<(), Error>,
        protocol: Protocol,
    ) -> Result<Self, Error> {
        if !sys::supported() {
            return Err(Error::Unsupported);
        }
        if !policy.valid() {
            return Err(Error::Image);
        }
        let pin = pin::Pin::open(location, policy)?;
        verify(&pin)?;
        let mut owner = Self {
            pin: Some(pin),
            base: 0,
            initialized: false,
            terminated: false,
            uncertain: false,
            thread: sys::thread(),
            entries: Entries::default(),
            slot: 0,
            slot_locked: false,
            live: false,
            epoch: 0,
            generation: 0,
            protocol,
        };
        owner.base = sys::create()?;
        sys::load(
            owner.base,
            &owner.pin.as_ref().ok_or(Error::Image)?.location,
        )?;
        let threads = sys::initialize(owner.base)?;
        owner.initialized = true;
        if threads != 1 {
            return Err(Error::Platform);
        }
        owner.entries = Entries {
            wire: sys::export(owner.base, b"PublicRetained\0")?,
            window: sys::export(owner.base, b"PublicLockedWindow\0")?,
            registration: sys::export(owner.base, b"PublicLockedHost\0")?,
            control: sys::export(owner.base, b"PublicRetainedControl\0")?,
            guard: sys::export(owner.base, b"PublicGuardControl\0")?,
            output: sys::export(owner.base, b"PublicRetainedOutput\0")?,
            input: sys::export(
                owner.base,
                match protocol {
                    Protocol::Sha2 => b"PublicSha2InputSource\0",
                    Protocol::Sha2Batch => b"PublicSha2BatchInputSource\0",
                    #[cfg(feature = "strict-sha3")]
                    Protocol::Sha3 => b"PublicSha3InputSource\0",
                    #[cfg(feature = "strict-kmac")]
                    Protocol::Kmac => b"PublicKmacInputSource\0",
                    #[cfg(feature = "strict-tuplehash")]
                    Protocol::TupleHash => b"PublicTupleInputSource\0",
                    Protocol::Legacy => b"PublicRetainedInput\0",
                },
            )?,
            input_control: if protocol != Protocol::Legacy {
                0
            } else {
                sys::export(owner.base, b"PublicInputControl\0")?
            },
            rehash_control: if protocol != Protocol::Legacy {
                0
            } else {
                sys::export(owner.base, b"PublicRehashControl\0")?
            },
            sha2_control: match protocol {
                Protocol::Sha2 => sys::export(owner.base, b"PublicSha2Control\0")?,
                Protocol::Sha2Batch => sys::export(owner.base, b"PublicSha2BatchControl\0")?,
                #[cfg(feature = "strict-sha3")]
                Protocol::Sha3 => sys::export(owner.base, b"PublicSha3Control\0")?,
                #[cfg(feature = "strict-kmac")]
                Protocol::Kmac => sys::export(owner.base, b"PublicKmacControl\0")?,
                #[cfg(feature = "strict-tuplehash")]
                Protocol::TupleHash => sys::export(owner.base, b"PublicTupleControl\0")?,
                Protocol::Legacy => 0,
            },
        };
        Ok(owner)
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
        let registrations = Registration {
            registration: self.entries.registration,
            input: self.entries.input,
            output: self.entries.output,
        };
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
                Protocol::Sha2 => self.run_sha2(3, None, 0, None)?,
                Protocol::Sha2Batch => self.run_sha2_batch(3, None, 0, None)?,
                #[cfg(feature = "strict-sha3")]
                Protocol::Sha3 => self.run_sha3(3, None, 0, None)?,
                #[cfg(feature = "strict-kmac")]
                Protocol::Kmac => self.run_kmac(3, None, 0, None)?,
                #[cfg(feature = "strict-tuplehash")]
                Protocol::TupleHash => self.run_tuplehash(3, None, 0, None)?,
                Protocol::Legacy => self.run(3, None, 0, None)?,
            }
            self.live = false;
        }
        Ok(())
    }
}
struct Registration {
    registration: usize,
    input: usize,
    output: usize,
}
impl Registration {
    fn revoke(self) {
        // Drop performs the same mandatory revocation on the success location.
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        let a = sys::call(self.registration, 0);
        let b = sys::call(self.output, 0);
        let c = sys::call(self.input, 0);
        if a != Ok(1) || b != Ok(1) || c != Ok(1) {
            std::process::abort();
        }
        // Context is normally consumed by run; it contains no Rust pointers.
        // On unwind it must not keep the thread occupied forever.
        if std::thread::panicking() {
            let _ = callback::take();
        }
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
        if self.thread != sys::thread() {
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
impl Drop for Backend {
    fn drop(&mut self) {
        if self.close().is_err() {
            // Never release file guards while an uncertain enclave remains.
            // No host callback borrows survive: revocation failures abort above.
            if let Some(pin) = self.pin.take() {
                core::mem::forget(pin);
            }
        }
    }
}

#[cfg(test)]
mod tests;
