//! Private Windows executable adapter. Development execution is compiled only
//! into this probe; this is not a runtime fallback in a shipping constructor.
use super::{pin, sys};
use crate::{Error, ImagePolicy};
use core::marker::PhantomData;
use std::path::Path;
use std::sync::{Arc, Mutex};
mod callbacks;
use callbacks::{Context, Frames, Installed, Shared};

pub(crate) struct Enclave {
    pin: Option<pin::Pin>,
    base: usize,
    initialized: bool,
    terminated: bool,
    used: bool,
    shared: Option<Arc<Shared>>,
    thread_bound: PhantomData<*mut ()>,
}
impl Enclave {
    pub(crate) fn settled(&self) -> Result<(), Error> {
        self.shared.as_ref().ok_or(Error::Protocol)?.settled()
    }
    pub(crate) fn open(
        path: &Path,
        policy: &ImagePolicy,
        development: bool,
    ) -> Result<Self, Error> {
        if !sys::supported() {
            return Err(Error::Unsupported);
        }
        let pin = pin::Pin::open(path, policy)?;
        // Probe-only development branch still requires the production trust
        // check to reject this file. No code in this file is a shipping API.
        if development {
            if pin.signature() != Err(Error::Signature) {
                return Err(Error::Signature);
            }
        } else {
            pin.signature()?;
        }
        let mut result = Self {
            pin: Some(pin),
            base: 0,
            initialized: false,
            terminated: false,
            used: false,
            shared: None,
            thread_bound: PhantomData,
        };
        result.base = sys::create()?;
        sys::load(
            result.base,
            &result.pin.as_ref().ok_or(Error::Image)?.location,
        )?;
        let threads = sys::initialize(result.base)?;
        result.initialized = true;
        if threads != 5 {
            return Err(Error::Platform);
        }
        result.shared = Some(Arc::new(Shared {
            base: result.base,
            root: sys::export(result.base, b"PublicWaveRoot\0")?,
            leaf: sys::export(result.base, b"PublicWaveWorker\0")?,
            query: sys::export(result.base, b"PublicStackQuery\0")?,
            state: sys::export(result.base, b"PublicSchedulerState\0")?,
            register: sys::export(result.base, b"PublicStackRegister\0")?,
            output: sys::export(result.base, b"PublicInputOutputSource\0")?,
            frames: Mutex::new(Frames::default()),
        }));
        Ok(result)
    }

    pub(crate) fn execute(
        &mut self,
        header: &[u64; 16],
        output: &mut [u8],
        fault: u8,
    ) -> Result<(), Error> {
        if self.used {
            return Err(Error::Quarantined);
        }
        self.used = true;
        let shared = self.shared.as_ref().ok_or(Error::Protocol)?;
        let bits = *header.get(4).ok_or(Error::Bounds)?;
        let block = *header.get(3).ok_or(Error::Bounds)?;
        let scheduler = crate::scheduler::Scheduler::new(bits, block).map_err(|_| Error::Bounds)?;
        let guard = Installed::new(Context {
            shared: Arc::clone(shared),
            lane: 4,
            scheduler: Some(scheduler),
            fault,
            generation: 0,
        })?;
        // Owner, pin, input header and output remain borrowed for this entire
        // synchronous root entry; worker entries are joined by the Rust scope.
        {
            if sys::call(shared.register, callbacks::address())? != 1
                || sys::call(shared.output, output.as_mut_ptr() as usize)? != 1
            {
                return Err(Error::Protocol);
            }
            let returned = sys::call(shared.root, header.as_ptr() as usize)?;
            let context = guard.take()?;
            shared.verify(0, 4)?;
            let native = u64::try_from(sys::call(shared.state, 0)?).map_err(|_| Error::Protocol)?;
            if returned != 1 || shared.frames.lock().map_err(|_| Error::Protocol)?.failed {
                return Err(Error::Protocol);
            }
            context
                .scheduler
                .ok_or(Error::Protocol)?
                .finish(native)
                .map_err(|_| Error::Protocol)?;
            Ok(())
        }
    }
}
impl Drop for Enclave {
    fn drop(&mut self) {
        if self.base != 0
            && sys::destroy(self.base, self.initialized, &mut self.terminated).is_err()
        {
            // Do not release the image pin on uncertain enclave teardown.
            std::process::abort();
        }
    }
}
