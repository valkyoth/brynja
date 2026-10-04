//! Scoped five-thread VBS transport. Production admission never bypasses trust.
use super::super::parallel_concurrent::Request;
use super::{Error, ImagePolicy, pin, sys};
mod scheduler;
use core::marker::PhantomData;
use std::path::Path;
use std::sync::{Arc, Mutex};
mod callbacks;
use callbacks::{Context, Frames, Installed, Shared};

pub(in crate::windows_enclave) struct Transport {
    pin: Option<pin::Pin>,
    base: usize,
    initialized: bool,
    terminated: bool,
    used: bool,
    shared: Option<Arc<Shared>>,
    thread_bound: PhantomData<*mut ()>,
}
impl Transport {
    #[cfg(test)]
    pub(in crate::windows_enclave) fn test_budget() -> Result<(), Error> {
        sys::test_parallel_budget()
    }
    pub(in crate::windows_enclave) fn open_avx2(
        location: &Path,
        policy: &'static ImagePolicy,
    ) -> Result<Self, Error> {
        Self::open_with(location, policy, |pin| pin.signature())
    }
    #[cfg(test)]
    pub(in crate::windows_enclave) fn development(
        location: &Path,
        policy: &ImagePolicy,
    ) -> Result<Self, Error> {
        Self::open_with(location, policy, |pin| {
            if pin.signature() != Err(Error::Signature) {
                return Err(Error::Signature);
            }
            Ok(())
        })
    }

    pub(in crate::windows_enclave) fn settled(&self) -> Result<(), Error> {
        self.shared.as_ref().ok_or(Error::Protocol)?.settled()
    }
    fn open_with(
        location: &Path,
        policy: &ImagePolicy,
        verify: impl FnOnce(&pin::Pin) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        if !sys::supported() {
            return Err(Error::Unsupported);
        }
        let pin = pin::Pin::open_threads(location, policy, 5)?;
        verify(&pin)?;
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
        let threads = sys::initialize_threads(result.base, 5)?;
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

    pub(in crate::windows_enclave) fn execute(
        &mut self,
        request: &Request<'_>,
        output: &mut [u8; 1024],
    ) -> Result<(), Error> {
        if self.used {
            return Err(Error::Quarantined);
        }
        self.used = true;
        let guard = Entry(self);
        guard.0.run(request, output)
        // Entry tears down the one-shot enclave before any caller borrow ends,
        // including failure/unwind paths. A teardown failure is fail-stop.
    }
    fn run(&mut self, request: &Request<'_>, output: &mut [u8; 1024]) -> Result<(), Error> {
        let shared = self.shared.as_ref().ok_or(Error::Protocol)?;
        let header = request.header()?;
        let bits = *header.get(4).ok_or(Error::Bounds)?;
        let block = *header.get(3).ok_or(Error::Bounds)?;
        let scheduler = scheduler::Scheduler::new(bits, block).map_err(|_| Error::Bounds)?;
        let guard = Installed::new(Context {
            shared: Arc::clone(shared),
            lane: 4,
            scheduler: Some(scheduler),
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
    fn teardown(&mut self) {
        if self.base != 0
            && sys::destroy(self.base, self.initialized, &mut self.terminated).is_err()
        {
            // Do not release the image pin on uncertain enclave teardown.
            std::process::abort();
        }
        self.base = 0;
        self.pin = None;
    }
    #[cfg(test)]
    pub(in crate::windows_enclave) fn test_closed(&self) -> bool {
        self.base == 0 && self.pin.is_none() && self.terminated
    }
}
struct Entry<'a>(&'a mut Transport);
impl Drop for Entry<'_> {
    fn drop(&mut self) {
        self.0.teardown();
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        self.teardown();
    }
}
