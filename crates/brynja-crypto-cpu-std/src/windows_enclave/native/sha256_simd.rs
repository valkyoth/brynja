//! Version-21 transport; scoped borrows and the existing image/lifetime owner.
use super::super::{
    engine::Driver,
    sha256_simd::{
        Input,
        wire::{self, Request},
    },
};
use super::{Backend, Context, Error, ImagePolicy, Protocol, Registration, callback, sys};
use std::path::Path;

pub(crate) struct Transport(Backend);
impl Transport {
    pub(crate) fn open_avx2(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Backend::open_protocol(
            location,
            policy,
            |pin| pin.signature(),
            Protocol::Sha256Simd,
        )?))
    }
    pub(crate) fn request(
        &mut self,
        request: Request,
        inputs: &[Input<'_>; 8],
        output: Option<&mut [u8; 256]>,
    ) -> Result<(), Error> {
        let header = request.header(inputs)?;
        if !self.0.live {
            if request.op != 100 {
                return Err(Error::Protocol);
            }
            self.0.live = true;
            self.0.run_sha256_simd(0, None, None)?;
        }
        // `inputs` stays borrowed through this synchronous call and mandatory
        // address revocation. Only metadata pointers cross the host boundary.
        self.0.run_sha256_simd(request.op, Some(&header), output)
    }
    pub(crate) fn close(&mut self) -> Result<(), Error> {
        self.0.close()
    }
    #[cfg(test)]
    pub(crate) fn development(location: &Path, policy: &ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Backend::open_protocol(
            location,
            policy,
            |pin| {
                if pin.signature() != Err(Error::Signature) {
                    return Err(Error::Signature);
                }
                Ok(())
            },
            Protocol::Sha256Simd,
        )?))
    }
}
impl Backend {
    pub(super) fn run_sha256_simd(
        &mut self,
        operation: usize,
        input: Option<&[u8; 288]>,
        output: Option<&mut [u8; 256]>,
    ) -> Result<(), Error> {
        if self.protocol != Protocol::Sha256Simd
            || self.uncertain
            || self.terminated
            || self.base == 0
            || self.thread != sys::thread()
            || !matches!(operation, 0 | 3 | 100..=102)
            || matches!(operation, 0 | 3) == input.is_some()
            || (operation == 101) != output.is_some()
        {
            return Err(Error::Quarantined);
        }
        callback::install(Context {
            base: self.base,
            operation,
            slot: self.slot,
            slot_locked: self.slot_locked,
            ..Context::default()
        })?;
        let registration = Registration {
            registration: self.entries.registration,
            input: self.entries.input,
            output: self.entries.output,
        };
        self.uncertain = true;
        let result = (|| {
            if sys::call(self.entries.input, input.map_or(0, |v| v.as_ptr() as usize))? != 1
                || sys::call(
                    self.entries.output,
                    output.map_or(0, |v| v.as_mut_ptr() as usize),
                )? != 1
                || sys::call(self.entries.registration, callback::address())? != 1
            {
                return Err(Error::Protocol);
            }
            Ok((
                sys::call(self.entries.wire, operation)?,
                Self::read::<7>(self.entries.window, 2)?,
                Self::read::<13>(self.entries.guard, 16)?,
                Self::read::<10>(self.entries.control, 16)?,
                Self::read::<7>(self.entries.sha2_control, 16)?,
            ))
        })();
        registration.revoke();
        let context = callback::take()?;
        self.slot = context.slot;
        self.slot_locked = context.slot_locked;
        let (returned, outer, guards, inner, receipt) = result?;
        let expected = match operation {
            0 => 1,
            3 => 4,
            _ => operation,
        };
        context.inspect_common(returned, outer, guards, inner, expected, operation >= 100)?;
        wire::receipt(context.low, operation, receipt)?;
        if operation == 3 {
            self.slot = 0;
        } else if !sys::pages(self.slot, 1, true) {
            return Err(Error::Protocol);
        }
        self.uncertain = false;
        Ok(())
    }
}
