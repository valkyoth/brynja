//! Private SHA-2 streaming protocol; reuses the same OS admission/lifetime owner.
use super::super::engine::Driver;
use super::{Backend, Context, Error, ImagePolicy, Registration, callback, sys};
use std::path::Path;

pub(crate) struct Transport(Backend);
impl Transport {
    pub(crate) fn open(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Backend::open_protocol(
            location,
            policy,
            |pin| pin.signature(),
            super::Protocol::Sha2,
        )?))
    }
    #[cfg(feature = "strict-sha2-acceleration")]
    pub(crate) fn open_sha_ni(
        location: &Path,
        policy: &'static ImagePolicy,
    ) -> Result<Self, Error> {
        Ok(Self(Backend::open_protocol(
            location,
            policy,
            |pin| pin.signature(),
            super::Protocol::Sha2ShaNi,
        )?))
    }
    pub(crate) fn request(
        &mut self,
        operation: usize,
        sequence: u64,
        algorithm: u64,
        input: &[u8],
        last: u8,
        output: Option<&mut [u8]>,
    ) -> Result<(), Error> {
        if !self.0.live {
            if operation != 11 {
                return Err(Error::Protocol);
            }
            self.0.live = true;
            self.0.run_sha2(0, None, 0, None)?;
        }
        if self.0.protocol == super::Protocol::Sha2ShaNi {
            let header = super::super::sha2_wire::sha_ni_header(sequence, algorithm, input, last)?;
            self.0
                .run_sha2(operation, Some(&header), input.len(), output)
        } else {
            let header = super::super::sha2_wire::header(sequence, algorithm, input, last)?;
            self.0
                .run_sha2(operation, Some(&header), input.len(), output)
        }
    }
    pub(crate) fn close(&mut self) -> Result<(), Error> {
        self.0.close()
    }
    #[cfg(test)]
    pub(crate) fn development(location: &Path, policy: &ImagePolicy) -> Result<Self, Error> {
        Self::development_route(location, policy, super::Protocol::Sha2)
    }
    #[cfg(all(test, feature = "strict-sha2-acceleration"))]
    pub(crate) fn development_sha_ni(location: &Path, policy: &ImagePolicy) -> Result<Self, Error> {
        Self::development_route(location, policy, super::Protocol::Sha2ShaNi)
    }
    #[cfg(test)]
    fn development_route(
        location: &Path,
        policy: &ImagePolicy,
        route: super::Protocol,
    ) -> Result<Self, Error> {
        Ok(Self(Backend::open_protocol(
            location,
            policy,
            |pin| {
                if pin.signature() != Err(Error::Signature) {
                    return Err(Error::Signature);
                }
                Ok(())
            },
            route,
        )?))
    }
}

impl Backend {
    pub(super) fn run_sha2(
        &mut self,
        operation: usize,
        input: Option<&[u8]>,
        length: usize,
        output: Option<&mut [u8]>,
    ) -> Result<(), Error> {
        let accelerated = self.protocol == super::Protocol::Sha2ShaNi;
        if !matches!(
            self.protocol,
            super::Protocol::Sha2 | super::Protocol::Sha2ShaNi
        ) || self.uncertain
            || self.terminated
            || self.base == 0
            || self.thread != sys::thread()
            || !matches!(operation, 0 | 3 | 11..=16)
            || matches!(operation, 0 | 3) == input.is_some()
            || input.is_some_and(|v| v.len() != if accelerated { 64 } else { 48 })
            || (operation == 15) != output.is_some()
            || output
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > if accelerated { 32 } else { 64 })
        {
            return Err(Error::Quarantined);
        }
        callback::install(Context {
            base: self.base,
            operation,
            length,
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
        context.inspect_common(returned, outer, guards, inner, expected, operation >= 11)?;
        if accelerated {
            super::super::sha2_wire::sha_ni_receipt(context.low, operation, length, receipt)?;
        } else {
            super::super::sha2_wire::receipt(context.low, operation, length, receipt)?;
        }
        if operation == 3 {
            self.slot = 0;
        } else if !sys::pages(self.slot, 1, true) {
            return Err(Error::Protocol);
        }
        self.uncertain = false;
        Ok(())
    }
}
