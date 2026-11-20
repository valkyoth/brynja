//! Private operation-local schedule owner; not public or fault-qualified.
//! Stores only separately borrowed raw-key replicas and lifecycle between calls.
//! Both schedules and decoded/captured temporary keys clear before output release.
use super::*;
use brynja_core::copy_secret_region;

pub(super) struct Ephemeral<'a> {
    lifecycle: Lifecycle,
    keys: Keys<'a>,
    local: core::marker::PhantomData<*mut ()>,
}

impl<'a> Ephemeral<'a> {
    pub(super) fn new(
        key: &[u8],
        primary: &'a mut [u8],
        secondary: &'a mut [u8],
    ) -> Result<Self, Error> {
        Self::new_profile(key, primary, secondary).map_err(Into::into)
    }

    pub(super) fn new_profile(
        key: &[u8],
        primary: &'a mut [u8],
        secondary: &'a mut [u8],
    ) -> Result<Self, ProfileFailure> {
        Ok(Self {
            keys: Keys::new_profile(key, primary, secondary)?,
            lifecycle: Lifecycle::new(),
            local: core::marker::PhantomData,
        })
    }

    fn compute(
        keys: &Keys<'_>,
        input: &[u8; 16],
        p: &mut [u8; 16],
        s: &mut [u8; 16],
        inverse: bool,
        completion: &mut super::super::transaction::Completion,
    ) -> Result<(), Error> {
        keys.validate()?;
        let mut first = Scratch::<32>::new();
        let mut second = Scratch::<32>::new();
        let width = keys.primary.len();
        let primary = first.0.get_mut(..width).ok_or(Error::SecretMemory)?;
        let complemented = second.0.get_mut(..width).ok_or(Error::SecretMemory)?;
        // Each domain reads only its own persistent key replica. The secondary
        // retains its complement encoding until independent expansion.
        copy_secret_region(primary, keys.primary)?;
        copy_secret_region(complemented, keys.complemented)?;
        #[cfg(all(test, brynja_fault_evidence))]
        recapture_evidence::checkpoint(primary, complemented);
        let mut retained = Retained::from_captured(Keys {
            primary,
            complemented,
        })?;
        let mut inner_completion = super::super::transaction::Completion::new();
        retained.compute(input, p, s, inverse, &mut inner_completion)?;
        inner_completion.check()?;
        #[cfg(all(test, brynja_fault_evidence))]
        evidence_tests::checkpoint(&mut retained)?;
        keys.validate()?;
        let mut difference = Scratch::<1>::new();
        let sum = difference.0.first_mut().ok_or(Error::SecretMemory)?;
        for (captured, stored) in retained.keys.primary.iter().zip(keys.primary.iter()) {
            *sum |= *captured ^ *stored;
        }
        for (captured, stored) in retained
            .keys
            .complemented
            .iter()
            .zip(keys.complemented.iter())
        {
            *sum |= *captured ^ *stored;
        }
        if *sum != 0 {
            return Err(Error::SecretMemory);
        }
        // All local clearing owners drop here, on error, and on unwind. Only
        // result scratch reaches the enclosing transaction's release checks.
        completion.mark_complete();
        Ok(())
    }

    pub(super) fn encrypt_public(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
        ack: PublicCiphertext,
    ) -> Result<(), Error> {
        self.encrypt_public_profile(input, output, ack)
            .map_err(Into::into)
    }

    pub(super) fn encrypt_public_profile(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
        ack: PublicCiphertext,
    ) -> Result<(), ProfileFailure> {
        self.lifecycle
            .public_profile(output, ack, |p, s, completion| {
                Self::compute(&self.keys, input, p, s, false, completion)
            })
    }

    pub(super) fn secret<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
        inverse: bool,
    ) -> Result<SecretBlock<'out>, Error> {
        self.secret_profile(input, output, inverse)
            .map_err(Into::into)
    }

    pub(super) fn secret_profile<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
        inverse: bool,
    ) -> Result<SecretBlock<'out>, ProfileFailure> {
        self.lifecycle.secret_profile(output, |p, s, completion| {
            Self::compute(&self.keys, input, p, s, inverse, completion)
        })
    }
}

#[cfg(all(test, brynja_fault_evidence))]
mod recapture_evidence;

#[cfg(all(test, brynja_fault_evidence))]
mod evidence_tests;
#[cfg(test)]
mod tests;
