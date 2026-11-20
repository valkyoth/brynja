//! Private retained-key integration. NOT a qualified/public fault-integrity owner.
//! Separate borrows are logical independence, not separate physical fault domains.
//! Capture uses core transfer calls; linked independence, checks and normalization
//! remain unqualified for D3/C1/DC1.
use super::{
    Error, ProfileFailure, Scratch, primary::Primary, read, schedule::Schedule,
    transaction::Lifecycle,
};
use crate::aes::{PublicCiphertext, SecretBlock};

struct Keys<'a> {
    primary: &'a mut [u8],
    complemented: &'a mut [u8],
}

impl<'a> Keys<'a> {
    fn new_profile(
        key: &[u8],
        primary: &'a mut [u8],
        complemented: &'a mut [u8],
    ) -> Result<Self, ProfileFailure> {
        Self::new_with_fixture_profile(key, primary, complemented, cfg!(test))
    }

    fn new_with_fixture_profile(
        key: &[u8],
        primary: &'a mut [u8],
        complemented: &'a mut [u8],
        workbench_fixture: bool,
    ) -> Result<Self, ProfileFailure> {
        // Fail closed before reading, copying or expanding key material.
        // Only the test harness may exercise the unqualified fixture owner.
        super::admission::require(workbench_fixture)
            .map_err(|_| ProfileFailure::UnsupportedBuild)?;
        // After build admission, borrow both buffers before validation so
        // every later import error clears both.
        let keys = Self {
            primary,
            complemented,
        };
        if !matches!(key.len(), 16 | 24 | 32)
            || keys.primary.len() != key.len()
            || keys.complemented.len() != key.len()
        {
            return Err(ProfileFailure::ImportRejected);
        }
        super::capture::pair(key, keys.primary, keys.complemented)
            .map_err(|_| ProfileFailure::ImportRejected)?;
        for destination in keys.complemented.iter_mut() {
            *destination = !*destination;
        }
        #[cfg(all(test, brynja_fault_evidence))]
        encoding_evidence::checkpoint(keys.primary, keys.complemented);
        keys.validate()
            .map_err(|_| ProfileFailure::ImportRejected)?;
        Ok(keys)
    }

    fn validate(&self) -> Result<(), Error> {
        if !matches!(self.primary.len(), 16 | 24 | 32)
            || self.primary.len() != self.complemented.len()
        {
            return Err(Error::SecretMemory);
        }
        let mut difference = Scratch::<1>::new();
        let sum = difference.0.first_mut().ok_or(Error::SecretMemory)?;
        for (primary, complemented) in self.primary.iter().zip(self.complemented.iter()) {
            *sum |= *primary ^ !*complemented;
        }
        if *sum == 0 {
            Ok(())
        } else {
            Err(Error::SecretMemory)
        }
    }
}

#[cfg(all(test, brynja_fault_evidence))]
mod encoding_evidence;

impl Drop for Keys<'_> {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(self.primary);
        let _ = brynja_core::clear_owned_region(self.complemented);
        #[cfg(test)]
        crate::aes::tests::observe_clear(self.primary);
        #[cfg(test)]
        crate::aes::tests::observe_clear(self.complemented);
    }
}

struct Retained<'a> {
    keys: Keys<'a>,
    primary: Primary,
    secondary: Schedule,
}

impl<'a> Retained<'a> {
    #[cfg(all(test, brynja_fault_evidence))]
    fn new(key: &[u8], primary: &'a mut [u8], complemented: &'a mut [u8]) -> Result<Self, Error> {
        Self::new_profile(key, primary, complemented).map_err(Into::into)
    }

    fn new_profile(
        key: &[u8],
        primary: &'a mut [u8],
        complemented: &'a mut [u8],
    ) -> Result<Self, ProfileFailure> {
        Self::from_captured(Keys::new_profile(key, primary, complemented)?)
            .map_err(|_| ProfileFailure::ImportRejected)
    }

    // Accept two already separate, encoded captures. Never regenerate the
    // secondary key from the primary when making operation-local schedules.
    fn from_captured(keys: Keys<'a>) -> Result<Self, Error> {
        keys.validate()?;
        let schedule = Primary::new(keys.primary.len())?;
        let mut retained = Self {
            keys,
            primary: schedule,
            secondary: Schedule::new(),
        };
        retained.primary.expand(retained.keys.primary)?;
        let mut decoded = Scratch::<32>::new();
        let bytes = decoded
            .0
            .get_mut(..retained.keys.primary.len())
            .ok_or(Error::SecretMemory)?;
        for (destination, source) in bytes.iter_mut().zip(retained.keys.complemented.iter()) {
            *destination = !source;
        }
        // Each engine expands only its own key capture; decoded is never used
        // as the primary's expansion input. Compiler fusion is still unqualified.
        retained.secondary.expand(bytes)?;
        #[cfg(all(test, brynja_fault_evidence))]
        evidence_tests::checkpoint(evidence_tests::Stage::Import, &mut retained)?;
        retained.validate()?;
        Ok(retained)
    }

    fn validate(&self) -> Result<(), Error> {
        let width = self.primary.width();
        let rounds = match width {
            16 => 10,
            24 => 12,
            32 => 14,
            _ => return Err(Error::SecretMemory),
        };
        if self.keys.primary.len() != width
            || self.keys.complemented.len() != width
            || self.secondary.rounds != rounds
        {
            return Err(Error::SecretMemory);
        }
        let mut difference = Scratch::<1>::new();
        let sum = difference.0.first_mut().ok_or(Error::SecretMemory)?;
        for (position, byte) in self.keys.primary.iter().enumerate() {
            *sum |= *byte ^ !read(self.keys.complemented, position)?;
            // Tie retained keys to the schedule's initial Nk words; this also
            // prevents two matching changed key captures agreeing with old keys.
            *sum |= *byte ^ read(self.primary.as_bytes(), position)?;
        }
        let mut decoded = Scratch::<16>::new();
        for (round, plane) in self.secondary.keys.iter().enumerate() {
            plane.store(&mut decoded.0)?;
            for (byte, actual) in decoded.0.iter().enumerate() {
                let position = round.wrapping_mul(16).wrapping_add(byte);
                let expected = if round <= rounds {
                    read(self.primary.as_bytes(), position)?
                } else {
                    0
                };
                *sum |= *actual ^ expected;
            }
        }
        // Includes every active round and all unused secondary storage. No
        // normalization writes either retained schedule or repairs disagreement.
        if *sum == 0 {
            Ok(())
        } else {
            Err(Error::SecretMemory)
        }
    }

    fn compute(
        &mut self,
        input: &[u8; 16],
        p: &mut [u8; 16],
        s: &mut [u8; 16],
        inverse: bool,
        completion: &mut super::transaction::Completion,
    ) -> Result<(), Error> {
        let mut first_input = Scratch::<16>::new();
        let mut second_input = Scratch::<16>::new();
        super::capture::pair(input, &mut first_input.0, &mut second_input.0)?;
        #[cfg(all(test, brynja_fault_evidence))]
        evidence_tests::checkpoint(evidence_tests::Stage::Before, self)?;
        self.validate()?;
        if first_input.0 != second_input.0 {
            return Err(Error::SecretMemory);
        }
        p.copy_from_slice(&first_input.0);
        self.primary.transform(p, inverse)?;
        #[cfg(all(test, brynja_fault_evidence))]
        evidence_tests::checkpoint(evidence_tests::Stage::AfterPrimary, self)?;
        self.secondary.transform(&second_input.0, s, inverse)?;
        #[cfg(all(test, brynja_fault_evidence))]
        evidence_tests::checkpoint(evidence_tests::Stage::AfterCompute, self)?;
        // Mandatory post-use retained-storage check BEFORE the transaction can
        // tentatively write any output, even when both computed results agree.
        self.validate()?;
        if first_input.0 != second_input.0 {
            return Err(Error::SecretMemory);
        }
        completion.mark_complete();
        Ok(())
    }
}

struct Cached<'a> {
    lifecycle: Lifecycle,
    retained: Retained<'a>,
    local: core::marker::PhantomData<*mut ()>,
}

impl<'a> Cached<'a> {
    fn new(key: &[u8], primary: &'a mut [u8], secondary: &'a mut [u8]) -> Result<Self, Error> {
        Self::new_profile(key, primary, secondary).map_err(Into::into)
    }

    fn new_profile(
        key: &[u8],
        primary: &'a mut [u8],
        secondary: &'a mut [u8],
    ) -> Result<Self, ProfileFailure> {
        Ok(Self {
            retained: Retained::new_profile(key, primary, secondary)?,
            lifecycle: Lifecycle::new(),
            local: core::marker::PhantomData,
        })
    }

    fn encrypt_public(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
        ack: PublicCiphertext,
    ) -> Result<(), Error> {
        self.encrypt_public_profile(input, output, ack)
            .map_err(Into::into)
    }

    fn encrypt_public_profile(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
        ack: PublicCiphertext,
    ) -> Result<(), ProfileFailure> {
        self.lifecycle
            .public_profile(output, ack, |p, s, completion| {
                self.retained.compute(input, p, s, false, completion)
            })
    }

    fn secret<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
        inverse: bool,
    ) -> Result<SecretBlock<'out>, Error> {
        self.secret_profile(input, output, inverse)
            .map_err(Into::into)
    }

    fn secret_profile<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
        inverse: bool,
    ) -> Result<SecretBlock<'out>, ProfileFailure> {
        self.lifecycle.secret_profile(output, |p, s, completion| {
            self.retained.compute(input, p, s, inverse, completion)
        })
    }
}

#[cfg(test)]
mod avs_tests;
#[cfg(all(test, brynja_fault_evidence))]
mod common_mode_constant_tests;
mod ephemeral;
#[cfg(all(test, brynja_fault_evidence))]
mod evidence_tests;
#[cfg(all(test, brynja_fault_evidence))]
mod persistent_constant_tests;
#[cfg(all(test, brynja_fault_evidence))]
mod primary_constant_tests;
#[cfg(test)]
mod probe_tests;
#[cfg(test)]
mod tests;
