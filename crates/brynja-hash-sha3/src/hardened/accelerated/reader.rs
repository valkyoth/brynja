use super::super::output::{begin_secret, finish_secret};
use super::{
    Error, HardenedSha3SecretOutput, Report, Sha3PublicDeclassification,
    engine::{Engine, Operation},
};
use crate::Fips202Output;
use brynja_core::clear_owned_region;

/// Affine, thread-bound accelerated XOF reader. It retains the selected session.
/// Secret output is typed; releasing public output requires explicit declassification.
pub struct Reader<'a> {
    pub(super) engine: Engine<'a>,
}

pub(super) struct Stage(pub(super) [u8; 168]);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
    }
}
struct BorrowedStage<'a>(&'a mut [u8]);
impl Drop for BorrowedStage<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0);
    }
}

impl Reader<'_> {
    /// Observes exact backend health without granting authority.
    pub fn report(&self) -> Report {
        self.engine.report()
    }
    /// Irreversibly cancels this reader and clears its owned sponge state.
    pub fn cancel(&mut self) {
        self.engine.cancel();
    }

    /// Releases at most 168 bytes as public; failures preserve destination.
    /// Use caller-owned scratch for larger transactional public reads.
    pub fn squeeze_public(
        &mut self,
        output: &mut [u8],
        authority: Sha3PublicDeclassification,
    ) -> Result<(), Error> {
        let mut stage = Stage([0; 168]);
        self.squeeze_public_with_scratch(output, &mut stage.0, authority)
    }

    /// Releases arbitrary-length public output transactionally. Scratch must be
    /// at least output.len(), is treated as secret during the operation, and is
    /// completely cleared on success, error and recoverable unwind. It must not
    /// alias output; the Rust borrows enforce this. Failures terminate the reader.
    pub fn squeeze_public_with_scratch(
        &mut self,
        output: &mut [u8],
        scratch: &mut [u8],
        authority: Sha3PublicDeclassification,
    ) -> Result<(), Error> {
        self.engine.read_public(output, scratch, authority)
    }

    /// Initializes a typed secret output of arbitrary length. All destination
    /// bytes clear on any failure and on the returned owner's Drop.
    pub fn squeeze_secret<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
        self.engine.read_secret(output, 8)
    }

    /// Consumes the reader, emits canonical LSB-first output bits, and transfers
    /// typed secret ownership. Invalid shape clears the entire destination.
    pub fn squeeze_final_bits_secret<'out>(
        mut self,
        output: &'out mut [u8],
        valid_bits: u8,
    ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
        if (output.is_empty() && valid_bits != 0)
            || (!output.is_empty() && !(1..=8).contains(&valid_bits))
        {
            let _ = clear_owned_region(output);
            return Err(Error::OutputLength);
        }
        self.engine.read_secret(output, valid_bits)
    }

    /// Consumes the reader and declassifies canonical partial-byte output with
    /// caller-owned erasing scratch. No state can continue after a partial byte.
    pub fn squeeze_final_bits_public(
        mut self,
        output: Fips202Output<'_>,
        scratch: &mut [u8],
        authority: Sha3PublicDeclassification,
    ) -> Result<(), Error> {
        let (bytes, valid) = output.into_parts();
        self.squeeze_public_with_scratch(bytes, scratch, authority)?;
        if valid != 0
            && valid != 8
            && let Some(last) = bytes.last_mut()
        {
            *last &= u8::MAX >> 8_u8.saturating_sub(valid);
        }
        Ok(())
    }
}

impl Engine<'_> {
    pub(super) fn read_public(
        &mut self,
        output: &mut [u8],
        scratch: &mut [u8],
        _authority: Sha3PublicDeclassification,
    ) -> Result<(), Error> {
        let stage = BorrowedStage(scratch);
        let mut operation = Operation::new(self);
        let buffer = stage.0.get_mut(..output.len()).ok_or(Error::OutputLength)?;
        operation.engine.read(buffer)?;
        output.copy_from_slice(buffer);
        operation.completed = true;
        Ok(())
    }

    pub(super) fn read_secret<'out>(
        &mut self,
        output: &'out mut [u8],
        valid: u8,
    ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
        let mut operation = Operation::new(self);
        let length = output.len();
        let mut initialization = begin_secret(output)?;
        if (length == 0 && valid != 0 && valid != 8) || (length != 0 && !(1..=8).contains(&valid)) {
            return Err(Error::OutputLength);
        }
        operation.engine.preflight(length)?;
        let mut stage = Stage([0; 168]);
        let mut remaining = length;
        while remaining != 0 {
            let count = remaining.min(stage.0.len());
            let buffer = stage.0.get_mut(..count).ok_or(Error::OutputLength)?;
            operation.engine.read(buffer)?;
            if remaining == count && valid != 8 {
                let last = buffer.last_mut().ok_or(Error::OutputLength)?;
                *last &= u8::MAX >> 8_u8.saturating_sub(valid);
            }
            initialization
                .as_mut()
                .ok_or(Error::SecretMemory)?
                .write(buffer)
                .map_err(|_| Error::SecretMemory)?;
            let _ = clear_owned_region(&mut stage.0);
            remaining = remaining.saturating_sub(count);
        }
        let output = finish_secret(initialization)?;
        operation.completed = true;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::BorrowedStage;

    #[test]
    fn borrowed_staging_clears_on_drop_and_unwind() {
        let mut buffer = [0xa5; 201];
        drop(BorrowedStage(&mut buffer));
        assert_eq!(buffer, [0; 201]);
        buffer.fill(0x9b);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = BorrowedStage(&mut buffer);
            std::panic::resume_unwind(std::boxed::Box::new("staging unwind"));
        }));
        assert!(result.is_err());
        assert_eq!(buffer, [0; 201]);
    }
}
