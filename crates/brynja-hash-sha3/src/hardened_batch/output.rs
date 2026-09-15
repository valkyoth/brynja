use super::{Algorithm, CAPACITY, Error, Input, Sha3PublicDeclassification};
use brynja_core::clear_owned_region;
use core::marker::PhantomData;

/// Exact-identity, non-copying owner of completed borrowed secret digest slots.
/// Drop clears all destinations. Exposed byte copies remain caller-owned.
///
/// A view cannot survive its owner or authorize an implicit public conversion.
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::SecretBatchOutput;
/// fn escape<'a>(out: SecretBatchOutput<'a>) -> Option<&'a [u8]> {
///     out.expose(0)
/// }
/// ```
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::SecretBatchOutput;
/// fn move_with_live_view(out: SecretBatchOutput<'_>) {
///     let view = out.expose(0);
///     drop(out);
///     core::hint::black_box(view);
/// }
/// ```
/// ```compile_fail
/// use brynja_hash_sha3::{Sha3_256Digest, hardened_batch::SecretBatchOutput};
/// fn implicit_public(out: SecretBatchOutput<'_>) -> Sha3_256Digest { out.into() }
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::SecretBatchOutput;
/// fn require<T: Send>() {}
/// require::<SecretBatchOutput<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::SecretBatchOutput;
/// fn require<T: Sync>() {}
/// require::<SecretBatchOutput<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::SecretBatchOutput;
/// fn require<T: Copy>() {}
/// require::<SecretBatchOutput<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::SecretBatchOutput;
/// fn require<T: Clone>() {}
/// require::<SecretBatchOutput<'_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_sha3::hardened_batch::SecretBatchOutput;
/// fn require<T: core::fmt::Debug>() {}
/// require::<SecretBatchOutput<'_>>();
/// ```
pub struct SecretBatchOutput<'a> {
    pub(super) destinations: [Option<&'a mut [u8]>; CAPACITY],
    pub(super) identities: [u8; CAPACITY],
    pub(super) bits: [[u8; 8]; CAPACITY],
    thread_bound: PhantomData<*mut ()>,
}
impl<'a> SecretBatchOutput<'a> {
    pub(super) fn new(destinations: [Option<&'a mut [u8]>; CAPACITY]) -> Self {
        Self {
            destinations,
            identities: [0; CAPACITY],
            bits: [[0; 8]; CAPACITY],
            thread_bound: PhantomData,
        }
    }
    /// Explicit view of a completed slot, borrowing this output owner's lifetime.
    pub fn expose(&self, index: usize) -> Option<&[u8]> {
        self.destinations.get(index)?.as_deref()
    }
    /// Public exact algorithm identity; absent for inactive or invalid slots.
    pub fn algorithm(&self, index: usize) -> Option<Algorithm> {
        Algorithm::from_code(*self.identities.get(index)?)
    }
    /// Exact finite output bit count; absent for inactive/invalid slots.
    pub fn output_bits(&self, index: usize) -> Option<usize> {
        self.algorithm(index)?;
        super::framing::number(self.bits.get(index)?).ok()
    }
    /// Consumes the secret owner and explicitly copies all digests into public
    /// slots, then clears the secret originals. On shape error public output is
    /// untouched and the consumed secret owner still clears on Drop.
    pub fn declassify(
        self,
        mut destinations: [Option<&mut [u8]>; CAPACITY],
        _authority: Sha3PublicDeclassification,
    ) -> Result<(), Error> {
        for (source, destination) in self.destinations.iter().zip(&destinations) {
            match (source, destination) {
                (None, None) => {}
                (Some(source), Some(destination)) if source.len() == destination.len() => {}
                _ => return Err(Error::InvalidDestination),
            }
        }
        for (source, destination) in self.destinations.iter().zip(&mut destinations) {
            if let (Some(source), Some(destination)) = (source, destination) {
                destination.copy_from_slice(source);
            }
        }
        Ok(())
    }
}
impl Drop for SecretBatchOutput<'_> {
    fn drop(&mut self) {
        for destination in self.destinations.iter_mut().flatten() {
            if !destination.is_empty() {
                let _ = clear_owned_region(destination);
            }
        }
        let _ = clear_owned_region(&mut self.identities);
        let _ = clear_owned_region(self.bits.as_flattened_mut());
    }
}
pub(super) fn validate(
    inputs: &[Option<Input<'_>>; CAPACITY],
    destinations: &[Option<&mut [u8]>; CAPACITY],
) -> Result<(), Error> {
    for (input, destination) in inputs.iter().zip(destinations) {
        match (input, destination) {
            (None, None) => {}
            (Some(input), Some(destination)) if destination.len() == input.output_bytes() => {}
            _ => return Err(Error::InvalidDestination),
        }
    }
    Ok(())
}
