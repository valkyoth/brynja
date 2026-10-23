use super::{Bits, Error, PublicDeclassification, ResidentBytes};

/// One borrowed legacy lane. Input buffers remain caller-owned.
pub struct Md5BatchInput<'a> {
    /// Unpredictable legacy key; empty/predictable keys are accepted but insecure.
    pub key: &'a [u8],
    /// Canonical MSB-first message; secret bit contents are checked on worker.
    pub message: Bits<'a>,
}
/// Public per-session bounds, applied afresh to each complete batch.
/// Stack reservation is not a worst-case depth proof.
#[derive(Clone, Copy, Debug)]
pub struct Md5BatchLimits {
    /// Worker stack reservation, minimum 64 KiB allocation floor.
    pub stack_bytes: usize,
    /// Maximum stack mapping including guards and rounding.
    pub max_stack_mapping_bytes: usize,
    /// Maximum individual staging/output mapping including guards and rounding.
    pub max_buffer_mapping_bytes: usize,
    /// Maximum bytes in EACH active key (at most eight keys).
    pub max_key_bytes: usize,
    /// Maximum bits in EACH active message (at most eight messages).
    pub max_message_bits: u128,
    /// Shared actual independent-message compressions across key/inner/outer
    /// phases, including padding. Zero is valid but cannot complete a batch.
    pub max_compressions: usize,
}
/// Affine loan over all 128 output bytes. Dropping it clears every slot, not
/// just the exposed prefix. Forgetting a loan cannot prevent session clearing.
///
/// ```compile_fail
/// fn bound<T: Clone>() {}
/// bound::<brynja_legacy_hmac_std::macos_resident::Md5BatchOutput<'static>>();
/// ```
pub struct Md5BatchOutput<'a> {
    pub(super) storage: &'a mut ResidentBytes,
    pub(super) active: [bool; 8],
    pub(super) bytes: usize,
}
impl Md5BatchOutput<'_> {
    /// Explicit secret exposure of one active tag; invalid/inactive slots yield
    /// None. Copies become the caller's responsibility.
    pub fn expose(&self, lane: usize) -> Option<&[u8]> {
        if !self.active.get(lane).copied().unwrap_or(false) {
            return None;
        }
        let start = lane.checked_mul(16)?;
        self.storage
            .as_bytes()
            .get(start..start.checked_add(self.bytes)?)
    }
    /// Explicit public release; inactive slots and trailing truncation bytes
    /// are zero. The retained mapping clears when this loan is consumed.
    pub fn declassify(
        self,
        output: &mut [[u8; 16]; 8],
        _ack: PublicDeclassification,
    ) -> Result<(), Error> {
        brynja_core::copy_secret_region(output.as_flattened_mut(), self.storage.as_bytes())
            .map_err(|_| Error::Invariant)
    }
}
impl Drop for Md5BatchOutput<'_> {
    fn drop(&mut self) {
        self.storage.clear();
    }
}
pub(super) fn validate(
    inputs: &[Option<Md5BatchInput<'_>>; 8],
    candidates: Option<&[Option<&[u8]>; 8]>,
    limits: Md5BatchLimits,
    width: usize,
    bytes: usize,
) -> Result<(), Error> {
    if !matches!(width, 4 | 8) {
        return Err(Error::Invariant);
    }
    if !inputs
        .chunks(width)
        .any(|group| group.iter().all(Option::is_some))
    {
        return Err(Error::Mac(brynja_legacy_hmac::Error::IneligibleWorkload));
    }
    for (lane, input) in inputs.iter().enumerate() {
        if let Some(input) = input
            && (input.key.len() > limits.max_key_bytes
                || input.message.bit_len()? > limits.max_message_bits)
        {
            return Err(Error::WorkLimit);
        }
        if let Some(candidates) = candidates {
            match (input, candidates.get(lane).ok_or(Error::Invariant)?) {
                (None, None) => (),
                (Some(_), Some(candidate)) if candidate.len() == bytes => (),
                _ => return Err(Error::OutputLength),
            }
        }
    }
    Ok(())
}
