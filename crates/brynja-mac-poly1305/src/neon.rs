//! Explicit NEON Poly1305 for AArch64 Linux and macOS. Ordinary `OneTimeKey::start`
//! remains portable, even with this feature enabled. Throughput depends on
//! contiguous update size; short updates use the ordinary scalar arithmetic.

use crate::{Error, OneTimeKey, Poly1305};
pub use brynja_crypto_cpu::poly1305_neon::{Error as AdmissionError, Neon};

/// A single message borrowing a previously tested, thread-local CPU handle.
#[must_use = "finish or verify the message; dropping clears the key"]
pub struct Poly1305Neon<'key, 'cpu> {
    message: Option<Poly1305<'key>>,
    cpu: &'cpu mut Neon,
}

impl<'key> OneTimeKey<'key> {
    /// Consume a fresh one-time key. Reuse the CPU handle, never the key.
    /// A retired handle is rejected and the consumed key storage is cleared.
    pub fn start_neon(self, cpu: &mut Neon) -> Result<Poly1305Neon<'key, '_>, Error> {
        cpu.check().map_err(|_| Error::Quarantined)?;
        Ok(Poly1305Neon {
            message: Some(self.start()),
            cpu,
        })
    }
}

struct Pending<'a, 'key> {
    slot: &'a mut Option<Poly1305<'key>>,
    committed: bool,
}
impl Drop for Pending<'_, '_> {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.slot.take());
        }
    }
}

impl Poly1305Neon<'_, '_> {
    /// Reject overflow before mutation. Any interruption after admission drops
    /// the message and clears its key, partial block and accumulator.
    pub fn update(&mut self, mut input: &[u8]) -> Result<(), Error> {
        self.cpu.check().map_err(|_| Error::Quarantined)?;
        let m = self.message.as_ref().ok_or(Error::Quarantined)?;
        let total = m
            .length
            .checked_add(u64::try_from(input.len()).map_err(|_| Error::TooLong)?)
            .ok_or(Error::TooLong)?;
        let mut pending = Pending {
            slot: &mut self.message,
            committed: false,
        };
        let m = pending.slot.as_mut().ok_or(Error::Quarantined)?;
        let prefix = if m.used == 0 {
            0
        } else {
            16usize.saturating_sub(m.used)
        };
        if input.len().saturating_sub(prefix) >= 1024 {
            let (head, body) = input.split_at(prefix);
            if !head.is_empty() {
                m.update(head)?;
            }
            let (groups, tail) = body.as_chunks::<32>();
            let raw_r = m.key.0.first_chunk::<16>().ok_or(Error::Quarantined)?;
            self.cpu
                .absorb_groups(&mut m.acc, raw_r, groups)
                .map_err(|_| Error::Quarantined)?;
            // The portable tail accounts for itself. Both lengths were
            // included in the preflight above, including a buffered prefix.
            m.length = total
                .checked_sub(u64::try_from(tail.len()).map_err(|_| Error::TooLong)?)
                .ok_or(Error::TooLong)?;
            input = tail;
        }
        m.update(input)?;
        pending.committed = true;
        Ok(())
    }

    /// Finish the full tag only while both the message and CPU are healthy.
    pub fn finalize(mut self) -> Result<[u8; 16], Error> {
        self.cpu.check().map_err(|_| Error::Quarantined)?;
        Ok(self.message.take().ok_or(Error::Quarantined)?.finalize())
    }

    /// Verify all 16 bytes using the portable owner's existing verifier.
    pub fn verify(mut self, tag: &[u8; 16]) -> Result<(), Error> {
        self.cpu.check().map_err(|_| Error::Quarantined)?;
        self.message.take().ok_or(Error::Quarantined)?.verify(tag)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn rejected_length_preserves_buffered_state_and_key() -> Result<(), Error> {
        let mut cpu = Neon::probe().map_err(|_| Error::Quarantined)?;
        let mut key = [0x67; 32];
        let mut native = OneTimeKey::new(&mut key)?.start_neon(&mut cpu)?;
        native.update(&[0x39; 1031])?;
        let m = native.message.as_mut().ok_or(Error::Quarantined)?;
        m.length = u64::MAX - 1;
        let before = (m.acc, m.tail, m.used, m.length);
        assert_eq!(native.update(&[0; 1024]), Err(Error::TooLong));
        let m = native.message.as_ref().ok_or(Error::Quarantined)?;
        assert_eq!((m.acc, m.tail, m.used, m.length), before);
        native.update(&[1])?;
        native.update(&[])?;
        assert_eq!(native.update(&[1]), Err(Error::TooLong));
        let _ = native.finalize()?;
        assert_eq!(key, [0; 32]);
        Ok(())
    }

    #[test]
    fn interrupted_pending_update_retires_the_message_and_clears_key() -> Result<(), Error> {
        let mut key = [0x35; 32];
        let mut slot = Some(OneTimeKey::new(&mut key)?.start());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let guard = Pending {
                slot: &mut slot,
                committed: false,
            };
            if let Some(m) = guard.slot.as_mut() {
                assert_eq!(m.update(&[0x59; 37]), Ok(()));
            }
            std::panic::resume_unwind(std::boxed::Box::new(()));
        }));
        assert!(result.is_err());
        assert!(slot.is_none());
        drop(slot);
        assert_eq!(key, [0; 32]);
        Ok(())
    }
}
