use super::{Batch, Error, Request, State};
/// Exclusive slot writer. Drop quarantines, while forgetting leaves the batch
/// busy until cancellation or closure. No accumulated-length preflight oracle.
#[must_use = "finish the item"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Item<'static, 'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Item<'static, 'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Item<'static, 'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Item<'static, 'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Item<'static, 'static>>();\n```"]
pub struct Item<'s, 'a> {
    pub(super) batch: &'s mut Batch<'a>,
    pub(super) slot: usize,
    pub(super) complete: bool,
}
impl Item<'_, '_> {
    /// Public slot index selected from the declared plan.
    #[must_use]
    pub fn slot(&self) -> usize {
        self.slot
    }
    /// Copy complete bytes into bounded enclave snapshots.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        if input.is_empty() {
            return self.batch.0.session.0.issue(
                Request {
                    op: 82,
                    slot: self.slot,
                    ..Request::default()
                },
                &[],
                None,
            );
        }
        for chunk in input.chunks(1024) {
            self.batch.0.session.0.issue(
                Request {
                    op: 82,
                    slot: self.slot,
                    last: 8,
                    ..Request::default()
                },
                chunk,
                None,
            )?;
        }
        Ok(())
    }
    /// Complete this slot, retaining its result inside the batch owner.
    pub fn finish(self) -> Result<(), Error> {
        self.finish_bits(&[], 0)
    }
    /// Finish with canonical MSB-first bits. Empty input requires last=0;
    /// otherwise last=1..=8 and unused low bits must be zero. Invalid input
    /// terminates the batch. The worker independently validates the copied tail.
    pub fn finish_bits(mut self, input: &[u8], last: u8) -> Result<(), Error> {
        brynja_hash_sha2::BitString::new(input, last).map_err(|_| Error::Bounds)?;
        let split = input.len().saturating_sub(1);
        if split != 0 {
            self.update(input.get(..split).ok_or(Error::Bounds)?)?;
        }
        self.batch.0.session.0.issue(
            Request {
                op: 83,
                slot: self.slot,
                last,
                ..Request::default()
            },
            input.get(split..).ok_or(Error::Bounds)?,
            None,
        )?;
        self.batch.0.next = self.slot.checked_add(1).ok_or(Error::Bounds)?;
        self.batch.0.item_open = false;
        self.complete = true;
        Ok(())
    }
}
impl Drop for Item<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.batch.0.session.0.state = State::Quarantined;
        }
    }
}
