"""Bounded real streaming update/flush ownership proof, with a modeled consumer.

The collector's otherwise-unused pre-output fields carry an oracle payload and
failure selector in injected state. The merge stub checks original byte order,
then models complete four-leaf consumption or rejection; it does not hash.
Actual update, buffer copying, flush clearing and cancellation guards are retained.
Scope: B=1, zero to twelve symbolic bytes, all two-update split points, four
outer cancellation polls and any of the three complete-group rejections. Partial
bits, hashing, arbitrary sizes and the consumer's work charging are not modeled.
"""

STREAM = r'''
#[cfg(kani)]
mod buffer_qualification {
    use super::*;
    fn clear(bytes: &mut [u8]) { bytes.fill(0); }
    fn merge<'p: 'p, 'i: 'i, 'a: 'a>(
        root: &mut Collector<'p, 'i, 'a>, input: Fips202BitString<'_>,
        _executor: &Executor<'_>, _workspace: &mut batch::Workspace,
        _control: &mut Control<'_>,
    ) -> Result<(), Error> {
        root.qualification_consume_buffer(input)
    }
    #[kani::proof]
    #[kani::stub(Collector::merge_stream_batch, merge)]
    #[kani::stub(brynja_core::secret_memory_volatile::zeroize_region_volatile, clear)]
    // At most four buffer-copy iterations per update and four bytes per group.
    // Kani's unwinding assertions remain enabled, including on source mutants.
    #[kani::unwind(5)]
    fn two_updates_preserve_order_and_clear_failed_storage() {
        let payload: [u8; 12] = kani::any();
        let length: u8 = kani::any();
        let split: u8 = kani::any();
        let cancel_at: u8 = kani::any();
        let fail_group: u8 = kani::any();
        kani::assume(length <= 12 && split <= length && cancel_at <= 4 && fail_group <= 3);
        let executor = Executor::portable();
        let mut storage = [0; 4];
        let mut root = Collector::qualification_root(0);
        root.qualification_buffer_oracle(payload, fail_group);
        let mut stream = Stream {
            root, executor: &executor, workspace: &mut storage,
            hash: batch::Workspace::new(), used: [0; 16], input_bits: [0; 16],
            block: 1, limit: 12,
        };
        let mut polls = 0_u8;
        let mut cancelled = || { polls += 1; polls == cancel_at };
        let mut control = Control::new(0, &mut cancelled);
        let first = stream.update(&payload[..usize::from(split)], &mut control);
        let result = first.and_then(|()| stream.update(
            &payload[usize::from(split)..usize::from(length)], &mut control));
        let groups = length / 4;
        let valid = cancel_at == 0 && (fail_group == 0 || fail_group > groups);
        assert_eq!(result.is_ok(), valid);
        assert_eq!(control.used(), 0); // The modeled consumer does not charge work.
        if valid {
            assert_eq!(stream.input_bits(), u128::from(length) * 8);
            assert_eq!(stream.root.merged_leaves(), u128::from(groups) * 4);
            assert_eq!(stream.used().unwrap(), usize::from(length % 4));
            for index in 0..4 {
                let expected = if index < usize::from(length % 4) {
                    payload[usize::from(groups) * 4 + index]
                } else { 0 };
                assert_eq!(stream.workspace[index], expected);
            }
        } else {
            assert_eq!(stream.root.qualification_phase(), 0);
            assert_eq!(stream.root.merged_leaves(), 0);
            assert_eq!(stream.input_bits(), 0);
            assert_eq!(stream.used().unwrap(), 0);
            for index in 0..4 { assert_eq!(stream.workspace[index], 0); }
            // Actual failed stream must remain terminal, even with no new bytes.
            assert!(stream.update(&[], &mut control).is_err());
        }
        drop(stream);
        for byte in storage { assert_eq!(byte, 0); }
    }
}
'''

COLLECTOR = r'''
#[cfg(kani)]
impl Collector<'_, '_, '_> {
    pub(in crate::execution) fn qualification_buffer_oracle(&mut self, payload: [u8; 12], fail: u8) {
        // Harness-only oracle, not a claim of valid cryptographic root contents.
        self.output_bits[..12].copy_from_slice(&payload);
        self.accelerated[0] = fail;
    }
    pub(in crate::execution) fn qualification_consume_buffer(
        &mut self, input: crate::Fips202BitString<'_>,
    ) -> Result<(), crate::execution::batch::Error> {
        assert_eq!(self.phase[0], 1);
        assert_eq!(input.bit_len(), 32);
        let start = usize::try_from(self.merged_leaves()).unwrap();
        assert!(start <= 8);
        assert_eq!(input.as_bytes().len(), 4);
        for index in 0..4 {
            assert_eq!(input.as_bytes()[index], self.output_bits[start + index]);
        }
        if usize::from(self.accelerated[0]) == start / 4 + 1 {
            return Err(Error::State.into());
        }
        self.merged = ((start + 4) as u128).to_le_bytes();
        Ok(())
    }
}
'''

HARNESSES = {
    'buffer': 'execution::stream::batch::buffer_qualification::two_updates_preserve_order_and_clear_failed_storage',
}
MUTANTS = (
    ('buffer', 'execution/stream/batch.rs',
     '.copy_from_slice(input.get(..take).ok_or(RootError::State)?);', '.fill(0);'),
    ('buffer', 'execution/stream/batch.rs',
     'input = input.get(take..).ok_or(RootError::State)?;', 'input = &[];'),
    ('buffer', 'execution/stream/batch.rs',
     'let _ = clear_owned_region(self.workspace);\n        let _ = clear_owned_region(&mut self.used);\n        Ok(())',
     'let _ = clear_owned_region(&mut self.used);\n        Ok(())'),
    ('buffer', 'execution/stream/batch.rs',
     'guard.stream.input_bits = total.to_le_bytes();', 'guard.stream.input_bits = [0; 16];'),
    ('buffer', 'execution/stream/batch.rs',
     'if !self.complete {\n            self.stream.cancel();', 'if false {\n            self.stream.cancel();'),
)
