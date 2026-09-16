"""Bounded partial-bit finish_input proof with injected valid pending bytes.

B=1, one to eight total bytes, zero to three already-pending bytes, every valid
partial-bit count and symbolic canonical payload. The consumer checks byte/bit
handoff then models leaf counting or rejection. Hashing, root output and actual
volatile stores are outside the claim; final input/flush/guard methods stay real.
"""

STREAM = r'''
#[cfg(kani)]
mod tail_qualification {
    use super::*;
    fn clear(bytes: &mut [u8]) { bytes.fill(0); }
    fn merge<'p: 'p, 'i: 'i, 'a: 'a>(
        root: &mut Collector<'p, 'i, 'a>, input: Fips202BitString<'_>,
        _executor: &Executor<'_>, _workspace: &mut batch::Workspace,
        _control: &mut Control<'_>,
    ) -> Result<(), Error> {
        root.qualification_consume_tail(input)
    }
    #[kani::proof]
    #[kani::stub(Collector::merge_stream_batch, merge)]
    #[kani::stub(brynja_core::secret_memory_volatile::zeroize_region_volatile, clear)]
    #[kani::unwind(5)]
    fn partial_tail_preserves_bytes_bits_and_completion() {
        let mut payload: [u8; 8] = kani::any();
        let length: u8 = kani::any();
        let pending: u8 = kani::any();
        let valid_bits: u8 = kani::any();
        let cancel_at: u8 = kani::any();
        let fail_group: u8 = kani::any();
        kani::assume(length >= 1 && length <= 8 && pending < length && pending <= 3);
        kani::assume(valid_bits >= 1 && valid_bits <= 7 && cancel_at <= 2 && fail_group <= 2);
        payload[usize::from(length - 1)] &= u8::MAX >> (8 - valid_bits);
        let executor = Executor::portable();
        let mut storage = [0; 4];
        for index in 0..4 {
            if index < usize::from(pending) { storage[index] = payload[index]; }
        }
        let mut root = Collector::qualification_root(0);
        root.qualification_tail_oracle(payload, length, valid_bits, fail_group);
        let mut stream = Stream {
            root, executor: &executor, workspace: &mut storage,
            hash: batch::Workspace::new(), used: u128::from(pending).to_le_bytes(),
            input_bits: (u128::from(pending) * 8).to_le_bytes(), block: 1, limit: 8,
        };
        let root_address = core::ptr::addr_of!(stream.root);
        let tail = Fips202BitString::new(
            &payload[usize::from(pending)..usize::from(length)], valid_bits).unwrap();
        let mut polls = 0_u8;
        let mut cancelled = || { polls += 1; polls == cancel_at };
        let mut control = Control::new(0, &mut cancelled);
        let groups = (length + 3) / 4;
        let accepted = cancel_at == 0 && (fail_group == 0 || fail_group > groups);
        let result = stream.finish_input(tail, &mut control);
        assert_eq!(result.is_ok(), accepted);
        if let Ok(token) = result {
            assert!(core::ptr::eq(&*token.root, root_address));
            assert_eq!(token.root.merged_leaves(), u128::from(length));
        }
        if accepted {
            assert_eq!(stream.input_bits(), u128::from(length - 1) * 8 + u128::from(valid_bits));
            assert_eq!(stream.root.qualification_phase(), 1);
        } else {
            assert_eq!(stream.root.qualification_phase(), 0);
            assert_eq!(stream.input_bits(), 0);
            assert_eq!(stream.root.merged_leaves(), 0);
            assert!(stream.finish_input(crate::execution::bits(&[]).unwrap(), &mut control).is_err());
        }
        assert_eq!(stream.used().unwrap(), 0);
        assert_eq!(control.used(), 0); // Consumer charging is deliberately modeled away.
        for index in 0..4 { assert_eq!(stream.workspace[index], 0); }
        drop(stream);
        for byte in storage { assert_eq!(byte, 0); }
    }
}
'''

COLLECTOR = r'''
#[cfg(kani)]
impl Collector<'_, '_, '_> {
    pub(in crate::execution) fn qualification_tail_oracle(
        &mut self, payload: [u8; 8], length: u8, valid: u8, fail: u8,
    ) {
        // Harness-only oracle, not a cryptographically valid root transcript.
        self.output_bits[..8].copy_from_slice(&payload);
        self.output_bits[8] = length;
        self.output_bits[9] = valid;
        self.output_bits[10] = fail;
    }
    pub(in crate::execution) fn qualification_consume_tail(
        &mut self, input: crate::Fips202BitString<'_>,
    ) -> Result<(), crate::execution::batch::Error> {
        assert_eq!(self.phase[0], 1);
        let start = usize::try_from(self.merged_leaves()).unwrap();
        let length = usize::from(self.output_bits[8]);
        assert!(start < length && length <= 8);
        let size = (length - start).min(4);
        let valid = if start + size == length { self.output_bits[9] } else { 8 };
        assert_eq!(input.as_bytes().len(), size);
        assert_eq!(input.valid_bits_in_last_byte(), valid);
        assert_eq!(input.bit_len(), (size - 1) * 8 + usize::from(valid));
        for index in 0..4 {
            if index < size { assert_eq!(input.as_bytes()[index], self.output_bits[start + index]); }
        }
        if usize::from(self.output_bits[10]) == start / 4 + 1 {
            return Err(Error::State.into());
        }
        self.merged = ((start + size) as u128).to_le_bytes();
        Ok(())
    }
}
'''

HARNESSES = {
    'tail': 'execution::stream::batch::tail_qualification::partial_tail_preserves_bytes_bits_and_completion',
}
MUTANTS = (
    ('tail', 'execution/stream/batch.rs',
     '*stream.workspace.get_mut(used).ok_or(RootError::State)? = *last;',
     '*stream.workspace.get_mut(used).ok_or(RootError::State)? = 0;'),
    ('tail', 'execution/stream/batch.rs',
     'stream.flush(tail.valid_bits_in_last_byte(), control)?;', 'stream.flush(8, control)?;'),
    ('tail', 'execution/stream/batch.rs',
     'stream.update_inner(prefix, control)?;', 'stream.update_inner(&[], control)?;'),
    ('tail', 'execution/stream/batch.rs',
     '\n        stream.input_bits = total.to_le_bytes();', '\n        stream.input_bits = [0; 16];'),
    ('tail', 'execution/stream/batch.rs',
     'stream.flush(tail.valid_bits_in_last_byte(), control)?;', '// omitted partial flush'),
)
