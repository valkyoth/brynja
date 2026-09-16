"""Bounded completion-token construction/consumption through actual methods.

The setup supplies an empty portable root and injects counters; it does not model
a valid previously hashed transcript. Sponge absorption/finalization are modeled
as successful calls, and volatile clearing as slice fill. Token, collector and
stream lifecycle methods remain real. Machine erasure is a separate obligation.
"""

STREAM = r'''
#[cfg(kani)]
mod token_qualification {
    use super::*;
    fn clear(bytes: &mut [u8]) { bytes.fill(0); }
    fn absorb<'a: 'a>(_state: &mut crate::execution::backend::State<'a>, _input: &[u8]) -> Result<(), RootError> { Ok(()) }
    fn finish<'a: 'a>(_state: &mut crate::execution::backend::State<'a>, _tail: Fips202BitString<'_>) -> Result<(), RootError> { Ok(()) }
    #[kani::proof]
    #[kani::stub(crate::execution::backend::State::update, absorb)]
    #[kani::stub(crate::execution::backend::State::finish, finish)]
    #[kani::stub(brynja_core::secret_memory_volatile::zeroize_region_volatile, clear)]
    #[kani::unwind(33)]
    fn token_construction_and_consumption() {
        let total: u16 = kani::any();
        let merged: u128 = kani::any();
        let cancel_at: u8 = kani::any();
        kani::assume(cancel_at <= 2);
        let executor = Executor::portable();
        let mut storage = [0; 4];
        let mut stream = Stream {
            root: Collector::qualification_root(merged), executor: &executor,
            workspace: &mut storage, hash: batch::Workspace::new(),
            used: [0; 16], input_bits: u128::from(total).to_le_bytes(),
            block: 1, limit: u128::MAX,
        };
        let address = core::ptr::addr_of!(stream.root);
        let mut polls = 0_u8;
        let mut cancelled = || { polls += 1; polls == cancel_at };
        let mut control = Control::new(0, &mut cancelled);
        let valid = merged == (u128::from(total) + 7) / 8 && cancel_at == 0;
        let result = stream.finish_input(crate::execution::bits(&[]).unwrap(), &mut control);
        assert_eq!(result.is_ok(), valid);
        match result {
            Ok(token) => {
                // A token must borrow the exact root whose input was checked.
                assert!(core::ptr::eq(&*token.root, address));
                assert_eq!(token.root.merged_leaves(), merged);
                assert!(Collector::finish_stream(token, 0, false).is_ok());
                assert_eq!(stream.root.qualification_phase(), 2);
                // Actual completion is terminal: a second proof cannot reopen it.
                assert!(stream.finish_input(crate::execution::bits(&[]).unwrap(), &mut control).is_err());
            }
            Err(_) => {}
        }
        assert_eq!(stream.root.qualification_phase(), 0);
        assert_eq!(stream.root.merged_leaves(), 0);
        assert_eq!(stream.input_bits(), 0);
        assert_eq!(stream.used().unwrap(), 0);
        assert_eq!(control.used(), 0);
    }
}
'''

COLLECTOR = r'''
#[cfg(kani)]
impl Collector<'_, '_, '_> {
    pub(in crate::execution) fn qualification_phase(&self) -> u8 { self.phase[0] }
}
'''

HARNESSES = {
    'token': 'execution::stream::batch::token_qualification::token_construction_and_consumption',
}
MUTANTS = (
    ('token', 'execution/stream/batch.rs', 'stream.check_complete()?;', '// omitted exact completion'),
    ('token', 'execution/collector.rs', 'input.into_root().finish_inner(output_bits, xof, true)',
     'input.into_root().finish_inner(output_bits, xof, false)'),
    ('token', 'execution/collector.rs', 'root.phase = [2];', 'root.phase = [1];'),
)
