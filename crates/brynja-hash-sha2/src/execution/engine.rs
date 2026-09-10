// Expanded inside each ordinary engine so its private state never becomes public.
macro_rules! impl_engine {
    ($state:ident, $length:ty, $digest:ty, $check_bits:ident, $compress:ident, $wide:expr) => {
        impl $state {
            pub(crate) fn execution_update(
                &mut self,
                input: &[u8],
                execution: &crate::execution::Execution<'_>,
                report: &mut crate::execution::Report,
            ) -> Result<(), crate::execution::Error> {
                use crate::execution::Error;
                execution.check($wide)?;
                // Transactional ordinary copy: an error cannot mutate the live
                // stream, buffered input, length or its successful-work report.
                let mut candidate = Self {
                    state: self.state,
                    buffer: self.buffer,
                    buffer_len: self.buffer_len,
                    message_bytes: self.message_bytes,
                };
                let mut counts = *report;
                candidate
                    .update_inner(input, |state, block| {
                        execution.$compress(state, block)?;
                        counts.count(false)
                    })
                    .map_err(|error| match error {
                        UpdateInnerError::MessageTooLong => Error::MessageTooLong,
                        UpdateInnerError::Compression(error) => error,
                    })?;
                *self = candidate;
                *report = counts;
                Ok(())
            }

            pub(crate) fn execution_finalize(
                mut self,
                input: crate::BitString<'_>,
                execution: &crate::execution::Execution<'_>,
                report: &mut crate::execution::Report,
            ) -> Result<$digest, crate::execution::Error> {
                use crate::execution::Error;
                let additional =
                    <$length>::try_from(input.bit_len()).map_err(|_| Error::MessageTooLong)?;
                let bits = crate::bit_input::$check_bits(self.message_bytes, additional)
                    .map_err(|_| Error::MessageTooLong)?;
                let (complete, partial) = input.split();
                self.execution_update(complete, execution, report)?;
                self.finalize_inner(partial, bits, |state, block| {
                    execution.$compress(state, block)?;
                    report.count(true)
                })
            }
        }

        #[cfg(test)]
        #[test]
        fn execution_transaction_rejects_length_and_mid_update_counter_failure() {
            use crate::execution::{Error, Execution, Report, Route};
            let mut state = $state {
                state: [7; 8],
                buffer: [3; BLOCK_BYTES],
                buffer_len: 3,
                message_bytes: 3,
            };
            let mut report = Report {
                route: Route::Portable,
                message_blocks: u128::MAX,
                padding_blocks: 0,
                portable_iv_blocks: 0,
            };
            assert_eq!(
                state.execution_update(&[0x42; 256], &Execution::portable(), &mut report),
                Err(Error::MessageTooLong)
            );
            assert_eq!(state.state, [7; 8]);
            assert_eq!(state.buffer, [3; BLOCK_BYTES]);
            assert_eq!(state.buffer_len, 3);
            assert_eq!(state.message_bytes, 3);
            assert_eq!(report.message_blocks, u128::MAX);
            state.message_bytes = <$length>::MAX / 8;
            assert_eq!(
                state.execution_update(&[0], &Execution::portable(), &mut report),
                Err(Error::MessageTooLong)
            );
            assert_eq!(state.state, [7; 8]);
            assert_eq!(state.buffer, [3; BLOCK_BYTES]);
            assert_eq!(state.buffer_len, 3);
            assert_eq!(state.message_bytes, <$length>::MAX / 8);
        }
    };
}
pub(crate) use impl_engine;
