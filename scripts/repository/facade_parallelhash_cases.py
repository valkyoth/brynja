"""Synthetic public downstream data and lifecycle checks for threaded batches."""

RUST = r'''
#[cfg(test)]
mod parallel_lifecycle {
    use super::api::parallelhash::{Fips202BitString, execution::Identity};
    use threads::{CancellationToken, execution::batch::{Config, Preference, Request}};

    macro_rules! lifecycle {
        ($name:ident, $executor:ty) => {
            #[test]
            fn $name() {
                for identity in [Identity::ParallelHash128, Identity::ParallelHash256,
                                 Identity::ParallelHashXof128, Identity::ParallelHashXof256] {
                    for phase in 0..6 {
                        let executor = <$executor>::new(Config {
                            workers: 3, max_leaves: if phase == 2 { 1 } else { 128 },
                            root: Preference::Portable, leaves: Preference::Portable,
                            minimum_permutations: 1,
                            max_group_permutations: if phase == 1 { 0 } else { 128 },
                        }).unwrap();
                        let input = [0x15; 65];
                        let mut request = Request {
                            identity, input: Fips202BitString::new(&input, 5).unwrap(),
                            block_size: if phase == 3 { 0 } else { 8 },
                            customization: Fips202BitString::new(&[3], 2).unwrap(),
                        };
                        let token = CancellationToken::new();
                        if phase == 0 { token.cancel(); }
                        let valid = if phase == 4 { 9 } else { 5 };
                        let mut output = [0xa5; 174];
                        let mut scratch = [0x5a; 190];
                        let size = if phase == 5 { 1 } else { 190 };
                        assert!(executor.hash_public_bits(&request, &mut output[..173], valid,
                            &mut scratch[..size], &token).is_err());
                        assert_eq!(output, [0xa5; 174]);
                        assert!(scratch[..size].iter().all(|b| *b == 0));
                        assert!(scratch[size..].iter().all(|b| *b == 0x5a));
                        if phase != 5 {
                            assert!(executor.hash_secret_bits(&request, &mut output[..173], valid,
                                &token).is_err());
                            assert_eq!(&output[..173], &[0; 173]);
                            assert_eq!(output[173], 0xa5);
                        }
                        // A failed call must release its single-operation gate.
                        // Empty input consumes no leaf budget even when budget=0.
                        request.input = Fips202BitString::new(&[], 0).unwrap();
                        request.block_size = 8;
                        let clean = CancellationToken::new();
                        let (secret, report) = executor.hash_secret_bits(&request,
                            &mut output[..173], 5, &clean).unwrap();
                        assert_eq!(report.execution.leaves, 0);
                        assert_eq!(report.execution.thread_width, 0);
                        assert_eq!(report.vector_calls, 0);
                        assert_eq!(secret.expose().last().unwrap() & 0xe0, 0);
                        drop(secret);
                        assert_eq!(&output[..173], &[0; 173]);
                        assert_eq!(output[173], 0xa5);
                    }
                }
            }
        };
    }
    lifecycle!(owned_failures_and_reuse, threads::execution::batch::Executor);
    lifecycle!(scoped_failures_and_reuse, threads::execution::batch::in_place::Executor);
}
'''
