use super::*;
use brynja_hash_sha3::HardenedSha3SecretOutput;
use core::cell::Cell;
extern crate std;

struct Failed<'a> {
    panic: bool,
    dropped: &'a Cell<bool>,
}
impl Failed<'_> {
    fn error<T>(&self) -> Result<T, KmacError> {
        if self.panic {
            std::panic::resume_unwind(std::boxed::Box::new(()));
        }
        Err(KmacError::OutputTooLong)
    }
}
impl Drop for Failed<'_> {
    fn drop(&mut self) {
        self.dropped.set(true);
    }
}
impl Reader for Failed<'_> {
    fn public(&mut self, _: &mut [u8]) -> Result<(), KmacError> {
        self.error()
    }
    fn secret<'out>(
        &mut self,
        _: &'out mut [u8],
    ) -> Result<HardenedSha3SecretOutput<'out>, KmacError> {
        self.error()
    }
    fn final_public(self, _: Fips202Output<'_>) -> Result<(), KmacError> {
        self.error()
    }
    fn final_secret<'out>(
        self,
        _: &'out mut [u8],
        _: u8,
    ) -> Result<HardenedSha3SecretOutput<'out>, KmacError> {
        self.error()
    }
}

#[test]
fn reader_failure_and_unwind_clear_and_reject_every_followup() {
    for panic in [false, true] {
        for secret in [false, true] {
            let mut metadata = Metadata::new();
            metadata.poison();
            let dropped = Cell::new(false);
            let mut reader = Output::new(
                Failed {
                    panic,
                    dropped: &dropped,
                },
                Guard(&mut metadata),
            );
            let mut output = [0xa5; 32];
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if secret {
                    reader.secret(&mut output).map(|_| ())
                } else {
                    reader.public(&mut output)
                }
            }));
            if panic {
                assert!(result.is_err());
            } else {
                assert!(matches!(result, Ok(Err(KmacError::OutputTooLong))));
            }
            assert!(dropped.get());
            assert!(reader.cleanup.0.cleared());
            assert_eq!(output, if secret { [0; 32] } else { [0xa5; 32] });
            assert_eq!(reader.public(&mut []), Err(KmacError::StateConsumed));
            output.fill(0xa5);
            assert!(matches!(
                reader.secret(&mut output),
                Err(KmacError::StateConsumed)
            ));
            assert_eq!(output, [0; 32]);
            assert!(matches!(
                reader.secret(&mut []),
                Err(KmacError::StateConsumed)
            ));
            drop(reader);
            assert!(metadata.cleared());
        }
    }
}

#[test]
fn consuming_reader_failures_clear_metadata_and_secret_output() {
    for valid in [0, 8, 9] {
        for secret in [false, true] {
            let mut metadata = Metadata::new();
            metadata.poison();
            let dropped = Cell::new(false);
            let reader = Output::new(
                Failed {
                    panic: false,
                    dropped: &dropped,
                },
                Guard(&mut metadata),
            );
            let mut output = [0xa5; 32];
            let result = if secret {
                reader.final_secret(&mut output, valid).map(|_| ())
            } else {
                reader.final_public(&mut output, valid)
            };
            assert!(result.is_err());
            assert!(dropped.get());
            assert!(metadata.cleared());
            assert_eq!(output, if secret { [0; 32] } else { [0xa5; 32] });
        }
    }
}
