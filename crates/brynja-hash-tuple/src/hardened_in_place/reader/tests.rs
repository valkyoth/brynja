extern crate std;
use super::*;
use brynja_hash_sha3::HardenedSha3SecretOutput;
use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
};

struct Mock<'a> {
    calls: &'a Cell<usize>,
    dropped: &'a Cell<bool>,
    panic: bool,
}
impl Drop for Mock<'_> {
    fn drop(&mut self) {
        self.dropped.set(true);
    }
}
impl Mock<'_> {
    fn reject(&self) -> Result<(), TupleHashError> {
        self.calls.set(self.calls.get().saturating_add(1));
        assert!(!self.panic, "injected reader unwind");
        Err(TupleHashError::SecretMemory)
    }
}
impl Reader for Mock<'_> {
    fn read_public(&mut self, _: &mut [u8]) -> Result<(), TupleHashError> {
        self.reject()
    }
    fn read_secret<'out>(
        &mut self,
        _: &'out mut [u8],
    ) -> Result<HardenedSha3SecretOutput<'out>, TupleHashError> {
        self.reject()?;
        Err(TupleHashError::SecretMemory)
    }
    fn public(self, _: Fips202Output<'_>) -> Result<(), TupleHashError> {
        self.reject()
    }
    fn secret<'out>(
        self,
        _: &'out mut [u8],
        _: u8,
    ) -> Result<HardenedSha3SecretOutput<'out>, TupleHashError> {
        self.reject()?;
        Err(TupleHashError::SecretMemory)
    }
}

#[test]
fn scoped_tuple_xof_reader_errors_are_terminal_including_empty_reads() {
    for secret in [false, true] {
        for panic in [false, true] {
            let calls = Cell::new(0);
            let dropped = Cell::new(false);
            let mut metadata = Metadata::new();
            metadata.poison();
            let mut reader = Output::new(
                Mock {
                    calls: &calls,
                    dropped: &dropped,
                    panic,
                },
                Guard(&mut metadata),
            );
            let mut bytes = [0xa5; 3];
            let result = catch_unwind(AssertUnwindSafe(|| {
                if secret {
                    reader.secret(&mut bytes).map(drop)
                } else {
                    reader.public(&mut bytes)
                }
            }));
            if panic {
                assert!(result.is_err());
            } else {
                assert!(matches!(result, Ok(Err(TupleHashError::SecretMemory))));
            }
            assert_eq!(bytes, if secret { [0; 3] } else { [0xa5; 3] });
            assert!(dropped.get());
            assert!(reader.reader.is_none());
            assert!(reader.cleanup.0.cleared());
            assert_eq!(reader.public(&mut []), Err(TupleHashError::StateConsumed));
            assert!(matches!(
                reader.secret(&mut []),
                Err(TupleHashError::StateConsumed)
            ));
            bytes.fill(0x55);
            assert!(matches!(
                reader.secret(&mut bytes),
                Err(TupleHashError::StateConsumed)
            ));
            assert_eq!(bytes, [0; 3]);
            bytes.fill(0x55);
            assert_eq!(
                reader.public(&mut bytes),
                Err(TupleHashError::StateConsumed)
            );
            assert_eq!(bytes, [0x55; 3]);
            assert_eq!(calls.get(), 1);
            assert!(matches!(
                reader.final_secret(&mut bytes, 8),
                Err(TupleHashError::StateConsumed)
            ));
            assert_eq!(bytes, [0; 3]);
        }
    }
}

#[test]
fn scoped_tuple_xof_reader_final_errors_drop_backend() {
    for valid in [0, 1, 8, 9, 255] {
        for secret in [false, true] {
            let calls = Cell::new(0);
            let dropped = Cell::new(false);
            let mut metadata = Metadata::new();
            metadata.poison();
            let reader = Output::new(
                Mock {
                    calls: &calls,
                    dropped: &dropped,
                    panic: false,
                },
                Guard(&mut metadata),
            );
            let mut bytes = [0xa5; 3];
            let result = if secret {
                reader.final_secret(&mut bytes, valid).map(drop)
            } else {
                reader.final_public(&mut bytes, valid)
            };
            let expected = if (1..=8).contains(&valid) {
                TupleHashError::SecretMemory
            } else {
                TupleHashError::InvalidBitString
            };
            assert_eq!(result, Err(expected));
            assert!(dropped.get());
            assert!(metadata.cleared());
            assert_eq!(calls.get(), usize::from((1..=8).contains(&valid)));
            assert_eq!(bytes, if secret { [0; 3] } else { [0xa5; 3] });
        }
    }
}
