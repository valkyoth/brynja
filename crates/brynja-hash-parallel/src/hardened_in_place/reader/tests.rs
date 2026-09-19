extern crate std;
use super::*;
use brynja_hash_sha3::HardenedSha3SecretOutput;
use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
};

struct Mock<'a> {
    calls: &'a Cell<u8>,
    dropped: &'a Cell<bool>,
    panic: bool,
}
impl Drop for Mock<'_> {
    fn drop(&mut self) {
        self.dropped.set(true);
    }
}
impl Mock<'_> {
    fn reject(&self) -> Result<(), Error> {
        self.calls.set(self.calls.get().saturating_add(1));
        assert!(!self.panic, "injected reader unwind");
        Err(Error::SecretMemory)
    }
}
impl Reader for Mock<'_> {
    fn read_public(&mut self, _: &mut [u8]) -> Result<(), Error> {
        self.reject()
    }
    fn read_secret<'a>(&mut self, _: &'a mut [u8]) -> Result<HardenedSha3SecretOutput<'a>, Error> {
        self.reject()?;
        Err(Error::SecretMemory)
    }
    fn public(self, _: Fips202Output<'_>) -> Result<(), Error> {
        self.reject()
    }
    fn secret<'a>(self, _: &'a mut [u8], _: u8) -> Result<HardenedSha3SecretOutput<'a>, Error> {
        self.reject()?;
        Err(Error::SecretMemory)
    }
}

#[test]
fn scoped_parallel_xof_read_errors_and_unwind_are_terminal() {
    for secret in [false, true] {
        for panic in [false, true] {
            let calls = Cell::new(0);
            let dropped = Cell::new(false);
            let mut reader = Output::new(Mock {
                calls: &calls,
                dropped: &dropped,
                panic,
            });
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
                assert!(matches!(result, Ok(Err(Error::SecretMemory))));
            }
            assert_eq!(bytes, if secret { [0; 3] } else { [0xa5; 3] });
            assert!(dropped.get());
            assert!(reader.reader.is_none());
            assert!(reader.public(&mut []).is_err());
            assert!(reader.secret(&mut []).is_err());
            assert_eq!(calls.get(), 1);
            bytes.fill(0xa5);
            if secret {
                assert!(reader.final_secret(&mut bytes, 8).is_err());
                assert_eq!(bytes, [0; 3]);
            } else {
                assert!(reader.final_public(&mut bytes, 8).is_err());
                assert_eq!(bytes, [0xa5; 3]);
            }
        }
    }
}

#[test]
fn scoped_parallel_xof_final_errors_drop_reader_and_validate_before_output() {
    for valid in [0, 1, 8, 9, 255] {
        for secret in [false, true] {
            let calls = Cell::new(0);
            let dropped = Cell::new(false);
            let reader = Output::new(Mock {
                calls: &calls,
                dropped: &dropped,
                panic: false,
            });
            let mut bytes = [0xa5; 3];
            if secret {
                assert!(reader.final_secret(&mut bytes, valid).is_err());
            } else {
                assert!(reader.final_public(&mut bytes, valid).is_err());
            }
            assert_eq!(bytes, if secret { [0; 3] } else { [0xa5; 3] });
            assert!(dropped.get());
            assert_eq!(calls.get(), u8::from((1..=8).contains(&valid)));
        }
    }
}
