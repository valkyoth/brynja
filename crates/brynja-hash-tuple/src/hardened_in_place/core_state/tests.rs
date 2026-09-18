extern crate std;
use super::*;
use brynja_hash_sha3::HardenedSha3SecretOutput;
use core::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Mock<'a> {
    calls: &'a Cell<usize>,
    dropped: &'a Cell<bool>,
    fail: &'a Cell<bool>,
    unwind: &'a Cell<bool>,
}
struct MockReader;
impl Drop for Mock<'_> {
    fn drop(&mut self) {
        self.dropped.set(true);
    }
}
impl State for Mock<'_> {
    type Reader = MockReader;
    fn update(&mut self, _: &[u8]) -> Result<(), TupleHashError> {
        self.calls.set(
            self.calls
                .get()
                .checked_add(1)
                .ok_or(TupleHashError::MessageTooLong)?,
        );
        if self.unwind.get() {
            std::panic::resume_unwind(std::boxed::Box::new(()));
        }
        if self.fail.get() {
            return Err(TupleHashError::SecretMemory);
        }
        Ok(())
    }
    fn finish(self, _: Fips202BitString<'_>) -> Result<MockReader, TupleHashError> {
        Ok(MockReader)
    }
}
impl Reader for MockReader {
    fn public(self, _: Fips202Output<'_>) -> Result<(), TupleHashError> {
        Err(TupleHashError::SecretMemory)
    }
    fn secret<'out>(
        self,
        _: Fips202Output<'out>,
    ) -> Result<HardenedSha3SecretOutput<'out>, TupleHashError> {
        Err(TupleHashError::SecretMemory)
    }
}

#[test]
fn scoped_tuple_metadata_wipes_all_seven_regions() {
    let mut metadata = Metadata::new();
    metadata.pending.fill(0xa5);
    metadata.used.fill(0xa5);
    metadata.items.fill(0xa5);
    metadata.remaining.fill(0xa5);
    metadata.input_bits.fill(0xa5);
    metadata.phase.fill(0xa5);
    metadata.staging.fill(0xa5);
    drop(Guard(&mut metadata));
    assert!(metadata.cleared());
}

#[test]
fn scoped_tuple_failures_clear_and_drop_borrowed_state() -> Result<(), TupleHashError> {
    let calls = Cell::new(0);
    let dropped = Cell::new(false);
    let fail = Cell::new(false);
    let unwind = Cell::new(false);
    let mut metadata = Metadata::new();
    for mode in 0..8 {
        dropped.set(false);
        fail.set(false);
        unwind.set(false);
        {
            let mut core = Core::new(
                Mock {
                    calls: &calls,
                    dropped: &dropped,
                    fail: &fail,
                    unwind: &unwind,
                },
                &mut metadata,
            );
            core.item_bytes(b"secret")?;
            let result = match mode {
                0 => {
                    write(&mut core.cleanup.0.items, u128::MAX)?;
                    core.begin(0)
                }
                1 => {
                    write(&mut core.cleanup.0.input_bits, u128::MAX)?;
                    core.begin(0)
                }
                2 => core.begin(u128::MAX),
                3 => {
                    core.begin(8)?;
                    write(&mut core.cleanup.0.input_bits, u128::MAX)?;
                    core.fragment_bytes(b"x")
                }
                4 => {
                    core.begin(0)?;
                    write(&mut core.cleanup.0.items, u128::MAX)?;
                    core.complete()
                }
                5 => {
                    core.cleanup.0.used = [9];
                    core.begin(0)
                }
                6 => {
                    fail.set(true);
                    core.begin(0)
                }
                _ => {
                    core.begin(8)?;
                    fail.set(true);
                    core.fragment_bytes(b"x")
                }
            };
            assert!(result.is_err());
            assert!(core.cleanup.0.cleared());
            assert!(core.state.is_none());
            assert!(dropped.get());
            assert_eq!(core.begin(0), Err(TupleHashError::StateConsumed));
        }
        assert!(metadata.cleared());
    }
    fail.set(false);
    unwind.set(false);
    dropped.set(false);
    let caught = catch_unwind(AssertUnwindSafe(|| {
        let mut core = Core::new(
            Mock {
                calls: &calls,
                dropped: &dropped,
                fail: &fail,
                unwind: &unwind,
            },
            &mut metadata,
        );
        assert!(core.item_bytes(b"secret").is_ok());
        unwind.set(true);
        let _ = core.begin(0);
    }));
    assert!(caught.is_err());
    assert!(metadata.cleared());
    assert!(dropped.get());
    Ok(())
}

#[test]
fn scoped_tuple_partial_items_keep_bulk_absorption() -> Result<(), TupleHashError> {
    let calls = Cell::new(0);
    let dropped = Cell::new(false);
    let fail = Cell::new(false);
    let unwind = Cell::new(false);
    let mut metadata = Metadata::new();
    let mut core = Core::new(
        Mock {
            calls: &calls,
            dropped: &dropped,
            fail: &fail,
            unwind: &unwind,
        },
        &mut metadata,
    );
    core.item(Fips202BitString::new(&[5], 3).map_err(|_| TupleHashError::InvalidBitString)?)?;
    calls.set(0);
    core.item_bytes(&[0x55; 4096])?;
    assert_eq!(calls.get(), 1 + 4096_usize.div_ceil(168));
    Ok(())
}
