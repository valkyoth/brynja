use super::*;
use brynja_hash_sha3::HardenedSha3SecretOutput;
use core::cell::Cell;

struct Mock<'a> {
    dropped: &'a Cell<u8>,
    reject: bool,
}
impl Drop for Mock<'_> {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get().saturating_add(1));
    }
}
struct MockReader;
impl Reader for MockReader {
    fn public(self, _: Fips202Output<'_>) -> Result<(), Error> {
        Err(Error::StateConsumed)
    }
    fn secret<'a>(self, _: &'a mut [u8], _: u8) -> Result<HardenedSha3SecretOutput<'a>, Error> {
        Err(Error::StateConsumed)
    }
}
impl State for Mock<'_> {
    type Reader = MockReader;
    fn update(&mut self, _: &[u8]) -> Result<(), Error> {
        if self.reject {
            Err(Error::StateConsumed)
        } else {
            Ok(())
        }
    }
    fn finish(self) -> Result<MockReader, Error> {
        Err(Error::StateConsumed)
    }
    fn leaf<'a>(
        _: Fips202BitString<'_>,
        _: &'a mut [u8; 64],
    ) -> Result<HardenedSha3SecretOutput<'a>, Error> {
        Err(Error::StateConsumed)
    }
}

#[test]
fn scoped_core_rejections_clear_every_region_and_stay_terminal() -> Result<(), Error> {
    for mode in 0..3 {
        let dropped = Cell::new(0);
        let mut metadata = Metadata::new();
        let mut block = [0xa5; 8];
        let mut core = Core::new(
            Mock {
                dropped: &dropped,
                reject: false,
            },
            &mut metadata,
            &mut block,
        )?;
        core.metadata.leaf.fill(0xa5);
        if mode == 0 {
            core.metadata.leaves.fill(255);
        }
        if mode == 1 {
            core.metadata.used.fill(255);
        }
        // Third mode reaches the deliberately failing leaf backend.
        assert!(core.update(&[1; 8]).is_err());
        assert_eq!(dropped.get(), 1);
        assert!(core.state.is_none());
        assert!(core.metadata.cleared());
        assert_eq!(core.block, &[0; 8]);
        assert!(core.update(&[]).is_err());
        let mut output = [0xa5; 3];
        assert!(
            core.secret(crate::core_state::byte_string(&[])?, &mut output, 8)
                .is_err()
        );
        assert_eq!(output, [0; 3]);
    }
    Ok(())
}

#[test]
fn scoped_setup_failure_and_outer_guards_clear_poisoned_storage() {
    let mut metadata = Metadata::new();
    let mut block = [0xa5; 8];
    metadata.used.fill(0xa5);
    metadata.leaves.fill(0xa5);
    metadata.leaf.fill(0xa5);
    let dropped = Cell::new(0);
    assert!(
        Core::new(
            Mock {
                dropped: &dropped,
                reject: true
            },
            &mut metadata,
            &mut block
        )
        .is_err()
    );
    assert_eq!(dropped.get(), 1);
    assert!(metadata.cleared());
    assert_eq!(block, [0; 8]);
    metadata.used.fill(0xa5);
    metadata.leaves.fill(0xa5);
    metadata.leaf.fill(0xa5);
    drop(Guard(&mut metadata));
    assert!(metadata.cleared());
    block.fill(0xa5);
    drop(Block(&mut block));
    assert_eq!(block, [0; 8]);
}

#[test]
fn scoped_final_errors_preserve_public_and_clear_secret() -> Result<(), Error> {
    for valid in [0, 8, 9, 255] {
        let dropped = Cell::new(0);
        let mut metadata = Metadata::new();
        let mut block = [0; 8];
        let core = Core::new(
            Mock {
                dropped: &dropped,
                reject: false,
            },
            &mut metadata,
            &mut block,
        )?;
        let mut output = [0xa5; 3];
        assert!(
            core.public(crate::core_state::byte_string(&[])?, &mut output, valid)
                .is_err()
        );
        assert_eq!(output, [0xa5; 3]);
        assert_eq!(dropped.get(), 1);
        assert!(metadata.cleared());
        let core = Core::new(
            Mock {
                dropped: &dropped,
                reject: false,
            },
            &mut metadata,
            &mut block,
        )?;
        assert!(
            core.secret(crate::core_state::byte_string(&[])?, &mut output, valid)
                .is_err()
        );
        assert_eq!(output, [0; 3]);
        assert_eq!(dropped.get(), 2);
        assert!(metadata.cleared());
    }
    Ok(())
}
