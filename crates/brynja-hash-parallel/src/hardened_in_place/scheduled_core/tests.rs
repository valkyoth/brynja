use super::*;
use brynja_hash_sha3::HardenedSha3SecretOutput;
use core::cell::Cell;

struct Mock<'a> {
    dropped: &'a Cell<u8>,
    reject: &'a Cell<bool>,
}
impl Drop for Mock<'_> {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get().saturating_add(1));
    }
}
struct MockReader;
impl Reader for MockReader {
    fn read_public(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::StateConsumed)
    }
    fn read_secret<'a>(&mut self, _: &'a mut [u8]) -> Result<HardenedSha3SecretOutput<'a>, Error> {
        Err(Error::StateConsumed)
    }
    fn public(self, _: Fips202Output<'_>) -> Result<(), Error> {
        Err(Error::StateConsumed)
    }
    fn secret<'a>(self, _: &'a mut [u8], _: u8) -> Result<HardenedSha3SecretOutput<'a>, Error> {
        Err(Error::StateConsumed)
    }
}
impl State for Mock<'_> {
    type Reader = MockReader;
    fn check(&mut self) -> Result<(), Error> {
        if self.reject.get() {
            Err(Error::StateConsumed)
        } else {
            Ok(())
        }
    }
    fn update(&mut self, _: &[u8]) -> Result<(), Error> {
        self.check()
    }
    fn finish(mut self) -> Result<Self::Reader, Error> {
        self.check()?;
        Ok(MockReader)
    }
    fn leaf<'a>(
        &mut self,
        _: crate::Fips202BitString<'_>,
        _: &'a mut [u8; 64],
    ) -> Result<HardenedSha3SecretOutput<'a>, Error> {
        Err(Error::StateConsumed)
    }
}
#[test]
fn scoped_scheduled_merge_failures_clear_and_terminate() -> Result<(), Error> {
    for mode in 0..4 {
        let dropped = Cell::new(0);
        let reject = Cell::new(false);
        let mut count = Count::new();
        let mut root = Root::new(
            Mock {
                dropped: &dropped,
                reject: &reject,
            },
            &mut count,
            8,
            2,
        )?;
        root.merge(Ok(0), &[1; 32])?;
        assert_eq!(read(&root.count.merged), 1);
        if mode == 2 {
            reject.set(true);
        }
        if mode == 3 {
            root.count.merged.fill(255);
        }
        let index = match mode {
            0 => Err(Error::LeafIdentity),
            1 => Ok(0),
            _ => Ok(1),
        };
        assert!(root.merge(index, &[2; 32]).is_err());
        assert!(root.count.cleared());
        assert_eq!(dropped.get(), 1);
        assert!(root.merge(Ok(1), &[2; 32]).is_err());
        let mut output = [0xa5; 3];
        assert!(root.secret(&mut output, 8).is_err());
        assert_eq!(output, [0; 3]);
    }
    Ok(())
}
#[test]
fn scoped_scheduled_finish_errors_clear_and_complete_transition_wipes_count() -> Result<(), Error> {
    let dropped = Cell::new(0);
    let reject = Cell::new(false);
    let mut count = Count::new();
    for valid in [0, 8, 9, 255] {
        let mut root = Root::new(
            Mock {
                dropped: &dropped,
                reject: &reject,
            },
            &mut count,
            8,
            2,
        )?;
        root.merge(Ok(0), &[1; 32])?;
        let mut output = [0xa5; 3];
        assert!(root.public(&mut output, valid).is_err());
        assert_eq!(output, [0xa5; 3]);
        assert!(count.cleared());
        let mut root = Root::new(
            Mock {
                dropped: &dropped,
                reject: &reject,
            },
            &mut count,
            8,
            2,
        )?;
        root.merge(Ok(0), &[1; 32])?;
        assert!(root.secret(&mut output, valid).is_err());
        assert_eq!(output, [0; 3]);
        assert!(count.cleared());
    }
    let mut root = Root::new(
        Mock {
            dropped: &dropped,
            reject: &reject,
        },
        &mut count,
        8,
        1,
    )?;
    root.merge(Ok(0), &[1; 32])?;
    let _reader = root.xof()?;
    assert!(count.cleared());
    assert_eq!(dropped.get(), 9);
    count.merged.fill(0xa5);
    drop(CountGuard(&mut count));
    assert!(count.cleared());
    reject.set(true);
    assert!(
        Root::new(
            Mock {
                dropped: &dropped,
                reject: &reject
            },
            &mut count,
            8,
            1
        )
        .is_err()
    );
    assert!(count.cleared());
    assert_eq!(dropped.get(), 10);
    Ok(())
}
