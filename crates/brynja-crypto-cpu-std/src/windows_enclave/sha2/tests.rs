use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Mock {
    fail: bool,
    panic: bool,
    closed: bool,
}
impl Channel for Mock {
    fn request(
        &mut self,
        _: usize,
        _: u64,
        _: u64,
        _: &[u8],
        _: u8,
        output: Option<&mut [u8]>,
    ) -> Result<(), Error> {
        if let Some(output) = output {
            output.fill(42);
        }
        assert!(!self.panic, "injected transport unwind");
        if self.fail {
            Err(Error::Protocol)
        } else {
            Ok(())
        }
    }
    fn close(&mut self) -> Result<(), Error> {
        self.closed = true;
        Ok(())
    }
}
fn owner() -> Owner<Mock> {
    Owner {
        transport: Mock {
            fail: false,
            panic: false,
            closed: false,
        },
        state: State::Ready,
        sequence: 0,
        thread_bound: PhantomData,
    }
}
#[test]
fn request_failures_and_unwind_never_reopen_the_owner() -> Result<(), Error> {
    for panic in [false, true] {
        let mut owner = owner();
        owner.issue(11, Algorithm::SHA256, &[], 0, None)?;
        owner.transport.fail = true;
        owner.transport.panic = panic;
        let result = catch_unwind(AssertUnwindSafe(|| {
            owner.issue(12, Algorithm::SHA256, b"x", 8, None)
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Ok(Err(Error::Protocol))));
        }
        assert_eq!(owner.state, State::Quarantined);
        assert_eq!(
            owner.issue(13, Algorithm::SHA256, &[], 0, None),
            Err(Error::Quarantined)
        );
        owner.close()?;
        assert_eq!(owner.state, State::Closed);
        assert!(owner.transport.closed);
    }
    Ok(())
}

#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
mod native;
#[test]
fn checked_sequences_and_identity_boundaries() -> Result<(), Error> {
    let mut owner = owner();
    owner.sequence = u64::MAX;
    assert_eq!(
        owner.issue(11, Algorithm::SHA256, &[], 0, None),
        Err(Error::Exhausted)
    );
    assert_eq!(owner.state, State::Quarantined);
    for bits in 0..=512 {
        let result = Algorithm::sha512_t(bits);
        if bits == 0 || bits == 384 || bits == 512 {
            assert_eq!(result, Err(Error::Bounds));
        } else {
            let algorithm = result?;
            assert_eq!(algorithm.output_bytes(), usize::from(bits.div_ceil(8)));
            assert_eq!(algorithm.wire(), 0x1000 | u64::from(bits));
        }
    }
    assert_ne!(Algorithm::sha512_t(224)?, Algorithm::SHA512_224);
    assert_ne!(Algorithm::sha512_t(256)?, Algorithm::SHA512_256);
    Ok(())
}
#[test]
fn snapshot_headers_are_bounded_and_canonical() -> Result<(), Error> {
    use super::super::sha2_wire::header;
    assert_eq!(header(0, 1, &[], 0), Err(Error::Bounds));
    assert_eq!(header(1, 1, &[], 1), Err(Error::Bounds));
    assert_eq!(header(1, 1, &[0], 0), Err(Error::Bounds));
    assert_eq!(header(1, 1, &[0], 9), Err(Error::Bounds));
    assert_eq!(header(1, 1, &[0; 1025], 8), Err(Error::Bounds));
    assert!(header(1, 1, &[0; 1024], 8).is_ok());
    assert_eq!(
        header(1, 1, &[], 0)?.get(..8),
        Some(6_u64.to_le_bytes().as_slice())
    );
    Ok(())
}

#[test]
fn native_receipts_reject_missing_copy_clear_and_export_proofs() -> Result<(), Error> {
    use super::super::sha2_wire::receipt;
    let low = 0x10000_usize;
    for operation in 11..=16 {
        let length = if matches!(operation, 12 | 13) { 1 } else { 0 };
        let good = [
            low,
            0x10100,
            1,
            1,
            usize::from(length != 0),
            usize::from(operation == 15),
            0,
        ];
        receipt(low, operation, length, good)?;
        for index in 0..7 {
            let mut bad = good;
            *bad.get_mut(index).ok_or(Error::Bounds)? = usize::MAX;
            assert_eq!(receipt(low, operation, length, bad), Err(Error::Protocol));
        }
        let mut overlapping = good;
        *overlapping.get_mut(1).ok_or(Error::Bounds)? = low;
        assert_eq!(
            receipt(low, operation, length, overlapping),
            Err(Error::Protocol)
        );
    }
    for operation in [0, 3] {
        receipt(low, operation, 0, [0; 7])?;
        for index in 0..7 {
            let mut bad = [0; 7];
            *bad.get_mut(index).ok_or(Error::Bounds)? = 1;
            assert_eq!(receipt(low, operation, 0, bad), Err(Error::Protocol));
        }
    }
    Ok(())
}
