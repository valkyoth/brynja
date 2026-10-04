use super::*;
use std::cell::Cell;

struct Mock {
    mode: u8,
    calls: usize,
    settled: Cell<usize>,
}
impl Channel for Mock {
    fn execute(&mut self, request: &Request<'_>, output: &mut [u8; 1024]) -> Result<(), Error> {
        let header = request.header()?;
        assert_eq!(header.first(), Some(&0x4252594e50485749));
        self.calls = self.calls.checked_add(1).ok_or(Error::Exhausted)?;
        output.fill(0xa5);
        if self.mode == 1 {
            return Err(Error::Protocol);
        }
        if self.mode == 2 {
            std::panic::resume_unwind(Box::new(()));
        }
        let rem = request.plan.output_bits % 8;
        if self.mode != 4 && rem != 0 {
            let index = request
                .plan
                .output_bytes()
                .checked_sub(1)
                .ok_or(Error::Bounds)?;
            let mask = 255_u8 >> (8_usize.checked_sub(rem).ok_or(Error::Bounds)?);
            *output.get_mut(index).ok_or(Error::Bounds)? &= mask;
        }
        Ok(())
    }
    fn settled(&self) -> Result<(), Error> {
        self.settled
            .set(self.settled.get().checked_add(1).ok_or(Error::Exhausted)?);
        if self.mode == 3 {
            Err(Error::Release)
        } else {
            Ok(())
        }
    }
}
fn owner(mode: u8) -> Owner<Mock> {
    Owner::new(Mock {
        mode,
        calls: 0,
        settled: Cell::new(0),
    })
}
fn empty() -> Input<'static> {
    Input::new(
        Part {
            bytes: &[],
            bits: 0,
        },
        Part {
            bytes: &[],
            bits: 0,
        },
    )
}
fn plan(bits: usize) -> Result<Plan, Error> {
    Plan::new(Algorithm::ParallelHash128, 1, bits)
}
fn public() -> PublicDeclassification {
    PublicDeclassification::acknowledge()
}

#[test]
fn output_is_exact_transactional_canonical_and_terminal() -> Result<(), Error> {
    for bits in [0_usize, 1, 7, 8, 9, 8191, 8192] {
        let mut state = owner(0);
        let mut output = vec![0x77; bits.div_ceil(8)];
        state.digest_public(plan(bits)?, empty(), &mut output, public())?;
        let mut expected = vec![0xa5; bits.div_ceil(8)];
        if bits % 8 != 0 {
            *expected.last_mut().ok_or(Error::Bounds)? &= 255 >> (8 - bits % 8);
        }
        assert_eq!(output, expected);
        assert_eq!(state.state, State::Complete);
        assert_eq!(state.channel.settled.get(), 1);
        assert_eq!(
            state.digest_public(plan(bits)?, empty(), &mut output, public()),
            Err(Error::Quarantined)
        );
        assert_eq!(state.channel.calls, 1);
    }
    Ok(())
}
#[test]
fn rejects_partial_write_cleanup_error_and_noncanonical_output() -> Result<(), Error> {
    for mode in [1, 3, 4] {
        let mut state = owner(mode);
        let mut output = [0x77];
        let bits = if mode == 4 { 1 } else { 8 };
        assert!(
            state
                .digest_public(plan(bits)?, empty(), &mut output, public())
                .is_err()
        );
        assert_eq!(output, [0x77]);
        assert_eq!(state.state, State::Quarantined);
        assert_eq!(state.channel.settled.get(), 1);
        assert_eq!(
            state.digest_public(plan(8)?, empty(), &mut output, public()),
            Err(Error::Quarantined)
        );
        assert_eq!(state.channel.calls, 1);
    }
    Ok(())
}
#[test]
fn unwind_does_not_publish_or_reopen() -> Result<(), Error> {
    let mut state = owner(2);
    let mut output = [0x77];
    let p = plan(8)?;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = state.digest_public(p, empty(), &mut output, public());
        }))
        .is_err()
    );
    assert_eq!(state.state, State::Quarantined);
    assert_eq!(output, [0x77]);
    assert_eq!(
        state.digest_public(p, empty(), &mut output, public()),
        Err(Error::Quarantined)
    );
    Ok(())
}
#[test]
fn wrong_destination_width_never_calls_transport_and_is_retryable() -> Result<(), Error> {
    for bits in [0_usize, 1, 8, 9, 8192] {
        for length in [0, 1, 2, 1024, 1025] {
            if length == bits.div_ceil(8) {
                continue;
            }
            let mut state = owner(0);
            let mut output = vec![0x77; length];
            assert_eq!(
                state.digest_public(plan(bits)?, empty(), &mut output, public()),
                Err(Error::Bounds)
            );
            assert_eq!(output, vec![0x77; length]);
            assert_eq!(state.channel.calls, 0);
            assert_eq!(state.channel.settled.get(), 0);
            assert_eq!(state.state, State::Ready);
            state.digest_public(plan(0)?, empty(), &mut [], public())?;
        }
    }
    Ok(())
}
#[test]
fn plan_and_bit_shapes_fail_closed_at_boundaries() {
    for b in [0, 1025, u64::MAX] {
        assert!(Plan::new(Algorithm::ParallelHash256, b, 0).is_err());
    }
    for n in [8193, usize::MAX] {
        assert!(Plan::new(Algorithm::ParallelHash256, 1, n).is_err());
    }
    for b in [1, 1024] {
        for n in [0, 8192] {
            assert!(Plan::new(Algorithm::ParallelHash256, b, n).is_ok());
        }
    }
    assert_eq!(shape(0, 0), Ok(0));
    for last in 1..=255 {
        assert_eq!(shape(0, last), Err(Error::Bounds));
    }
    for last in [0, 9, 255] {
        assert_eq!(shape(1, last), Err(Error::Bounds));
    }
    for last in 1..=8 {
        assert_eq!(shape(1, last), Ok(u64::from(last)));
    }
    #[cfg(target_pointer_width = "64")]
    assert!(shape(usize::MAX, 8).is_err());
    assert!(Part::bits(&[255], 1).is_ok());
}
#[test]
fn request_metadata_does_not_accept_extra_leaf_or_custom_bit() -> Result<(), Error> {
    for (bytes, last, custom_len, custom_last, valid) in [
        (65536, 8, 1024, 8, true),
        (65537, 1, 0, 0, false),
        (0, 0, 1025, 1, false),
        (0, 0, 1024, 8, true),
    ] {
        let message = vec![0; bytes];
        let custom = vec![0; custom_len];
        let input = Input::new(
            Part::bits(&message, last)?,
            Part::bits(&custom, custom_last)?,
        );
        let mut state = owner(0);
        assert_eq!(
            state
                .digest_public(plan(0)?, input, &mut [], public())
                .is_ok(),
            valid
        );
        assert_eq!(state.channel.calls, usize::from(valid));
        if !valid {
            assert_eq!(state.state, State::Ready);
        }
    }
    Ok(())
}
#[test]
fn header_preserves_identity_borrowed_addresses_and_zero_empty_fields() -> Result<(), Error> {
    for (algorithm, id) in [
        (Algorithm::ParallelHash128, 1),
        (Algorithm::ParallelHash256, 2),
        (Algorithm::ParallelHashXof128, 3),
        (Algorithm::ParallelHashXof256, 4),
    ] {
        let message = [1, 2];
        let custom = [3];
        let request = Request {
            plan: Plan::new(algorithm, 7, 9)?,
            input: Input::new(Part::bits(&message, 1)?, Part::bits(&custom, 2)?),
        };
        assert_eq!(
            request.header()?,
            [
                0x4252594e50485749,
                1,
                id,
                7,
                9,
                2,
                9,
                message.as_ptr() as u64,
                custom.as_ptr() as u64,
                1,
                0,
                0,
                0,
                0,
                0,
                0
            ]
        );
    }
    assert_eq!(
        Request {
            plan: plan(0)?,
            input: empty()
        }
        .header()?
        .get(7..9),
        Some([0, 0].as_slice())
    );
    Ok(())
}
#[cfg(not(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
)))]
#[test]
fn constructor_on_unsupported_transport_has_no_fallback() {
    static POLICY: ImagePolicy =
        ImagePolicy::reviewed_sha256([1; 32], [2; 16], [3; 16], 1, 1, [0, 0]);
    assert!(matches!(
        Session::open_avx2(Path::new("unused"), &POLICY),
        Err(Error::Unsupported)
    ));
}
#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc",
    not(miri),
    not(kani)
))]
mod native;
