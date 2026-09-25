use super::*;

#[derive(Clone, Copy)]
// Native fault cases are intentionally unused on rejecting/model builds.
#[cfg_attr(
    not(all(
        target_os = "linux",
        target_env = "gnu",
        target_pointer_width = "64",
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )),
    allow(dead_code)
)]
pub(super) enum Fault {
    None,
    VerifyStorage,
    CancelAt(usize),
    PanicAfterWrite,
}
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
    static CHECKPOINT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
pub(super) fn configure(fault: Fault) {
    FAULT.with(|f| f.set(fault));
    CHECKPOINT.with(|c| c.set(0));
}
pub(super) fn checkpoint(cancel: &Cancellation) {
    let count = CHECKPOINT.with(|c| {
        let count = c.get();
        c.set(count.saturating_add(1));
        count
    });
    if let Fault::CancelAt(wanted) = FAULT.with(|f| f.get())
        && count == wanted
    {
        cancel.cancel();
    }
}
pub(super) fn after_write() {
    assert!(
        !matches!(FAULT.with(|f| f.get()), Fault::PanicAfterWrite),
        "intentional strict hash post-write unwind"
    );
}
pub(super) fn observe_storage<T: ?Sized>(value: &T) {
    if !matches!(FAULT.with(|f| f.get()), Fault::VerifyStorage) {
        return;
    }
    let address = core::ptr::from_ref(value).cast::<u8>() as usize;
    let maps = std::fs::read_to_string("/proc/self/smaps");
    assert!(maps.is_ok());
    if let Ok(maps) = maps {
        let mut selected = false;
        let mut verified = false;
        for line in maps.lines() {
            if let Some((range, _)) = line.split_once(' ')
                && let Some((start, stop)) = range.split_once('-')
                && let (Ok(start), Ok(stop)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(stop, 16),
                )
            {
                selected = start <= address && address < stop;
            }
            if selected && line.starts_with("VmFlags:") {
                for required in ["lo", "dd", "dc"] {
                    assert!(line.split_whitespace().any(|flag| flag == required));
                }
                verified = true;
            }
        }
        assert!(verified);
    }
}

fn limits() -> Limits {
    Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_output_mapping_bytes: 65536,
        max_message_bits: 16000000,
        max_chunks: 128,
    }
}

#[test]
fn metadata_and_request_arithmetic_are_bounded_without_touching_input() {
    let _resources = crate::protected_memory::test_resource_guard();
    assert_eq!(Algorithm::Sha256.output_bytes(), 32);
    assert_eq!(Algorithm::Sha512.output_bits(), 512);
    let mut bound = limits();
    bound.max_chunks = 1;
    assert_eq!(
        validate_request(Algorithm::Sha256, bound, &[&[], &[]], 0, 0),
        Err(Error::WorkLimit)
    );
    assert_eq!(
        validate_request(Algorithm::Sha256, bound, &[], 0, 1),
        Err(Error::InvalidBits)
    );
    assert_eq!(
        validate_request(Algorithm::Sha256, bound, &[], 1, 0),
        Err(Error::InvalidBits)
    );
    assert_eq!(
        validate_request(Algorithm::Sha256, bound, &[], 1, 9),
        Err(Error::InvalidBits)
    );
    bound.max_message_bits = 8;
    assert_eq!(
        validate_request(Algorithm::Sha256, bound, &[b"a"], 0, 0),
        Ok(())
    );
    assert_eq!(
        validate_request(Algorithm::Sha256, bound, &[b"a"], 1, 1),
        Err(Error::WorkLimit)
    );
    #[cfg(target_pointer_width = "64")]
    assert_eq!(
        validate_request(Algorithm::Sha256, bound, &[], usize::MAX, 8),
        Err(Error::MessageTooLong)
    );
}

#[cfg(not(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
)))]
#[test]
fn unsupported_targets_and_models_cannot_construct_a_session() {
    let _resources = crate::protected_memory::test_resource_guard();
    assert!(matches!(
        Session::new(Algorithm::Sha256, limits()),
        Err(Error::Resource(crate::protected_memory::Error::Unsupported))
    ));
}

#[cfg(all(
    target_os = "linux",
    target_env = "gnu",
    target_pointer_width = "64",
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
mod native {
    use super::*;
    use brynja_hash_sha2 as sha2;

    fn reference(algorithm: Algorithm, input: sha2::BitString<'_>) -> Vec<u8> {
        macro_rules! digest {
            ($function:ident) => {{
                let result = sha2::$function(input);
                assert!(result.is_ok());
                match result {
                    Ok(value) => value.as_bytes().to_vec(),
                    Err(_) => unreachable!(),
                }
            }};
        }
        match algorithm {
            Algorithm::Sha224 => digest!(sha224_bits),
            Algorithm::Sha256 => digest!(sha256_bits),
            Algorithm::Sha384 => digest!(sha384_bits),
            Algorithm::Sha512 => digest!(sha512_bits),
            Algorithm::Sha512_224 => digest!(sha512_224_bits),
            Algorithm::Sha512_256 => digest!(sha512_256_bits),
            Algorithm::Sha512T(t) => {
                let result = sha2::sha512_t_bits(t, input);
                assert!(result.is_ok());
                match result {
                    Ok(value) => value.as_bytes().to_vec(),
                    Err(_) => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn all_named_identities_match_padding_chunks_and_bit_tails() -> Result<(), Error> {
        let _resources = crate::protected_memory::test_resource_guard();
        for algorithm in [
            Algorithm::Sha224,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
            Algorithm::Sha512_224,
            Algorithm::Sha512_256,
        ] {
            let mut session = Session::new(algorithm, limits())?;
            for length in [
                0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 4095, 4096, 8193,
            ] {
                let input = vec![0x98; length];
                for valid in 1..=8 {
                    let mut input = input.clone();
                    if let Some(last) = input.last_mut() {
                        *last &= 0xff << (8 - valid);
                    }
                    let bits = if input.is_empty() { 0 } else { valid };
                    let canonical =
                        sha2::BitString::new(&input, bits).map_err(|_| Error::InvalidBits)?;
                    let expected = reference(algorithm, canonical);
                    let split = length.saturating_sub(1).min(33);
                    let digest = session.hash_chunks(
                        &[&[], input.get(..split).ok_or(Error::Invariant)?],
                        input.get(split..).ok_or(Error::Invariant)?,
                        bits,
                        &Cancellation::new(),
                    )?;
                    assert_eq!(digest.algorithm(), algorithm);
                    assert_eq!(digest.expose(), expected);
                    drop(digest);
                    assert!(session.output.as_bytes().iter().all(|b| *b == 0));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn all_510_general_parameters_keep_exact_identity_and_masking() -> Result<(), Error> {
        let _resources = crate::protected_memory::test_resource_guard();
        for t in 1..512 {
            let Ok(parameter) = Sha512TBits::new(t) else {
                continue;
            };
            let algorithm = Algorithm::Sha512T(parameter);
            let mut session = Session::new(algorithm, limits())?;
            let canonical = sha2::BitString::new(b"abc", 8).map_err(|_| Error::InvalidBits)?;
            let expected = reference(algorithm, canonical);
            let digest = session.hash(b"abc")?;
            assert_eq!(digest.algorithm(), algorithm);
            assert_eq!(digest.expose(), expected);
        }
        Ok(())
    }

    #[test]
    fn failures_clear_forgotten_outputs_and_resources_remain_reusable() -> Result<(), Error> {
        let _resources = crate::protected_memory::test_resource_guard();
        let mut bound = limits();
        bound.max_message_bits = 24;
        bound.max_chunks = 1;
        let mut session = Session::new(Algorithm::Sha256, bound)?;
        let cancelled = Cancellation::new();
        cancelled.cancel();
        for case in 0..5 {
            let previous = session.hash(b"abc")?;
            core::mem::forget(previous);
            assert!(session.output.as_bytes().iter().any(|b| *b != 0));
            let active = Cancellation::new();
            let result = match case {
                0 => session.hash(b"abcd"),
                1 => session.hash_chunks(&[], b"\xff", 1, &active),
                2 => session.hash_chunks(&[b"a", b"b"], &[], 0, &active),
                3 => session.hash_chunks(&[], &[], 0, &cancelled),
                _ => session.hash_chunks(&[], &[], 1, &active),
            };
            assert!(result.is_err());
            drop(result);
            assert!(session.output.as_bytes().iter().all(|b| *b == 0));
            let digest = session.hash(b"abc")?;
            assert_eq!(
                digest.expose(),
                sha2::sha256(b"abc")
                    .map_err(|_| Error::Invariant)?
                    .as_bytes()
            );
        }
        Ok(())
    }

    #[test]
    fn public_release_is_explicit_exact_width_and_clears_secret() -> Result<(), Error> {
        let _resources = crate::protected_memory::test_resource_guard();
        let mut session = Session::new(Algorithm::Sha256, limits())?;
        let mut wrong = [0xa5; 31];
        assert_eq!(
            session
                .hash(b"abc")?
                .declassify(&mut wrong, PublicDeclassification::acknowledge()),
            Err(Error::OutputLength)
        );
        assert_eq!(wrong, [0xa5; 31]);
        assert!(session.output.as_bytes().iter().all(|b| *b == 0));
        let mut public = [0; 32];
        session
            .hash(b"abc")?
            .declassify(&mut public, PublicDeclassification::acknowledge())?;
        assert_eq!(
            &public,
            sha2::sha256(b"abc")
                .map_err(|_| Error::Invariant)?
                .as_bytes()
        );
        assert!(session.output.as_bytes().iter().all(|b| *b == 0));
        Ok(())
    }

    #[test]
    fn output_protection_and_resource_failures_are_real() -> Result<(), Error> {
        let _resources = crate::protected_memory::test_resource_guard();
        for algorithm in [
            Algorithm::Sha224,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
            Algorithm::Sha512_224,
            Algorithm::Sha512_256,
            Algorithm::Sha512T(Sha512TBits::new(9).map_err(|_| Error::Invariant)?),
        ] {
            let mut session = Session::new(algorithm, limits())?;
            session.fault = Fault::VerifyStorage;
            drop(session.hash(b"abc")?);
        }
        let mut bound = limits();
        bound.max_output_mapping_bytes = 32;
        assert!(matches!(
            Session::new(Algorithm::Sha256, bound),
            Err(Error::Resource(_))
        ));
        bound = limits();
        bound.stack_bytes = 65535;
        assert!(matches!(
            Session::new(Algorithm::Sha256, bound),
            Err(Error::Resource(_))
        ));
        bound = limits();
        bound.max_chunks = 0;
        assert!(matches!(
            Session::new(Algorithm::Sha256, bound),
            Err(Error::InvalidLimits)
        ));
        let mut session = Session::new(Algorithm::Sha256, limits())?;
        session.fault = Fault::VerifyStorage;
        let digest = session.hash(b"abc")?;
        let address = digest.expose().as_ptr() as usize;
        let maps = std::fs::read_to_string("/proc/self/smaps").map_err(|_| Error::Invariant)?;
        let mut selected = false;
        let mut verified = false;
        for line in maps.lines() {
            if let Some((range, _)) = line.split_once(' ')
                && let Some((start, stop)) = range.split_once('-')
                && let (Ok(start), Ok(stop)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(stop, 16),
                )
            {
                selected = start <= address && address < stop;
            }
            if selected && line.starts_with("VmFlags:") {
                for required in ["lo", "dd", "dc"] {
                    assert!(line.split_whitespace().any(|flag| flag == required));
                }
                verified = true;
            }
        }
        assert!(verified);
        Ok(())
    }

    #[test]
    fn cancellation_at_each_boundary_and_post_write_panic_clear_output() -> Result<(), Error> {
        let _resources = crate::protected_memory::test_resource_guard();
        let input = vec![0x98; 8193];
        for algorithm in [
            Algorithm::Sha256,
            Algorithm::Sha512,
            Algorithm::Sha512T(Sha512TBits::new(9).map_err(|_| Error::Invariant)?),
        ] {
            let mut session = Session::new(algorithm, limits())?;
            for checkpoint in 0..8 {
                session.fault = Fault::CancelAt(checkpoint);
                let cancel = Cancellation::new();
                assert!(matches!(
                    session.hash_chunks(&[&input], b"\x80", 1, &cancel),
                    Err(Error::Cancelled)
                ));
                assert!(session.output.as_bytes().iter().all(|b| *b == 0));
            }
            session.fault = Fault::PanicAfterWrite;
            assert!(matches!(
                session.hash(b"abc"),
                Err(Error::Resource(
                    crate::protected_memory::Error::WorkerPanicked
                ))
            ));
            assert!(session.output.as_bytes().iter().all(|b| *b == 0));
            session.fault = Fault::None;
            let digest = session.hash(b"abc")?;
            let canonical = sha2::BitString::new(b"abc", 8).map_err(|_| Error::InvalidBits)?;
            assert_eq!(digest.expose(), reference(algorithm, canonical));
        }
        Ok(())
    }
}
