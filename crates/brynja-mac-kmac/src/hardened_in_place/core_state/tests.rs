use super::*;
use brynja_hash_sha3::HardenedSha3SecretOutput;
use core::cell::Cell;
extern crate std;

struct Failing<'a> {
    mode: &'a Cell<u8>,
    dropped: &'a Cell<bool>,
}
enum NoReader {}
impl Reader for NoReader {
    fn public(&mut self, _: &mut [u8]) -> Result<(), KmacError> {
        Err(KmacError::SecretMemory)
    }
    fn secret<'out>(
        &mut self,
        _: &'out mut [u8],
    ) -> Result<HardenedSha3SecretOutput<'out>, KmacError> {
        Err(KmacError::SecretMemory)
    }
    fn final_secret<'out>(
        self,
        _: &'out mut [u8],
        _: u8,
    ) -> Result<HardenedSha3SecretOutput<'out>, KmacError> {
        match self {}
    }
    fn final_public(self, _: Fips202Output<'_>) -> Result<(), KmacError> {
        match self {}
    }
}
impl State for Failing<'_> {
    type Reader = NoReader;
    fn update(&mut self, _: &[u8]) -> Result<(), KmacError> {
        match self.mode.get() {
            1 => Err(KmacError::MessageTooLong),
            2 => std::panic::resume_unwind(std::boxed::Box::new(())),
            _ => Ok(()),
        }
    }
    fn finish(self, _: Fips202BitString<'_>) -> Result<NoReader, KmacError> {
        Err(KmacError::SecretMemory)
    }
}
impl Drop for Failing<'_> {
    fn drop(&mut self) {
        self.dropped.set(true);
    }
}
fn poison(metadata: &mut Metadata) {
    metadata.key_class.fill(0xa5);
    metadata.verification.fill(0xa5);
    metadata.difference.fill(0xa5);
}

#[test]
fn rejected_and_unwinding_updates_destroy_state_immediately() -> Result<(), KmacError> {
    for mode_value in [1, 2] {
        let mut metadata = Metadata::new();
        let mode = Cell::new(0);
        let dropped = Cell::new(false);
        let mut state = Core::new(
            Failing {
                mode: &mode,
                dropped: &dropped,
            },
            &mut metadata,
            bytes(&[0x42; 16])?,
            168,
            128,
        )?;
        poison(state.cleanup.0);
        mode.set(mode_value);
        if mode_value == 1 {
            assert_eq!(state.update(b"secret"), Err(KmacError::MessageTooLong));
        } else {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.update(b"secret")));
            assert!(result.is_err());
        }
        assert!(dropped.get());
        assert!(state.cleanup.0.cleared());
        assert_eq!(state.update(b""), Err(KmacError::StateConsumed));
        let mut output = [0xa5; 16];
        assert!(matches!(
            state.secret(None, &mut output, 8, 128, true),
            Err(KmacError::StateConsumed)
        ));
        assert_eq!(output, [0; 16]);
        assert!(metadata.cleared());
    }
    Ok(())
}

#[test]
fn setup_and_finalization_failures_clear_owned_metadata() -> Result<(), KmacError> {
    for mode_value in [0, 1, 2] {
        let mut metadata = Metadata::new();
        poison(&mut metadata);
        let mode = Cell::new(mode_value);
        let dropped = Cell::new(false);
        let mut output = [0xa5; 16];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Core::new(
                Failing {
                    mode: &mode,
                    dropped: &dropped,
                },
                &mut metadata,
                bytes(&[0x42; 16])?,
                168,
                128,
            )?
            .secret(None, &mut output, 8, 128, true)
            .map(|_| ())
        }));
        if mode_value == 2 {
            assert!(result.is_err());
        } else {
            assert!(matches!(result, Ok(Err(_))));
        }
        assert!(dropped.get());
        assert!(metadata.cleared());
        if mode_value == 0 {
            assert_eq!(output, [0; 16]);
        }
    }
    Ok(())
}

#[test]
fn outer_guard_clears_all_regions_even_after_forgotten_inner_guard() {
    let mut metadata = Metadata::new();
    {
        let outer = Guard(&mut metadata);
        let inner = Guard(&mut *outer.0);
        poison(inner.0);
        core::mem::forget(inner);
    }
    assert!(metadata.cleared());
}

#[test]
fn xof_production_rejects_weak_keys_and_terminal_states() -> Result<(), KmacError> {
    for production in [false, true] {
        let mut metadata = Metadata::new();
        let mode = Cell::new(0);
        let dropped = Cell::new(false);
        let state = Core::new(
            Failing {
                mode: &mode,
                dropped: &dropped,
            },
            &mut metadata,
            bytes(b"")?,
            168,
            128,
        )?;
        let expected = if production {
            KmacError::KeyTooShort
        } else {
            KmacError::SecretMemory
        };
        assert!(matches!(state.finish_xof(None, production), Err(error) if error == expected));
        assert!(dropped.get());
        assert!(metadata.cleared());
        let mut state = Core::new(
            Failing {
                mode: &mode,
                dropped: &dropped,
            },
            &mut metadata,
            bytes(&[0x42; 16])?,
            168,
            128,
        )?;
        mode.set(1);
        assert_eq!(state.update(b""), Err(KmacError::MessageTooLong));
        assert!(matches!(
            state.finish_xof(None, production),
            Err(KmacError::StateConsumed)
        ));
        assert!(metadata.cleared());
    }
    Ok(())
}
