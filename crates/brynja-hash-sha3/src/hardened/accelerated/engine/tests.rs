extern crate std;
use super::*;
use crate::hardened::accelerated::{Reader, Sha3PublicDeclassification};
use brynja_crypto_cpu::static_execution::{Authority, Kernel};

fn cleared(memory: &Memory) -> bool {
    [
        &memory.lanes[..],
        &memory.message_count,
        &memory.output_count,
        &memory.suffix,
    ]
    .into_iter()
    .all(|region| region.iter().all(|b| *b == 0))
}

#[test]
fn every_memory_region_is_explicitly_cleared() {
    let mut memory = Memory::new();
    memory.lanes.fill(0xa5);
    memory.message_count.fill(0xb6);
    memory.output_count.fill(0xc7);
    memory.suffix.fill(0xd8);
    memory.wipe();
    assert!(cleared(&memory));
}

fn authority() -> Result<Option<Authority>, Error> {
    let compiled = cfg!(all(target_arch = "x86_64", target_feature = "avx2"))
        || cfg!(all(target_arch = "aarch64", target_feature = "sha3"));
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::ArmKeccak
    } else {
        Kernel::X86Keccak
    };
    if compiled {
        Authority::new(kernel).map(Some).map_err(Error::Backend)
    } else {
        Ok(None)
    }
}
fn engine(owner: &Authority) -> Result<Engine<'_>, Error> {
    Engine::new(
        KeccakSession::from_static(owner).map_err(Error::Backend)?,
        136,
    )
}

#[test]
fn late_squeeze_errors_clear_state_and_secret_output_but_preserve_public_output()
-> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    for secret in [false, true] {
        let mut engine = engine(&owner)?;
        engine.update(b"secret")?;
        engine.finish(crate::hardened::accelerated::empty()?, 0x1f, 5)?;
        engine.remaining_permutations = Some(1);
        let mut reader = Reader { engine };
        let mut output = [0xa5; 500];
        let mut scratch = [0x5a; 501];
        if secret {
            assert!(reader.squeeze_secret(&mut output).is_err());
            assert_eq!(output, [0; 500]);
        } else {
            assert!(
                reader
                    .squeeze_public_with_scratch(
                        &mut output,
                        &mut scratch,
                        Sha3PublicDeclassification::acknowledge()
                    )
                    .is_err()
            );
            assert_eq!(output, [0xa5; 500]);
            assert_eq!(scratch, [0; 501]);
        }
        assert!(reader.engine.failed);
        assert!(cleared(&reader.engine.memory));
        assert_eq!(reader.engine.check(true), Err(Error::Terminal));
    }
    Ok(())
}

#[test]
fn overflow_and_unwind_terminate_and_clear_the_owner() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    let mut state = engine(&owner)?;
    state.memory.message_count.fill(0xff);
    assert_eq!(state.update(b"x"), Err(Error::LengthOverflow));
    assert!(cleared(&state.memory));
    let mut state = engine(&owner)?;
    state.update(b"secret")?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _operation = Operation::new(&mut state);
        std::panic::resume_unwind(std::boxed::Box::new("hardened sponge unwind"));
    }));
    assert!(result.is_err());
    assert!(state.failed);
    assert!(cleared(&state.memory));
    Ok(())
}
