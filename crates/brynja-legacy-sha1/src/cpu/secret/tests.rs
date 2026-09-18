use super::*;
extern crate std;

fn model(revalidate: fn(Sha1Backend) -> bool) -> Authority {
    Authority {
        backend: Sha1Backend::X86Sha,
        healthy: Cell::new(true),
        revalidate,
        _thread: PhantomData,
    }
}
fn cleared(owner: &Sha1Owner) {
    assert_eq!(owner.chaining_state, [0; 20]);
    assert_eq!(owner.block, [0; 64]);
    assert_eq!(owner.schedule, [0; 320]);
    assert_eq!(owner.message_length, [0; 8]);
    assert_eq!(owner.buffered, [0]);
    assert_eq!(owner.output_staging, [0; 20]);
}

#[test]
fn rejected_callback_wipes_owner_and_cannot_revive() {
    let authority = model(|_| false);
    let mut owner = Sha1Owner::new();
    owner.block.fill(0xa5);
    assert_eq!(
        authority.compress(&mut owner),
        Err(Sha1BackendError::MissingFeatures)
    );
    cleared(&owner);
    assert_eq!(
        authority.ensure_healthy(),
        Err(Sha1BackendError::Quarantined)
    );
}

#[test]
fn callback_unwind_wipes_owner_and_quarantines() {
    fn interrupt(_: Sha1Backend) -> bool {
        std::panic::resume_unwind(std::boxed::Box::new("test-only callback interruption"));
    }
    let authority = model(interrupt);
    let mut owner = Sha1Owner::new();
    owner.block.fill(0xa5);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = authority.compress(&mut owner);
    }));
    assert!(outcome.is_err());
    cleared(&owner);
    assert_eq!(authority.health(), Sha1BackendHealth::Quarantined);
}

#[test]
fn one_shot_callback_unwind_clears_destination_before_start() {
    fn interrupt(_: Sha1Backend) -> bool {
        std::panic::resume_unwind(std::boxed::Box::new("test-only interruption"));
    }
    // The test lives inside the authority boundary; no instructions are reached.
    let executor = crate::hardened_execution::Executor::test_authority(model(interrupt));
    let mut destination = [0xa5; 20];
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = executor.hash_secret(b"secret", &mut destination);
        }))
        .is_err()
    );
    assert_eq!(destination, [0; 20]);
    assert_eq!(executor.report().health, Sha1BackendHealth::Quarantined);
}

#[test]
fn lane_wipe_clears_full_owner() {
    let mut scratch = Scratch::new();
    scratch.lanes.fill(0xa5);
    scratch.wipe();
    assert_eq!(scratch.lanes, [0; 16]);
}

#[test]
fn native_hardened_kernel_matches_512_arbitrary_compressions() -> Result<(), Sha1BackendError> {
    let authority = match Authority::for_compiled_target() {
        Ok(authority) => authority,
        Err(Sha1BackendError::MissingFeatures) => {
            assert!(
                std::env::var_os("BRYNJA_REQUIRE_HARDENED_SHA1").is_none(),
                "required hardened SHA-1 kernel has no compiled CPU feature bundle"
            );
            std::println!(
                "HARDENED_SHA1_EXECUTION: SKIPPED; portable build, not hardware evidence"
            );
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let mut seed = 0x5a41_0242_a912_4501_u64;
    for _ in 0..512 {
        let mut scalar = Sha1Owner::new();
        for byte in scalar
            .chaining_state
            .iter_mut()
            .chain(scalar.block.iter_mut())
        {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = u8::try_from(seed & 0xff).unwrap_or_default();
        }
        let mut accelerated = Sha1Owner::new();
        accelerated
            .chaining_state
            .copy_from_slice(&scalar.chaining_state);
        accelerated.block.copy_from_slice(&scalar.block);
        crate::compress::compress(&mut scalar);
        authority.compress(&mut accelerated)?;
        assert_eq!(accelerated.chaining_state, scalar.chaining_state);
        assert_eq!(accelerated.block, [0; 64]);
        assert_eq!(accelerated.schedule, [0; 320]);
        assert_eq!(accelerated.buffered, [0]);
    }
    std::println!(
        "\nHARDENED_SHA1_EXECUTION: {}; blocks=512",
        authority.backend().as_str()
    );
    Ok(())
}
