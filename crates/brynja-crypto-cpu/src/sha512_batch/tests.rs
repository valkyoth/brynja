use super::*;
extern crate std;

#[test]
fn absent_static_bundle_rejects_before_entry() {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            assert!(Authority::for_compiled_target(kernel).is_err());
        }
    }
}

#[test]
fn compiled_kernel_kat_and_revocation() -> Result<(), Error> {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let owner = Authority::for_compiled_target(kernel)?;
        let session = owner.session()?;
        let mut states = [crate::sha512::initial_state(); 4];
        let blocks = [crate::sha512::abc_block(); 4];
        assert_eq!(
            session.compress(PublicData::new(&mut states), PublicData::new(&blocks)),
            Ok(())
        );
        assert!(
            states
                .iter()
                .take(kernel.width())
                .all(|s| *s == crate::sha512::abc_digest_state())
        );
        assert!(
            states
                .iter()
                .skip(kernel.width())
                .all(|s| *s == crate::sha512::initial_state())
        );
        let before = states;
        owner.quarantine();
        assert_eq!(
            session.compress(PublicData::new(&mut states), PublicData::new(&blocks)),
            Err(Error::Quarantined)
        );
        assert_eq!(states, before);
    }
    Ok(())
}

#[test]
fn failed_revalidation_and_unwind_revoke_before_instruction_entry() {
    let denied = Authority {
        kernel: Kernel::Avx2,
        healthy: Cell::new(true),
        completed_calls: Cell::new(0),
        revalidate: |_| false,
        thread_bound: PhantomData,
    };
    assert_eq!(denied.check(), Err(Error::Quarantined));
    assert!(!denied.is_healthy());
    let unwinding = Authority {
        kernel: Kernel::Avx2,
        healthy: Cell::new(true),
        completed_calls: Cell::new(0),
        thread_bound: PhantomData,
        revalidate: |_| std::panic::resume_unwind(std::boxed::Box::new("test revalidator")),
    };
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unwinding.check())).is_err());
    assert!(!unwinding.is_healthy());
}
