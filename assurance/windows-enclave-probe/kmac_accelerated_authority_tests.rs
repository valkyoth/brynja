use super::kmac_accelerated_tests::{authority, bits, empty, whole};
use super::*;
fn failed(owner: &Owner<'_>) {
    assert_eq!(owner.phase, Phase::Quarantined);
    assert!(matches!(owner.state, State::Empty));
    assert_eq!(owner.output, [0; 1024]);
    assert!(owner.authority.session().is_err());
}
#[test]
fn every_phase_rejects_revocation_without_copy_or_fallback() {
    if let Ok(wrong) = Authority::new(Kernel::X86Sha256) {
        assert!(matches!(Owner::new(&wrong), Err(Error::Backend)));
    }
    for phase in 0..8 {
        let authority = authority();
        let mut owner = Owner::new(&authority).unwrap();
        match phase {
            1 | 2 => {
                owner.begin_setup(1, 1, 256, 8).unwrap();
            }
            3 => {
                owner.begin_setup(1, 1, 256, 0).unwrap();
                owner.finish_customization(2).unwrap();
            }
            4 => {
                owner.begin(1, 1, whole(&[3; 32]), empty()).unwrap();
            }
            5 | 6 => {
                owner.begin(1, 1, whole(&[3; 32]), empty()).unwrap();
                owner.finish(2, empty(), 32, 8).unwrap();
            }
            7 => {
                owner.begin(1, 3, whole(&[3; 32]), empty()).unwrap();
                owner.finish(2, empty(), 0, 0).unwrap();
            }
            _ => {}
        }
        authority.quarantine();
        let result = match phase {
            0 => owner.begin(1, 1, whole(&[3; 32]), empty()),
            1 => owner.customization(2, whole(b"x")),
            2 => owner.cancel(2),
            3 => owner.key(3, whole(&[3; 32])),
            4 => owner.update(2, &[]),
            5 => owner.export(3, 1, 32, 8, |_| panic!("revoked copy")),
            6 => owner.rekey_setup(3, 1, 0),
            _ => owner.squeeze(3, 0, 0, true),
        };
        assert_eq!(result, Err(Error::Backend));
        failed(&owner);
        assert!(matches!(Owner::new(&authority), Err(Error::Backend)));
    }
}
#[test]
fn copy_failure_unwind_and_mid_copy_revocation_are_terminal() {
    for mode in 0..3 {
        let authority = authority();
        let mut owner = Owner::new(&authority).unwrap();
        owner.begin(1, 1, whole(&[3; 32]), empty()).unwrap();
        owner.finish(2, empty(), 32, 8).unwrap();
        if mode == 0 {
            assert_eq!(owner.export(3, 1, 32, 8, |_| false), Err(Error::Copy));
        } else if mode == 1 {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    owner.export(3, 1, 32, 8, |_| panic!("injected unwind"))
                }))
                .is_err()
            );
        } else {
            assert_eq!(
                owner.export(3, 1, 32, 8, |_| {
                    authority.quarantine();
                    true
                }),
                Err(Error::Backend)
            );
        }
        failed(&owner);
    }
}
#[test]
fn key_completion_strength_sequence_and_shapes_fail_closed() {
    for mode in 0..12 {
        let authority = authority();
        let mut owner = Owner::new(&authority).unwrap();
        let result = match mode {
            0 => owner.begin_setup(1, 1, 127, 0),
            1 => owner.begin_setup(1, 2, 255, 0),
            2 => owner.begin_setup(1, 1, 256, u128::MAX),
            3 => {
                owner.begin_setup(1, 1, 256, 1).unwrap();
                owner.finish_customization(2)
            }
            4 => {
                owner.begin_setup(1, 1, 256, 0).unwrap();
                owner.finish_customization(2).unwrap();
                owner.finish_setup(3)
            }
            5 => {
                owner.begin_setup(1, 1, 256, 0).unwrap();
                owner.finish_customization(2).unwrap();
                owner.key(3, whole(&[0; 33]))
            }
            6 => {
                owner.begin(1, 1, whole(&[3; 32]), empty()).unwrap();
                owner.update(1, &[])
            }
            7 => {
                owner.begin(1, 1, whole(&[3; 32]), empty()).unwrap();
                owner.finish(2, empty(), 15, 8)
            }
            8 => {
                owner.begin(1, 2, whole(&[3; 32]), empty()).unwrap();
                owner.finish(2, empty(), 31, 8)
            }
            9 => {
                owner.begin(1, 1, whole(&[3; 32]), empty()).unwrap();
                owner.update(2, &[0; 1025])
            }
            10 => {
                owner.begin(1, 1, whole(&[3; 32]), empty()).unwrap();
                owner.finish(2, empty(), 32, 0)
            }
            _ => {
                owner.begin(1, 3, whole(&[3; 32]), empty()).unwrap();
                owner.finish(2, empty(), 0, 0).unwrap();
                owner.squeeze(3, 1, 1, false)
            }
        };
        if mode == 11 {
            assert_eq!(result, Err(Error::Bits));
        }
        assert!(result.is_err(), "mode {mode}");
        failed(&owner);
    }
}
#[test]
fn verification_checks_every_byte_and_cancellation_allows_reuse() {
    for id in 1..=2 {
        for changed in 0..=32 {
            let authority = authority();
            let mut owner = Owner::new(&authority).unwrap();
            owner.begin(1, id, whole(&[3; 32]), empty()).unwrap();
            owner.cancel(2).unwrap();
            assert!(authority.session().is_ok());
            owner.begin(3, id, whole(&[3; 32]), empty()).unwrap();
            owner.finish(4, empty(), 32, 8).unwrap();
            let mut candidate = owner.output[..32].to_vec();
            if changed != 32 {
                candidate[changed] ^= 1;
            }
            assert_eq!(
                owner.verify(5, id, whole(&candidate)).unwrap(),
                changed == 32
            );
            assert_eq!(owner.output, [0; 1024]);
            assert_eq!(owner.phase, Phase::Empty);
            assert!(authority.session().is_ok());
        }
    }
}
#[test]
fn fragmented_key_and_setup_pending_byte_is_cleared() {
    let authority = authority();
    let mut owner = Owner::new(&authority).unwrap();
    owner.begin_setup(1, 1, 129, 0).unwrap();
    owner.finish_customization(2).unwrap();
    owner.key(3, bits(&[1], 1)).unwrap();
    owner.cancel(4).unwrap();
    assert!(matches!(owner.state, State::Empty));
    assert_eq!(owner.output, [0; 1024]);
    assert!(authority.session().is_ok());
}

#[test]
fn empty_cancellation_and_replayed_export_reject() {
    let authority = authority();
    let mut owner = Owner::new(&authority).unwrap();
    assert_eq!(owner.cancel(1), Err(Error::State));
    failed(&owner);
    let authority = super::kmac_accelerated_tests::authority();
    let mut owner = Owner::new(&authority).unwrap();
    owner.begin(1, 1, whole(&[3; 32]), empty()).unwrap();
    owner.finish(2, empty(), 32, 8).unwrap();
    assert_eq!(
        owner.export(2, 1, 32, 8, |_| panic!("replayed export")),
        Err(Error::Sequence)
    );
    failed(&owner);
}
