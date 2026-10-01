use super::*;
fn authority() -> Authority {
    Authority::new(Kernel::X86Keccak).unwrap()
}
fn failed(owner: &Owner<'_>) {
    assert_eq!(owner.phase, Phase::Quarantined);
    assert!(matches!(owner.state, State::Empty));
    assert_eq!(owner.output, [0; 1024]);
    assert_eq!(owner.remaining, [0; 16]);
    assert_eq!(owner.width, 0);
    assert_eq!(owner.last, 0);
    assert!(owner.authority.session().is_err());
}
fn prepared<'a>(authority: &'a Authority, identity: u64) -> Owner<'a> {
    let mut owner = Owner::new(authority).unwrap();
    owner.begin(1, identity, 0).unwrap();
    owner.finish_custom(2).unwrap();
    owner
}
#[test]
fn every_operation_rejects_revocation_even_without_permutation() {
    if let Ok(wrong) = Authority::new(Kernel::X86Sha256) {
        assert!(matches!(Owner::new(&wrong), Err(Error::Backend)));
    }
    for mode in 0..11 {
        let authority = authority();
        let mut o = Owner::new(&authority).unwrap();
        if mode > 0 {
            o.begin(1, if mode == 6 { 3 } else { 1 }, 0).unwrap();
        }
        if mode > 2 {
            o.finish_custom(2).unwrap();
        }
        if matches!(mode, 4 | 5) {
            o.begin_item(3, 0).unwrap();
        }
        if mode == 6 {
            o.finish(3, 0, 0).unwrap();
        }
        if matches!(mode, 7 | 8) {
            o.finish(3, 32, 8).unwrap();
        }
        authority.quarantine();
        let seq = o.sequence + 1;
        let result = match mode {
            0 => o.begin(seq, 1, 0),
            1 => o.custom(seq, Bits::new(&[], 0).unwrap()),
            2 => o.finish_custom(seq),
            3 => o.begin_item(seq, 0),
            4 => o.fragment(seq, Bits::new(&[], 0).unwrap()),
            5 => o.finish_item(seq),
            6 => o.squeeze(seq, 0, 0, true),
            7 => o.export(seq, 1, 32, 8, |_| panic!("revoked export")),
            8 => o.rehash(seq, 2, 0),
            9 => o.cancel(seq),
            _ => o.finish(seq, 32, 8),
        };
        assert_eq!(result, Err(Error::Backend), "mode {mode}");
        failed(&o);
        assert!(matches!(Owner::new(&authority), Err(Error::Backend)));
    }
}
#[test]
fn output_copy_revocation_and_unwind_revoke_authority() {
    for mode in 0..3 {
        let authority = authority();
        let mut o = prepared(&authority, 1);
        o.finish(3, 32, 7).unwrap();
        if mode == 0 {
            assert_eq!(o.export(4, 1, 32, 7, |_| false), Err(Error::Copy));
        } else if mode == 1 {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    o.export(4, 1, 32, 7, |_| panic!("copy fault"))
                }))
                .is_err()
            );
        } else {
            assert_eq!(
                o.export(4, 1, 32, 7, |_| {
                    authority.quarantine();
                    true
                }),
                Err(Error::Backend)
            );
        }
        failed(&o);
    }
}
#[test]
fn cancellation_and_empty_updates_allow_reuse_but_drop_revokes() {
    for id in 1..=4 {
        let authority = authority();
        {
            let mut o = Owner::new(&authority).unwrap();
            o.begin(1, id, 0).unwrap();
            o.custom(2, Bits::new(&[], 0).unwrap()).unwrap();
            o.finish_custom(3).unwrap();
            o.begin_item(4, 9).unwrap();
            o.fragment(5, Bits::new(&[1], 1).unwrap()).unwrap();
            o.cancel(6).unwrap();
            assert_eq!(o.phase, Phase::Empty);
            assert_eq!(o.remaining, [0; 16]);
            assert_eq!(o.output, [0; 1024]);
            assert!(authority.session().is_ok());
            o.begin(7, id, 0).unwrap();
            o.finish_custom(8).unwrap();
            o.finish(9, 0, 0).unwrap();
            if id > 2 {
                o.squeeze(10, 0, 0, true).unwrap();
            }
        }
        assert!(authority.session().is_err());
    }
}
#[test]
fn invalid_cancel_replay_overflow_and_xof_length_are_terminal() {
    for mode in 0..5 {
        let authority = authority();
        let mut o = Owner::new(&authority).unwrap();
        let result = match mode {
            0 => o.cancel(1),
            1 => {
                o.sequence = u64::MAX;
                o.begin(0, 1, 0)
            }
            2 => o.begin(1, 1, u128::MAX),
            3 => {
                o.begin(1, 3, 0).unwrap();
                o.finish_custom(2).unwrap();
                o.finish(3, 1, 8)
            }
            _ => {
                o.begin(1, 1, 0).unwrap();
                o.finish_custom(2).unwrap();
                o.finish(3, 32, 8).unwrap();
                o.export(3, 1, 32, 8, |_| panic!("replayed export"))
            }
        };
        assert!(result.is_err(), "mode {mode}");
        failed(&o);
    }
}
