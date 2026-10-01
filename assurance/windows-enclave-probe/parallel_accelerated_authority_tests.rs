use super::*;
fn authority() -> Authority {
    Authority::new(Kernel::X86Keccak).unwrap()
}
fn failed(o: &Owner<'_>) {
    assert_eq!(o.phase, Phase::Quarantined);
    assert!(matches!(o.root, State::Empty));
    assert!(o.input.cleared());
    assert_eq!(o.output, [0; 1024]);
    assert_eq!(o.budget, [0; 8]);
    assert_eq!((o.width, o.last, o.next_width, o.next_last), (0, 0, 0, 0));
    assert!(o.authority.session().is_err());
}
#[test]
fn every_operation_checks_revocation_including_zero_work() {
    for mode in 0..9 {
        let a = authority();
        let mut o = Owner::new(&a).unwrap();
        if mode > 0 {
            o.begin(1, if mode == 5 { 3 } else { 1 }, 8, 0, 3).unwrap();
        }
        if mode > 2 {
            o.finish_custom(2).unwrap();
        }
        if mode == 5 {
            o.finish(3, empty().unwrap(), 0, 0).unwrap();
        }
        if matches!(mode, 6 | 7) {
            o.finish(3, empty().unwrap(), 32, 8).unwrap();
        }
        a.quarantine();
        let n = o.sequence + 1;
        let result = match mode {
            0 => o.begin(n, 1, 8, 0, 3),
            1 => o.custom(n, empty().unwrap()),
            2 => o.finish_custom(n),
            3 => o.update(n, &[]),
            4 => o.finish(n, empty().unwrap(), 0, 0),
            5 => o.squeeze(n, 0, 0, true),
            6 => o.export(n, 1, 32, 8, |_| panic!("revoked export")),
            7 => o.rehash(n, 2, 8, 0, 33, (32, 8)),
            _ => o.cancel(n),
        };
        assert_eq!(result, Err(Error::Backend), "mode {mode}");
        failed(&o);
        assert!(matches!(Owner::new(&a), Err(Error::Backend)));
    }
}
#[test]
fn copy_revocation_unwind_and_drop_revoke_authority() {
    for mode in 0..3 {
        let a = authority();
        let mut o = Owner::new(&a).unwrap();
        o.begin(1, 1, 8, 0, 3).unwrap();
        o.finish_custom(2).unwrap();
        o.finish(3, Bits::new(b"abc", 8).unwrap(), 32, 8).unwrap();
        match mode {
            0 => assert_eq!(o.export(4, 1, 32, 8, |_| false), Err(Error::Copy)),
            1 => assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| o.export(
                    4,
                    1,
                    32,
                    8,
                    |_| panic!("copy fault")
                )))
                .is_err()
            ),
            _ => assert_eq!(
                o.export(4, 1, 32, 8, |_| {
                    a.quarantine();
                    true
                }),
                Err(Error::Backend)
            ),
        }
        failed(&o);
    }
    let a = authority();
    {
        let _o = Owner::new(&a).unwrap();
    }
    assert!(a.session().is_err());
}
#[test]
fn accelerated_protocol_is_distinct_and_route_bound() {
    use super::parallel_accelerated_wire::{BEGIN, HEADER_BYTES, Header};
    let mut bytes = [0; HEADER_BYTES];
    for (word, value) in [(0, 18_u64), (1, 1), (2, 1), (3, 8), (14, 1)] {
        bytes[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    assert!(Header::decode(BEGIN, &bytes).is_ok());
    for (word, value) in [(0, 12_u64), (14, 0), (14, 2), (15, 1)] {
        let mut changed = bytes;
        changed[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
        assert!(Header::decode(BEGIN, &changed).is_err());
    }
}

#[test]
fn invalid_cancel_and_repeated_begin_are_terminal() {
    for mode in 0..2 {
        let a = authority();
        let mut o = Owner::new(&a).unwrap();
        let result = if mode == 0 {
            o.cancel(1)
        } else {
            o.begin(1, 1, 8, 0, 3).unwrap();
            o.begin(2, 1, 8, 0, 3)
        };
        assert_eq!(result, Err(Error::State));
        failed(&o);
    }
}

#[test]
fn partial_nonterminal_xof_is_rejected_before_crypto_dispatch() {
    let a = authority();
    let mut o = Owner::new(&a).unwrap();
    o.begin(1, 3, 8, 0, 0).unwrap();
    o.finish_custom(2).unwrap();
    o.finish(3, empty().unwrap(), 0, 0).unwrap();
    assert_eq!(o.squeeze(4, 1, 3, false), Err(Error::Bits));
    failed(&o);
}
