use super::*;

#[kani::proof]
fn reservation_and_successor() {
    let prefix: [u8; 4] = kani::any();
    let first: u64 = kani::any();
    let count: u64 = kani::any();
    let mut result = Sealer::from_reserved_range(&[0; 32], prefix, first, count);
    let fits = count != 0 && u128::from(first) + u128::from(count) <= (1_u128 << 64);
    assert_eq!(result.is_ok(), fits);
    if let Ok(sender) = &mut result {
        let nonce = sender.take_nonce().unwrap();
        assert_eq!(
            nonce.split_at(4),
            (prefix.as_slice(), first.to_be_bytes().as_slice())
        );
        let next = sender.take_nonce();
        if count == 1 {
            assert_eq!(next, Err(Error::Exhausted));
            assert_eq!(sender.take_nonce(), Err(Error::Exhausted));
        } else {
            assert_eq!(
                next.unwrap().split_at(4),
                (prefix.as_slice(), (first + 1).to_be_bytes().as_slice())
            );
        }
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn staged_commit_for_both_layouts() {
    let initial: [u8; 4] = kani::any();
    let source: [u8; 4] = kani::any();
    let computed: [u8; 4] = kani::any();
    let separate: bool = kani::any();
    let success: bool = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= 4);
    let mut dst = initial;
    let mut work: [u8; 4] = kani::any();
    let before = work;
    let io = if separate {
        Buffers::Separate(&source[..n], &mut dst[..n])
    } else {
        Buffers::InPlace(&mut dst[..n])
    };
    let result = io.transact(&mut work[..n], |input, scratch| {
        assert_eq!(
            input,
            if separate {
                &source[..n]
            } else {
                &initial[..n]
            }
        );
        scratch.copy_from_slice(&computed[..n]);
        if success {
            Ok(())
        } else {
            Err(Error::Invariant)
        }
    });
    assert_eq!(result.is_ok(), success);
    assert_eq!(
        &dst[..n],
        if success {
            &computed[..n]
        } else {
            &initial[..n]
        }
    );
    assert_eq!(&dst[n..], &initial[n..]);
    assert_eq!(&work[..n], &[0; 4][..n]);
    assert_eq!(&work[n..], &before[n..]);
}
