#![forbid(unsafe_code)]

#[cfg(kani)]
#[path = "../../../crates/brynja-aead-gcm/src/aes_gcm/portable/transaction.rs"]
mod transaction;

#[cfg(kani)]
mod proofs {
    use super::transaction::Buffers;

    const MAX: usize = 17; // empty, partial, full, and a byte of a second block

    fn length() -> usize {
        let n = usize::from(kani::any::<u8>());
        kani::assume(n <= MAX);
        n
    }

    fn check(in_place: bool) {
        let source: [u8; MAX] = kani::any();
        let original: [u8; MAX] = kani::any();
        let staged: [u8; MAX] = kani::any();
        let mut destination = original;
        let mut work: [u8; MAX] = kani::any();
        let (dst_len, work_len) = (length(), length());
        let src_len = if in_place { dst_len } else { length() };
        let expected_input = if in_place { &original } else { &source };
        let buffers = if in_place {
            Buffers::InPlace(&mut destination[..dst_len])
        } else {
            Buffers::Separate(&source[..src_len], &mut destination[..dst_len])
        };
        let ok: bool = kani::any();
        let mut called = false;
        let index = usize::from(kani::any::<u8>());
        kani::assume(index < MAX);
        let result = buffers.transact(&mut work[..work_len], 1, |input, scratch| {
            called = true;
            assert_eq!(input.len(), src_len);
            if index < src_len {
                assert_eq!(input[index], expected_input[index]);
            }
            // Arbitrary final scratch contents include partial writes on failure.
            scratch.copy_from_slice(&staged[..work_len]);
            if ok { Ok(3) } else { Err(2) }
        });
        let admitted = src_len == dst_len && dst_len == work_len;
        assert_eq!(called, admitted);
        assert_eq!(
            result,
            if !admitted {
                Err(1)
            } else if ok {
                Ok(3)
            } else {
                Err(2)
            }
        );
        assert_eq!(
            destination[index],
            if admitted && ok && index < dst_len {
                staged[index]
            } else {
                original[index]
            }
        );
    }

    #[kani::proof]
    fn separate_commit() {
        check(false);
    }

    #[kani::proof]
    fn in_place_commit() {
        check(true);
    }
}
