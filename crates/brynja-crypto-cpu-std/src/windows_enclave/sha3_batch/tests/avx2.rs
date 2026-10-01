use super::super::super::{sha3_batch_avx2_wire as wire, sha3_batch_receipt};
use super::*;

#[cfg(all(
    feature = "strict-sha3-acceleration",
    not(all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    ))
))]
#[test]
fn unsupported_avx2_constructor_never_selects_scalar_execution() {
    static POLICY: ImagePolicy =
        ImagePolicy::reviewed_sha256([1; 32], [1; 16], [2; 16], 1, 1, [0, 0]);
    assert!(matches!(
        Session::open_avx2(Path::new("unused.dll"), &POLICY),
        Err(Error::Unsupported)
    ));
}

#[test]
fn avx2_batch_wire_identity_and_complete_header_receipt() -> Result<(), Error> {
    assert_eq!(wire::PROTOCOL, 0x42524233);
    let request = Request {
        op: 95,
        sequence: 2,
        last: 8,
        ..Request::default()
    };
    let scalar = request.header(b"abc")?;
    let accelerated = wire::header(request, b"abc")?;
    assert_eq!(scalar.get(..8), Some(11_u64.to_le_bytes().as_slice()));
    assert_eq!(accelerated.get(..8), Some(17_u64.to_le_bytes().as_slice()));
    assert_eq!(accelerated.get(8..288), scalar.get(8..288));
    assert_eq!(
        accelerated.get(288..296),
        Some(1_u64.to_le_bytes().as_slice())
    );
    assert_eq!(accelerated.get(296..304), Some([0; 8].as_slice()));
    assert_eq!(
        wire::header(
            Request {
                sequence: 0,
                ..request
            },
            b"abc"
        ),
        Err(Error::Bounds)
    );
    assert_eq!(wire::header(request, &[0; 1025]), Err(Error::Bounds));
    assert_eq!(
        wire::header(
            Request {
                op: 90,
                sequence: 1,
                ..Request::default()
            },
            &[]
        ),
        Err(Error::Bounds)
    );
    let low = 0x10000;
    // Exactly disjoint for the old header but overlapping the larger new one.
    let overlap = [low + 64, low + 352, 1, 1, 1, 0, 0];
    sha3_batch_receipt::receipt(low, 95, 3, overlap)?;
    assert_eq!(wire::receipt(low, 95, 3, overlap), Err(Error::Protocol));
    for op in 90..=99 {
        let length = usize::from(matches!(op, 92 | 93 | 95 | 96));
        let valid = [low + 64, low + 512, 1, 1, length, usize::from(op == 98), 0];
        wire::receipt(low, op, length, valid)?;
        for index in 0..7 {
            let mut bad = valid;
            let value = bad.get_mut(index).ok_or(Error::Bounds)?;
            *value = if index < 2 {
                0
            } else {
                value.checked_add(1).ok_or(Error::Bounds)?
            };
            assert_eq!(wire::receipt(low, op, length, bad), Err(Error::Protocol));
        }
        assert_eq!(
            wire::receipt(usize::MAX, op, length, valid),
            Err(Error::Protocol)
        );
    }
    for op in [0, 3] {
        wire::receipt(low, op, 0, [0; 7])?;
        assert_eq!(wire::receipt(low, op, 0, [1; 7]), Err(Error::Protocol));
    }
    Ok(())
}
