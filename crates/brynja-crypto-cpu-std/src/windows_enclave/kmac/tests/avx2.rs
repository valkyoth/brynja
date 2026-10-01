use super::super::super::{kmac_avx2_wire as wire, kmac_wire};
use super::*;

#[cfg(all(
    feature = "strict-kmac-acceleration",
    not(all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc",
        not(miri),
        not(kani)
    ))
))]
#[test]
fn unsupported_avx2_constructor_never_selects_ordinary_execution() {
    static POLICY: ImagePolicy =
        ImagePolicy::reviewed_sha256([1; 32], [1; 16], [2; 16], 1, 1, [0, 0]);
    assert!(matches!(
        Session::open_avx2(Path::new("unused.dll"), &POLICY),
        Err(Error::Unsupported)
    ));
}

#[test]
fn avx2_wire_identity_and_full_header_receipts_are_distinct() -> Result<(), Error> {
    assert_eq!(wire::PROTOCOL, 0x42524b32);
    let request = Request {
        op: 45,
        sequence: 2,
        last: 8,
        ..Request::default()
    };
    let ordinary = request.header(b"abc")?;
    let accelerated = wire::header(request, b"abc")?;
    assert_eq!(ordinary.get(..8), Some(8_u64.to_le_bytes().as_slice()));
    assert_eq!(accelerated.get(..8), Some(15_u64.to_le_bytes().as_slice()));
    assert_eq!(accelerated.get(8..96), ordinary.get(8..96));
    assert_eq!(
        accelerated.get(96..104),
        Some(1_u64.to_le_bytes().as_slice())
    );
    assert_eq!(accelerated.get(104..112), Some([0; 8].as_slice()));
    for request in [
        Request {
            op: 40,
            sequence: 1,
            algorithm: 9,
            ..Request::default()
        },
        Request {
            op: 40,
            sequence: 1,
            algorithm: 0,
            ..Request::default()
        },
        Request {
            op: 47,
            sequence: 1,
            width: 1,
            ..Request::default()
        },
        Request {
            op: 47,
            sequence: 1,
            last: 8,
            ..Request::default()
        },
    ] {
        assert_eq!(wire::header(request, &[]), Err(Error::Bounds));
    }
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
    let low = 0x10000;
    let overlap = [low + 64, low + 160, 1, 1, 1, 0, 0];
    kmac_wire::receipt(low, 45, 3, overlap)?;
    assert_eq!(wire::receipt(low, 45, 3, overlap), Err(Error::Protocol));
    let valid = [low + 64, low + 512, 1, 1, 1, 0, 0];
    wire::receipt(low, 45, 3, valid)?;
    for index in 0..7 {
        let mut bad = valid;
        *bad.get_mut(index).ok_or(Error::Bounds)? = if index >= 5 { 1 } else { 0 };
        assert_eq!(wire::receipt(low, 45, 3, bad), Err(Error::Protocol));
    }
    wire::receipt(low, 0, 0, [0; 7])?;
    wire::receipt(low, 3, 0, [0; 7])?;
    assert_eq!(wire::receipt(low, 3, 0, valid), Err(Error::Protocol));
    Ok(())
}
