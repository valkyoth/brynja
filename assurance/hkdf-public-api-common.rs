//! Public synthetic vector support shared by the two independent consumers.
//! No allocation, std, secret-bearing errors or production-private access.

/// Value-free consumer acceptance failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// A public API returned an unexpected error.
    Api,
    /// An acceptance condition failed; no input/output bytes are disclosed.
    Contract,
}

pub fn require(condition: bool) -> Result<(), Failure> {
    if condition {
        Ok(())
    } else {
        Err(Failure::Contract)
    }
}

pub fn matches_hex(bytes: &[u8], expected: &str) -> bool {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes.len() * 2 == expected.len()
        && bytes
            .iter()
            .zip(expected.as_bytes().as_chunks::<2>().0.iter())
            .all(|(byte, pair)| {
                DIGITS[usize::from(byte >> 4)] == pair[0]
                    && DIGITS[usize::from(byte & 15)] == pair[1]
            })
}

pub const fn sequence<const N: usize>(start: u8) -> [u8; N] {
    let mut result = [0; N];
    let mut i = 0;
    while i < N {
        result[i] = start.wrapping_add(i as u8);
        i += 1;
    }
    result
}

/// Partition boundaries include both SHA-2 HMAC block widths; no heap needed.
pub fn multipart_cases(
    width: usize,
    mut compare: impl FnMut(&[u8], &[&[u8]], usize) -> Result<(), Failure>,
) -> Result<(), Failure> {
    let info = sequence::<129>(0);
    for split in 0..=info.len() {
        compare(
            &info,
            &[&[], &info[..split], &[], &info[split..], &[]],
            width + 1,
        )?;
    }
    for n in [0, 1, width - 1, width, width + 1] {
        compare(&[], &[], n)?;
        compare(&[], &[&[], &[], &[]], n)?;
        compare(b"abc", &[b"a", b"bc"], n)?;
        compare(b"abc", &[b"ab", b"c"], n)?;
        compare(b"bca", &[b"bc", b"a"], n)?;
        compare(b"ababc", &[b"ab", b"ab", b"c"], n)?;
    }
    let bytes: [&[u8]; 129] = core::array::from_fn(|i| &info[i..i + 1]);
    compare(&info, &bytes, width + 1)
}

pub struct Vector {
    pub salt: Option<&'static [u8]>,
    pub ikm: &'static [u8],
    pub info: &'static [u8],
    pub prk: &'static str,
    pub okm: &'static str,
}

// RFC 5869 Appendix A, cases 1–7. Fixed-size storage only.
#[allow(dead_code)] // Each separate consumer selects only its admitted family.
pub const SHA256: [Vector; 3] = [
    Vector {
        salt: Some(&sequence::<13>(0)),
        ikm: &[0x0b; 22],
        info: &sequence::<10>(0xf0),
        prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    },
    Vector {
        salt: Some(&sequence::<80>(0x60)),
        ikm: &sequence::<80>(0),
        info: &sequence::<80>(0xb0),
        prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    },
    Vector {
        salt: Some(&[]),
        ikm: &[0x0b; 22],
        info: &[],
        prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    },
];

#[allow(dead_code)] // Each separate consumer selects only its admitted family.
pub const SHA1: [Vector; 4] = [
    Vector {
        salt: Some(&sequence::<13>(0)),
        ikm: &[0x0b; 11],
        info: &sequence::<10>(0xf0),
        prk: "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
        okm: "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
    },
    Vector {
        salt: Some(&sequence::<80>(0x60)),
        ikm: &sequence::<80>(0),
        info: &sequence::<80>(0xb0),
        prk: "8adae09a2a307059478d309b26c4115a224cfaf6",
        okm: "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
    },
    Vector {
        salt: Some(&[]),
        ikm: &[0x0b; 22],
        info: &[],
        prk: "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
        okm: "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
    },
    Vector {
        salt: None,
        ikm: &[0x0c; 22],
        info: &[],
        prk: "2adccada18779e7c2077ad2eb19d3f3e731385dd",
        okm: "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
    },
];
