//! NIST AES_GCM.pdf, Encrypt-Generate example 3 for each key width.
//! Fixed, public AAD-only test vectors, not a seal/open or nonce API.
use brynja_crypto::{aes, ghash::Ghash};

struct Example {
    h: u128,
    s: u128,
    mask: u128,
    tag: u128,
}

const KEY_PREFIX: [u8; 16] = 0xfeffe9928665731c6d6a8f9467308308u128.to_be_bytes();
const J0: [u8; 16] = 0xcafebabefacedbaddecaf88800000001u128.to_be_bytes();
// Four AAD blocks followed by the NIST length block (512 AAD bits, 0 CT bits).
const FRAMED: [u128; 5] = [
    0x3ad77bb40d7a3660a89ecaf32466ef97,
    0xf5d3d58503b9699de785895a96fdbaaf,
    0x43b1cd7f598ece23881b00e3ed030688,
    0x7b0c785e27e8ad3f8223207104725dd4,
    512u128 << 64,
];

fn check(
    ex: &Example,
    encrypt: impl for<'a> Fn(&[u8; 16], &'a mut [u8; 16]) -> Result<aes::SecretBlock<'a>, aes::Error>,
) -> Result<(), &'static str> {
    let (mut h_storage, mut mask_storage) = ([0xa5; 16], [0x5a; 16]);
    let h = encrypt(&[0; 16], &mut h_storage).map_err(|_| "AES subkey derivation failed")?;
    let mask = encrypt(&J0, &mut mask_storage).map_err(|_| "AES mask derivation failed")?;
    assert!(h.expose() == ex.h.to_be_bytes(), "subkey mismatch");
    assert!(mask.expose() == ex.mask.to_be_bytes(), "mask mismatch");

    let key = h
        .expose()
        .try_into()
        .map_err(|_| "wrong AES output width")?;
    let (mut work, mut out) = ([0xa5; 16], [0x5a; 16]);
    let mut hash = Ghash::new(key, &mut work, 80);
    // Retain the clearing owner while GHASH borrows the derived bytes.
    let frames = FRAMED.map(u128::to_be_bytes);
    for chunk in frames.as_flattened().chunks(13) {
        hash.update(chunk)
            .map_err(|_| "forced GHASH update failed")?;
    }
    assert_eq!(
        hash.native_blocks()
            .map_err(|_| "native route unavailable")?,
        5
    );
    let sum = hash.finish(&mut out).map_err(|_| "GHASH finish failed")?;
    assert!(
        sum.expose() == ex.s.to_be_bytes(),
        "GHASH intermediate mismatch"
    );
    assert!(
        sum.expose()
            .iter()
            .zip(mask.expose())
            .zip(ex.tag.to_be_bytes())
            .all(|((&a, &b), tag)| a ^ b == tag),
        "masked result mismatch"
    );
    sum.clear();
    h.clear();
    mask.clear();
    assert_eq!(
        (work, out, h_storage, mask_storage),
        ([0; 16], [0; 16], [0; 16], [0; 16])
    );
    Ok(())
}

macro_rules! pairing {
    ($name:ident, $plain:ident, $cached:ident, $bytes:ident, $schedule:ident, $example:expr) => {
        #[test]
        fn $name() -> Result<(), &'static str> {
            let mut input = [0; aes::$bytes];
            for (dst, byte) in input.iter_mut().zip(KEY_PREFIX.iter().cycle()) {
                *dst = *byte;
            }
            let ex = $example;
            let mut storage = [0xa5; aes::$bytes];
            let owner =
                aes::$plain::new(&input, &mut storage).map_err(|_| "scalar key init failed")?;
            check(&ex, |block, out| owner.encrypt_block(block, out))?;
            owner.clear();
            assert_eq!(storage, [0; aes::$bytes]);
            let mut schedule = [0x5a; aes::$schedule];
            let cached =
                aes::$cached::new(&input, &mut schedule).map_err(|_| "cached key init failed")?;
            check(&ex, |block, out| cached.encrypt_block(block, out))?;
            cached.clear();
            assert_eq!(schedule, [0; aes::$schedule]);
            Ok(())
        }
    };
}

pairing!(
    aes128,
    Aes128Key,
    Aes128ExpandedKey,
    KEY_BYTES,
    EXPANDED_KEY_BYTES,
    Example {
        h: 0xb83b533708bf535d0aa6e52980d53b78,
        s: 0x6dd6cf3a1fa0371dd4c5c1ac1c3675f1,
        mask: 0x3247184b3c4f69a44dbcd22887bbb418,
        tag: 0x5f91d77123ef5eb9997913849b8dc1e9,
    }
);
pairing!(
    aes192,
    Aes192Key,
    Aes192ExpandedKey,
    AES192_KEY_BYTES,
    AES192_EXPANDED_KEY_BYTES,
    Example {
        h: 0x466923ec9ae682214f2c082badb39249,
        s: 0xcaf9ddb367a23dae9feb243aee706f04,
        mask: 0xc835aa88aebbc94f5a02e179fdcfc3e4,
        tag: 0x02cc773bc919f4e1c5e9c54313bface0,
    }
);
pairing!(
    aes256,
    Aes256Key,
    Aes256ExpandedKey,
    AES256_KEY_BYTES,
    AES256_EXPANDED_KEY_BYTES,
    Example {
        h: 0xacbef20579b4b8ebce889bac8732dad7,
        s: 0x23181cca714dcc8b14d0e2b4491f343a,
        mask: 0xfd2caa16a5832e76aa132c1453eeda7e,
        tag: 0xde34b6dcd4cee2fdbec3cea01af1ee44,
    }
);

#[cfg(all(brynja_cpu_evidence, target_arch = "x86_64"))]
#[test]
fn emulated_cpu_has_pclmul_but_no_aes() {
    assert!(std::is_x86_feature_detected!("pclmulqdq"));
    assert!(!std::is_x86_feature_detected!("aes"));
    assert!(!std::is_x86_feature_detected!("vaes"));
}
