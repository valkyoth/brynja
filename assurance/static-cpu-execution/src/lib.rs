#![no_std]
//! Downstream static-kernel acceptance; no evidence cfg or private imports.

use brynja_crypto_cpu::static_execution::{Authority, Error, Health, Kernel, PublicData};

/// Execute direct known vectors and permanent revocation using public APIs.
pub fn exercise() -> Result<usize, Error> {
    let mut executed = 0;
    for kernel in Kernel::ALL {
        if kernel.check_compiled_target().is_err() {
            continue;
        }
        let owner = Authority::new(kernel)?;
        assert_eq!(owner.report().health, Health::Healthy);
        let first = owner.session()?;
        let sibling = owner.session()?;
        match kernel {
            Kernel::X86Sha256 | Kernel::ArmSha256 => {
                let mut state = [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ];
                let mut block = [0; 64];
                block[0] = b'a';
                block[1] = b'b';
                block[2] = b'c';
                block[3] = 0x80;
                block[63] = 24;
                first.compress_sha256(PublicData::new(&mut state), PublicData::new(&block))?;
                assert_eq!(
                    state,
                    [
                        0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c,
                        0xb410ff61, 0xf20015ad
                    ]
                );
            }
            Kernel::ArmSha512 => {
                let mut state = [
                    0x6a09e667f3bcc908,
                    0xbb67ae8584caa73b,
                    0x3c6ef372fe94f82b,
                    0xa54ff53a5f1d36f1,
                    0x510e527fade682d1,
                    0x9b05688c2b3e6c1f,
                    0x1f83d9abfb41bd6b,
                    0x5be0cd19137e2179,
                ];
                let mut block = [0; 128];
                block[0] = b'a';
                block[1] = b'b';
                block[2] = b'c';
                block[3] = 0x80;
                block[127] = 24;
                first.compress_sha512(PublicData::new(&mut state), PublicData::new(&block))?;
                assert_eq!(
                    state,
                    [
                        0xddaf35a193617aba,
                        0xcc417349ae204131,
                        0x12e6fa4e89a97ea2,
                        0x0a9eeee64b55d39a,
                        0x2192992a274fc1a8,
                        0x36ba3c23a3feebbd,
                        0x454d4423643ce80e,
                        0x2a9ac94fa54ca49f
                    ]
                );
            }
            Kernel::X86Keccak | Kernel::ArmKeccak => {
                let mut lanes = [0; 25];
                first.permute_keccak(PublicData::new(&mut lanes))?;
                assert_eq!(
                    lanes,
                    [
                        0xf1258f7940e1dde7,
                        0x84d5ccf933c0478a,
                        0xd598261ea65aa9ee,
                        0xbd1547306f80494d,
                        0x8b284e056253d057,
                        0xff97a42d7f8e6fd4,
                        0x90fee5a0a44647c4,
                        0x8c5bda0cd6192e76,
                        0xad30a6f71b19059c,
                        0x30935ab7d08ffc64,
                        0xeb5aa93f2317d635,
                        0xa9a6e6260d712103,
                        0x81a57c16dbcf555f,
                        0x43b831cd0347c826,
                        0x01f22f1a11a5569f,
                        0x05e5635a21d9ae61,
                        0x64befef28cc970f2,
                        0x613670957bc46611,
                        0xb87c5a554fd00ecb,
                        0x8c3ee88a1ccf32c8,
                        0x940c7922ae3a2614,
                        0x1841f924a2c509e4,
                        0x16f53526e70465c2,
                        0x75f644e97f30a13b,
                        0xeaf1ff7b5ceca249
                    ]
                );
            }
            _ => return Err(Error::WrongOperation),
        }
        owner.quarantine();
        assert_eq!(owner.session().err(), Some(Error::Quarantined));
        for session in [first, sibling] {
            let mut small = [42; 8];
            let mut large = [42; 8];
            let mut lanes = [42; 25];
            assert_eq!(
                session.compress_sha256(PublicData::new(&mut small), PublicData::new(&[0; 64])),
                Err(Error::Quarantined)
            );
            assert_eq!(
                session.compress_sha512(PublicData::new(&mut large), PublicData::new(&[0; 128])),
                Err(Error::Quarantined)
            );
            assert_eq!(
                session.permute_keccak(PublicData::new(&mut lanes)),
                Err(Error::Quarantined)
            );
            assert_eq!(small, [42; 8]);
            assert_eq!(large, [42; 8]);
            assert_eq!(lanes, [42; 25]);
        }
        executed += 1;
    }
    Ok(executed)
}

#[test]
fn public_static_execution_matches_exact_compiled_coverage() -> Result<(), Error> {
    let expected = usize::from(cfg!(all(
        target_arch = "x86_64",
        target_feature = "sha",
        target_feature = "sse2"
    ))) + usize::from(cfg!(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        target_feature = "avx"
    ))) + usize::from(cfg!(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha2"
    ))) + 2 * usize::from(cfg!(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "sha3"
    )));
    assert_eq!(exercise()?, expected);
    Ok(())
}
