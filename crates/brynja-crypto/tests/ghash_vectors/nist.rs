//! NIST GCM worked examples, Encrypt-Generate fields A, CT, H and S.
//! Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
//! PDF SHA-256: 55e822592257799a4f895d6f3cb4c15515a065c008087105fc2063d2e757b5ef
//! Inputs below are already framed: A and CT each padded separately, then
//! their original bit lengths as two big-endian u64s. Expected S is copied
//! from the publication, not computed with Brynja. Examples 5 and 6 share
//! identical GHASH inputs and S; their different tag lengths are irrelevant.

use brynja_crypto::ghash::{Error, Ghash};

fn check(h: u128, cases: &[(&[u128], u128); 5]) -> Result<(), Error> {
    let h = h.to_be_bytes();
    for (index, (blocks, expected)) in cases.iter().enumerate() {
        let input: Vec<_> = blocks.iter().copied().flat_map(u128::to_be_bytes).collect();
        for split in 0..=input.len() {
            let (left, right) = input.split_at(split);
            let (mut work, mut out) = ([0xa5; 16], [0x5a; 16]);
            let mut hash = Ghash::new(&h, &mut work, input.len() as u64);
            hash.update(left)?;
            hash.update(right)?;
            let result = hash.finish(&mut out)?;
            assert_eq!(
                result.expose(),
                expected.to_be_bytes(),
                "case index {index}, split {split}"
            );
        }
    }
    Ok(())
}

#[test]
fn aes128_published_ghash_intermediates() -> Result<(), Error> {
    check(
        0xb83b533708bf535d0aa6e52980d53b78,
        &[
            // Example 1
            (
                &[0x00000000000000000000000000000000],
                0x00000000000000000000000000000000,
            ),
            // Example 2
            (
                &[
                    0x42831ec2217774244b7221b784d0d49c,
                    0xe3aa212f2c02a4e035c17e2329aca12e,
                    0x21d514b25466931c7d8f6a5aac84aa05,
                    0x1ba30b396a0aac973d58e091473f5985,
                    0x00000000000000000000000000000200,
                ],
                0x7f1b32b81b820d02614f8895ac1d4eac,
            ),
            // Example 3
            (
                &[
                    0x3ad77bb40d7a3660a89ecaf32466ef97,
                    0xf5d3d58503b9699de785895a96fdbaaf,
                    0x43b1cd7f598ece23881b00e3ed030688,
                    0x7b0c785e27e8ad3f8223207104725dd4,
                    0x00000000000002000000000000000000,
                ],
                0x6dd6cf3a1fa0371dd4c5c1ac1c3675f1,
            ),
            // Example 4
            (
                &[
                    0x3ad77bb40d7a3660a89ecaf32466ef97,
                    0xf5d3d58503b9699de785895a96fdbaaf,
                    0x43b1cd7f598ece23881b00e3ed030688,
                    0x7b0c785e27e8ad3f8223207104725dd4,
                    0x42831ec2217774244b7221b784d0d49c,
                    0xe3aa212f2c02a4e035c17e2329aca12e,
                    0x21d514b25466931c7d8f6a5aac84aa05,
                    0x1ba30b396a0aac973d58e091473f5985,
                    0x00000000000002000000000000000200,
                ],
                0x56873b6238e0502e16db1323d41eb655,
            ),
            // Example 5 and 6
            (
                &[
                    0x3ad77bb40d7a3660a89ecaf32466ef97,
                    0xf5d3d585000000000000000000000000,
                    0x42831ec2217774244b7221b784d0d49c,
                    0xe3aa212f2c02a4e035c17e2329aca12e,
                    0x21d514b25466931c7d8f6a5aac84aa05,
                    0x1ba30b396a0aac973d58e09100000000,
                    0x00000000000000a000000000000001e0,
                ],
                0xc23b3d63d2ed95056ca342769cd13c03,
            ),
        ],
    )
}

#[test]
fn aes192_published_ghash_intermediates() -> Result<(), Error> {
    check(
        0x466923ec9ae682214f2c082badb39249,
        &[
            // Example 1
            (
                &[0x00000000000000000000000000000000],
                0x00000000000000000000000000000000,
            ),
            // Example 2
            (
                &[
                    0x3980ca0b3c00e841eb06fac4872a2757,
                    0x859e1ceaa6efd984628593b40ca1e19c,
                    0x7d773d00c144c525ac619d18c84a3f47,
                    0x18e2448b2fe324d9ccda2710acade256,
                    0x00000000000000000000000000000200,
                ],
                0x51110d40f6c8fff0eb1ae33445a889f0,
            ),
            // Example 3
            (
                &[
                    0x3ad77bb40d7a3660a89ecaf32466ef97,
                    0xf5d3d58503b9699de785895a96fdbaaf,
                    0x43b1cd7f598ece23881b00e3ed030688,
                    0x7b0c785e27e8ad3f8223207104725dd4,
                    0x00000000000002000000000000000000,
                ],
                0xcaf9ddb367a23dae9feb243aee706f04,
            ),
            // Example 4
            (
                &[
                    0x3ad77bb40d7a3660a89ecaf32466ef97,
                    0xf5d3d58503b9699de785895a96fdbaaf,
                    0x43b1cd7f598ece23881b00e3ed030688,
                    0x7b0c785e27e8ad3f8223207104725dd4,
                    0x3980ca0b3c00e841eb06fac4872a2757,
                    0x859e1ceaa6efd984628593b40ca1e19c,
                    0x7d773d00c144c525ac619d18c84a3f47,
                    0x18e2448b2fe324d9ccda2710acade256,
                    0x00000000000002000000000000000200,
                ],
                0xf3a4f93c498a431061bc4d6972454d3f,
            ),
            // Example 5 and 6
            (
                &[
                    0x3ad77bb40d7a3660a89ecaf32466ef97,
                    0xf5d3d585000000000000000000000000,
                    0x3980ca0b3c00e841eb06fac4872a2757,
                    0x859e1ceaa6efd984628593b40ca1e19c,
                    0x7d773d00c144c525ac619d18c84a3f47,
                    0x18e2448b2fe324d9ccda271000000000,
                    0x00000000000000a000000000000001e0,
                ],
                0x5bdf824ef759a0df70824dabf5283f64,
            ),
        ],
    )
}

#[test]
fn aes256_published_ghash_intermediates() -> Result<(), Error> {
    check(
        0xacbef20579b4b8ebce889bac8732dad7,
        &[
            // Example 1
            (
                &[0x00000000000000000000000000000000],
                0x00000000000000000000000000000000,
            ),
            // Example 2
            (
                &[
                    0x522dc1f099567d07f47f37a32a84427d,
                    0x643a8cdcbfe5c0c97598a2bd2555d1aa,
                    0x8cb08e48590dbb3da7b08b1056828838,
                    0xc5f61e6393ba7a0abcc9f662898015ad,
                    0x00000000000000000000000000000200,
                ],
                0x4db870d37cb75fcb46097c36230d1612,
            ),
            // Example 3
            (
                &[
                    0x3ad77bb40d7a3660a89ecaf32466ef97,
                    0xf5d3d58503b9699de785895a96fdbaaf,
                    0x43b1cd7f598ece23881b00e3ed030688,
                    0x7b0c785e27e8ad3f8223207104725dd4,
                    0x00000000000002000000000000000000,
                ],
                0x23181cca714dcc8b14d0e2b4491f343a,
            ),
            // Example 4
            (
                &[
                    0x3ad77bb40d7a3660a89ecaf32466ef97,
                    0xf5d3d58503b9699de785895a96fdbaaf,
                    0x43b1cd7f598ece23881b00e3ed030688,
                    0x7b0c785e27e8ad3f8223207104725dd4,
                    0x522dc1f099567d07f47f37a32a84427d,
                    0x643a8cdcbfe5c0c97598a2bd2555d1aa,
                    0x8cb08e48590dbb3da7b08b1056828838,
                    0xc5f61e6393ba7a0abcc9f662898015ad,
                    0x00000000000002000000000000000200,
                ],
                0x3d41dce5bcb3d085d0d9ce2a878b741c,
            ),
            // Example 5 and 6
            (
                &[
                    0x3ad77bb40d7a3660a89ecaf32466ef97,
                    0xf5d3d585000000000000000000000000,
                    0x522dc1f099567d07f47f37a32a84427d,
                    0x643a8cdcbfe5c0c97598a2bd2555d1aa,
                    0x8cb08e48590dbb3da7b08b1056828838,
                    0xc5f61e6393ba7a0abcc9f66200000000,
                    0x00000000000000a000000000000001e0,
                ],
                0x1dbbb349e0b1f4fff5aa3bb1f6b2b0de,
            ),
        ],
    )
}
