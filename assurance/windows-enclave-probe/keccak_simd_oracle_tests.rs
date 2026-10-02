use super::*;
fn decode(text: &str) -> std::vec::Vec<u8> {
    if text == "-" {
        return std::vec![];
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn algorithm(code: usize) -> Algorithm {
    [
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Shake128,
        Algorithm::Shake256,
        Algorithm::Cshake128,
        Algorithm::Cshake256,
    ][code - 1]
}
fn bitstring(bytes: &[u8], bits: usize) -> Fips202BitString<'_> {
    assert_eq!(bytes.len(), bits.div_ceil(8));
    Fips202BitString::new(
        bytes,
        if bits == 0 {
            0
        } else {
            (1 + (bits - 1) % 8) as u8
        },
    )
    .unwrap()
}
#[test]
fn independent_oracles_all_identities_and_lane_isolation() {
    let rows: std::vec::Vec<_> = include_str!("keccak-simd-vectors.txt").lines().collect();
    assert_eq!(rows.len() % 4, 0);
    assert!(rows.len() >= 2000);
    for rows in rows.chunks_exact(4) {
        let fields: std::vec::Vec<std::vec::Vec<_>> = rows
            .iter()
            .map(|row| row.split_whitespace().collect())
            .collect();
        let mut messages = std::vec![];
        let mut names = std::vec![];
        let mut labels = std::vec![];
        let mut expected = [0; 1024];
        let plan: [Slot; 4] = core::array::from_fn(|i| {
            let f = &fields[i];
            assert_eq!(f.len(), 9);
            messages.push(decode(f[2]));
            names.push(decode(f[4]));
            labels.push(decode(f[6]));
            let answer = decode(f[8]);
            expected[i * 256..i * 256 + answer.len()].copy_from_slice(&answer);
            Slot {
                identity: algorithm(f[0].parse().unwrap()),
                output_bits: f[7].parse().unwrap(),
            }
        });
        let lanes = core::array::from_fn(|i| Lane {
            slot: plan[i],
            message: bitstring(&messages[i], fields[i][1].parse().unwrap()),
            name: bitstring(&names[i], fields[i][3].parse().unwrap()),
            custom: bitstring(&labels[i], fields[i][5].parse().unwrap()),
        });
        let a = Authority::for_compiled_target(Kernel::Avx2).unwrap();
        let mut owner = Owner::new(&a).unwrap();
        let report = owner.digest(1, lanes, 1000).unwrap();
        assert_eq!(report.kernel, Some(Kernel::Avx2));
        assert!(report.vector_calls > 0);
        assert_eq!(report.accelerated_slots, 15);
        owner
            .export_public(2, plan, |out| {
                assert_eq!(out, &expected, "plan={plan:?}");
                true
            })
            .unwrap();
        assert!(owner.output.iter().all(|b| *b == 0));
        assert_eq!(owner.plan, None);
    }
}
