use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn shape(identity: u64, width: usize, last: u8) -> Slot {
    Slot {
        identity,
        width,
        last,
    }
}
fn plan(slot: Slot) -> [Slot; 8] {
    let mut result = [Slot::default(); 8];
    result[0] = slot;
    result
}
fn clean(o: &Owner) {
    assert_eq!(o.output, [0; 1024]);
    assert!(matches!(o.state, State::Empty));
    assert_eq!(o.plan, [Slot::default(); 8]);
    assert_eq!(o.active, None);
    assert_eq!(o.completed, 0);
    assert_eq!(o.remaining, 0);
}
fn failed(o: &Owner) {
    clean(o);
    assert_eq!(o.phase, Phase::Quarantined);
}
fn tick(n: &mut u64) -> u64 {
    *n += 1;
    *n
}
fn retained() -> Owner {
    let mut o = Owner::new();
    o.begin(1, plan(shape(2, 32, 8)), 3).unwrap();
    o.start(2, 0, 0, 0).unwrap();
    o.finish_setup(3, 0).unwrap();
    o.finish(4, 0, b"abc", 8).unwrap();
    o.seal(5).unwrap();
    assert!(o.output.iter().any(|b| *b != 0));
    o
}
fn decode(hex: &str) -> std::vec::Vec<u8> {
    if hex == "-" {
        return std::vec![];
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn last(bits: usize) -> u8 {
    if bits == 0 {
        0
    } else {
        ((bits - 1) % 8 + 1) as u8
    }
}
fn setup(o: &mut Owner, n: &mut u64, slot: usize, name: bool, bytes: &[u8], bits: usize) {
    // Repack in irregular *bit* chunks, not merely byte-aligned fragments.
    let mut position = 0;
    while position < bits {
        let length = (bits - position).min(37);
        let mut chunk = [0_u8; 5];
        for i in 0..length {
            chunk[i / 8] |= ((bytes[(position + i) / 8] >> ((position + i) % 8)) & 1) << (i % 8);
        }
        o.setup_chunk(tick(n), slot, name, &[], 0).unwrap();
        o.setup_chunk(
            tick(n),
            slot,
            name,
            &chunk[..length.div_ceil(8)],
            last(length),
        )
        .unwrap();
        position += length;
    }
    o.setup_chunk(tick(n), slot, name, &[], 0).unwrap();
}
#[test]
fn independent_oracles_cover_framing_rates_and_bit_shapes() {
    for row in include_str!("sha3-batch-oracle.txt").lines() {
        let fields: std::vec::Vec<_> = row.split_whitespace().collect();
        let id: u64 = fields[0].parse().unwrap();
        let nb: usize = fields[1].parse().unwrap();
        let sb: usize = fields[3].parse().unwrap();
        let mb: usize = fields[5].parse().unwrap();
        let ob: usize = fields[7].parse().unwrap();
        let (name, custom, message, expected) = (
            decode(fields[2]),
            decode(fields[4]),
            decode(fields[6]),
            decode(fields[8]),
        );
        let p = plan(shape(id, ob.div_ceil(8), last(ob)));
        let mut o = Owner::new();
        let mut n = 1;
        o.begin(n, p, u64::MAX).unwrap();
        o.start(tick(&mut n), 0, nb as u128, sb as u128).unwrap();
        if id >= 7 {
            setup(&mut o, &mut n, 0, true, &name, nb);
            setup(&mut o, &mut n, 0, false, &custom, sb);
        }
        o.finish_setup(tick(&mut n), 0).unwrap();
        let split = message.len().saturating_sub(1);
        for chunk in message[..split].chunks(113) {
            o.update(tick(&mut n), 0, &[]).unwrap();
            o.update(tick(&mut n), 0, chunk).unwrap();
        }
        o.finish(tick(&mut n), 0, &message[split..], last(mb))
            .unwrap();
        o.seal(tick(&mut n)).unwrap();
        o.export(tick(&mut n), p, |out| {
            assert_eq!(&out[..expected.len()], expected, "{row}");
            assert!(out[expected.len()..].iter().all(|b| *b == 0));
            true
        })
        .unwrap();
        clean(&o);
    }
}
#[test]
fn mixed_slots_every_activity_mask_preserve_packed_offsets() {
    for mask in 1_u16..=255 {
        let shapes = [
            shape(1, 28, 8),
            shape(2, 32, 8),
            shape(3, 48, 8),
            shape(4, 64, 8),
            shape(5, 169, 3),
            shape(6, 137, 7),
            shape(7, 0, 0),
            shape(8, 136, 8),
        ];
        let p = core::array::from_fn(|i| {
            if mask & (1 << i) != 0 {
                shapes[i]
            } else {
                Slot::default()
            }
        });
        let mut o = Owner::new();
        o.begin(1, p, 24).unwrap();
        let mut n = 1;
        let mut expected = [0_u8; 1024];
        let mut offset = 0;
        for (i, s) in p.iter().enumerate() {
            if s.identity == 0 {
                continue;
            }
            o.start(tick(&mut n), i, 0, 0).unwrap();
            o.finish_setup(tick(&mut n), i).unwrap();
            let input = [i as u8; 3];
            o.finish(tick(&mut n), i, &input, 8).unwrap();
            let empty = Fips202BitString::new(&[], 0).unwrap();
            let mut reference =
                State::new(Algorithm::decode(s.identity).unwrap(), empty, empty).unwrap();
            let bits = Fips202BitString::new(&input, 8).unwrap();
            let destination = &mut expected[offset..offset + s.width];
            if s.identity <= 4 {
                reference.finish_fixed(bits, destination).unwrap();
            } else {
                reference.finish_xof(bits).unwrap();
                reference.squeeze(destination, s.last, true).unwrap();
            }
            offset += s.width;
        }
        o.seal(tick(&mut n)).unwrap();
        o.export(tick(&mut n), p, |bytes| {
            assert_eq!(bytes, &expected);
            true
        })
        .unwrap();
        clean(&o);
    }
}
#[test]
fn malformed_plans_and_exact_output_capacity() {
    for s in [
        shape(0, 1, 8),
        shape(0, 0, 1),
        shape(9, 32, 8),
        shape(u64::MAX, 0, 0),
        shape(1, 32, 8),
        shape(2, 32, 7),
        shape(5, 1025, 8),
        shape(5, 1, 9),
        shape(6, 1, 0),
        shape(7, 0, 8),
    ] {
        assert!(s.validate().is_err());
        let mut o = Owner::new();
        assert!(o.begin(1, plan(s), 0).is_err());
        failed(&o);
    }
    let mut o = Owner::new();
    assert!(o.begin(1, [Slot::default(); 8], 0).is_err());
    failed(&o);
    let mut o = Owner::new();
    assert!(o.begin(1, [shape(5, 129, 8); 8], 0).is_err());
    failed(&o);
    for p in [
        plan(shape(5, 1024, 8)),
        [shape(6, 128, 8); 8],
        plan(shape(7, 0, 0)),
    ] {
        let mut o = Owner::new();
        o.begin(1, p, 0).unwrap();
        o.cancel(2).unwrap();
        clean(&o);
    }
}
#[test]
fn ordering_phase_sequence_and_export_identity_fail_closed() {
    for wrong in [1, 7, 8, usize::MAX] {
        let mut o = Owner::new();
        o.begin(1, [shape(2, 32, 8); 8], 0).unwrap();
        assert!(o.start(2, wrong, 0, 0).is_err());
        failed(&o);
    }
    let mut o = Owner::new();
    o.begin(1, [shape(2, 32, 8); 8], 0).unwrap();
    o.start(2, 0, 0, 0).unwrap();
    o.finish_setup(3, 0).unwrap();
    o.finish(4, 0, &[], 0).unwrap();
    assert!(o.start(5, 0, 0, 0).is_err());
    failed(&o);
    let mut o = Owner::new();
    o.begin(1, [shape(2, 32, 8); 8], 0).unwrap();
    assert!(o.seal(2).is_err());
    failed(&o);
    let mut o = Owner::new();
    o.begin(1, plan(shape(2, 32, 8)), 0).unwrap();
    o.start(2, 0, 0, 0).unwrap();
    assert!(o.update(3, 0, &[]).is_err());
    failed(&o);
    for sequence in [0, 1, 5, 7, u64::MAX] {
        let mut o = retained();
        assert!(o.cancel(sequence).is_err());
        failed(&o);
    }
    let mut o = retained();
    o.sequence = u64::MAX;
    assert!(o.cancel(0).is_err());
    failed(&o);
    let mut o = retained();
    assert!(
        o.export(6, plan(shape(5, 32, 8)), |_| panic!(
            "wrong identity exported"
        ))
        .is_err()
    );
    failed(&o);
}
#[test]
fn budgets_slots_setup_and_canonical_bits_fail_closed() {
    for budget in 0..3 {
        let mut o = Owner::new();
        o.begin(1, plan(shape(2, 32, 8)), budget).unwrap();
        o.start(2, 0, 0, 0).unwrap();
        o.finish_setup(3, 0).unwrap();
        assert!(o.finish(4, 0, b"abc", 8).is_err());
        failed(&o);
    }
    for slot in [1, 8, usize::MAX] {
        let mut o = Owner::new();
        o.begin(1, plan(shape(2, 32, 8)), 99).unwrap();
        o.start(2, 0, 0, 0).unwrap();
        o.finish_setup(3, 0).unwrap();
        assert!(o.update(4, slot, b"abc").is_err());
        failed(&o);
    }
    for finishing in [false, true] {
        let mut o = Owner::new();
        o.begin(1, plan(shape(2, 32, 8)), 9999).unwrap();
        o.start(2, 0, 0, 0).unwrap();
        o.finish_setup(3, 0).unwrap();
        let result = if finishing {
            o.finish(4, 0, &[0; 1025], 8)
        } else {
            o.update(4, 0, &[0; 1025])
        };
        assert!(result.is_err());
        failed(&o);
    }
    for (input, last) in [(&[128][..], 1), (&[][..], 8), (&[0][..], 0)] {
        let mut o = Owner::new();
        o.begin(1, plan(shape(2, 32, 8)), 1).unwrap();
        o.start(2, 0, 0, 0).unwrap();
        o.finish_setup(3, 0).unwrap();
        assert!(o.finish(4, 0, input, last).is_err());
        failed(&o);
    }
    let mut o = Owner::new();
    o.begin(1, plan(shape(2, 32, 8)), 0).unwrap();
    assert!(o.start(2, 0, 1, 0).is_err());
    failed(&o);
    let mut o = Owner::new();
    o.begin(1, plan(shape(5, 32, 8)), 0).unwrap();
    o.start(2, 0, 0, 0).unwrap();
    assert!(o.setup_chunk(3, 0, true, &[], 0).is_err());
    failed(&o);
    for mode in 0..5 {
        let mut o = Owner::new();
        o.begin(1, plan(shape(7, 32, 8)), if mode == 4 { 0 } else { 9999 })
            .unwrap();
        o.start(2, 0, 1, 1).unwrap();
        let result = match mode {
            0 => o.finish_setup(3, 0),
            1 => o.setup_chunk(3, 0, false, &[1], 1),
            2 => o.setup_chunk(3, 0, true, &[0; 1025], 8),
            3 => o.setup_chunk(3, 0, true, &[128], 1),
            _ => o.setup_chunk(3, 0, true, &[1], 1),
        };
        assert!(result.is_err());
        failed(&o);
    }
}
#[test]
fn cancellation_copy_failure_and_unwind_clear_retained_state() {
    let mut o = retained();
    assert_eq!(
        o.export(6, plan(shape(2, 32, 8)), |_| false),
        Err(Error::Copy)
    );
    failed(&o);
    let mut o = retained();
    assert!(
        catch_unwind(AssertUnwindSafe(|| o.export(
            6,
            plan(shape(2, 32, 8)),
            |_| panic!("copy seam")
        )))
        .is_err()
    );
    failed(&o);
    let mut o = retained();
    o.cancel(6).unwrap();
    clean(&o);
    o.begin(7, plan(shape(2, 32, 8)), 0).unwrap();
    o.cancel(8).unwrap();
    clean(&o);
    for stage in 0..4 {
        let mut o = Owner::new();
        let mut n = 1;
        o.begin(n, plan(shape(7, 32, 8)), 100).unwrap();
        if stage >= 1 {
            o.start(tick(&mut n), 0, 3, 0).unwrap();
        }
        if stage >= 2 {
            o.setup_chunk(tick(&mut n), 0, true, &[3], 3).unwrap();
        }
        if stage >= 3 {
            o.finish_setup(tick(&mut n), 0).unwrap();
            o.update(tick(&mut n), 0, b"secret").unwrap();
        }
        o.cancel(tick(&mut n)).unwrap();
        clean(&o);
        assert_eq!(o.phase, Phase::Empty);
    }
    let mut o = retained();
    o.quarantine();
    assert!(o.begin(6, plan(shape(2, 32, 8)), 0).is_err());
    failed(&o);
}
