use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::vec::Vec;

struct Host {
    words: [u64; 16],
    input: Vec<u8>,
    custom: Vec<u8>,
    copies: Vec<(Kind, usize, usize)>,
    fault: Option<(Kind, bool)>,
}
impl Host {
    fn new(bits: usize) -> Self {
        Self {
            words: [
                MAGIC,
                1,
                1,
                1,
                bits as u64,
                8,
                256,
                if bits == 0 { 0 } else { 0x10000 },
                0x2000,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            input: std::vec![0; bits.div_ceil(8)],
            custom: std::vec![0x69],
            copies: Vec::new(),
            fault: None,
        }
    }
}
impl CopyIn for Host {
    fn copy_into(&mut self, kind: Kind, address: usize, destination: &mut [u8]) -> bool {
        self.copies.push((kind, address, destination.len()));
        if let Some((fail_kind, unwind)) = self.fault
            && kind == fail_kind
        {
            let prefix = destination.len().div_ceil(2);
            destination[..prefix].fill(0xa5);
            assert!(!unwind, "injected partial-copy unwind");
            return false;
        }
        match kind {
            Kind::Header => {
                assert_eq!(address, 0x1000);
                assert_eq!(destination.len(), HEADER_BYTES);
                for (word, bytes) in self.words.iter().zip(destination.as_chunks_mut::<8>().0) {
                    bytes.copy_from_slice(&word.to_le_bytes());
                }
            }
            Kind::Custom => {
                assert_eq!(address, 0x2000);
                destination.copy_from_slice(&self.custom);
            }
            Kind::Wave => {
                let offset = address.checked_sub(0x10000).unwrap();
                destination.copy_from_slice(&self.input[offset..offset + destination.len()]);
            }
        }
        true
    }
}
fn cleared(frame: &InputFrame) {
    assert!(
        frame
            .header
            .iter()
            .chain(&frame.custom)
            .chain(&frame.wave)
            .all(|b| *b == 0)
    );
    assert!(frame.request.is_none());
    assert_eq!(frame.loaded_bits, 0);
    assert!(frame.phase == Phase::Dead);
}
#[test]
fn every_metadata_field_is_checked_before_payload_copy() {
    let mut mutations = std::vec![
        (0, 0),
        (1, 0),
        (1, 2),
        (2, 0),
        (2, 5),
        (3, 0),
        (3, 1025),
        (4, 65536 * 8 + 1),
        (5, 8193),
        (6, 8193),
        (7, 0),
        (7, u64::MAX),
        (8, 0),
        (8, u64::MAX),
        (9, 0),
        (9, 2)
    ];
    mutations.extend((10..16).map(|i| (i, 1)));
    for (index, value) in mutations {
        let mut host = Host::new(72);
        host.words[index] = value;
        let mut frame = InputFrame::new();
        assert!(
            frame.begin(0x1000, &mut host).is_err(),
            "word {index}={value}"
        );
        assert_eq!(host.copies, [(Kind::Header, 0x1000, HEADER_BYTES)]);
        cleared(&frame);
    }
    for address in [0, usize::MAX - HEADER_BYTES + 1] {
        let mut host = Host::new(8);
        let mut frame = InputFrame::new();
        assert!(frame.begin(address, &mut host).is_err());
        assert!(host.copies.is_empty());
        cleared(&frame);
    }
    for index in [4, 5] {
        let mut host = Host::new(8);
        host.words[index] = 0; // Empty input requires a null source, not a dangling address.
        let mut frame = InputFrame::new();
        assert!(frame.begin(0x1000, &mut host).is_err());
        assert_eq!(host.copies.len(), 1);
        cleared(&frame);
    }
}
#[test]
fn partial_copy_failure_and_unwind_clear_all_regions_and_are_terminal() {
    for kind in [Kind::Header, Kind::Custom, Kind::Wave] {
        for unwind in [false, true] {
            let mut host = Host::new(72);
            let mut frame = InputFrame::new();
            if kind == Kind::Wave {
                frame.begin(0x1000, &mut host).unwrap();
            }
            host.fault = Some((kind, unwind));
            let result = catch_unwind(AssertUnwindSafe(|| {
                if kind == Kind::Wave {
                    frame.next_wave(&mut host).map(|_| ())
                } else {
                    frame.begin(0x1000, &mut host).map(|_| ())
                }
            }));
            if unwind {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), Err(Error::Copy));
            }
            cleared(&frame);
            host.fault = None;
            assert!(frame.begin(0x1000, &mut host).is_err());
            assert!(frame.next_wave(&mut host).is_err());
            assert!(frame.custom().is_err());
            assert!(frame.finish().is_err());
            cleared(&frame);
        }
    }
}
#[test]
fn copied_header_is_stable_offsets_are_exact_and_old_wave_tail_is_cleared() {
    let mut host = Host::new(67);
    host.input = std::vec![0x5a; 9];
    host.input[8] = 3;
    let mut frame = InputFrame::new();
    frame.begin(0x1000, &mut host).unwrap();
    host.words.fill(u64::MAX); // A hostile second header is never read.
    for (offset, bits, length) in [(0, 32, 4), (4, 32, 4), (8, 3, 1)] {
        let chunk = frame.next_wave(&mut host).unwrap();
        assert_eq!(
            (chunk.offset(), chunk.bit_len(), chunk.bytes().len()),
            (offset, bits, length)
        );
        assert_eq!(chunk.bytes(), &host.input[offset..offset + length]);
        assert!(frame.wave[length..].iter().all(|b| *b == 0));
    }
    assert_eq!(
        host.copies,
        [
            (Kind::Header, 0x1000, 128),
            (Kind::Custom, 0x2000, 1),
            (Kind::Wave, 0x10000, 4),
            (Kind::Wave, 0x10004, 4),
            (Kind::Wave, 0x10008, 1)
        ]
    );
    frame.finish().unwrap();
    cleared(&frame);
}
#[test]
fn noncanonical_custom_and_message_tails_reject_without_masking() {
    for custom in [false, true] {
        for tail in 1..8 {
            let mut host = Host::new(tail);
            let mut frame = InputFrame::new();
            if custom {
                host.words[5] = tail as u64;
                host.custom[0] = 1 << tail;
                assert!(matches!(frame.begin(0x1000, &mut host), Err(Error::Bits)));
            } else {
                host.input[0] = 1 << tail;
                frame.begin(0x1000, &mut host).unwrap();
                assert!(matches!(frame.next_wave(&mut host), Err(Error::Bits)));
            }
            cleared(&frame);
        }
    }
}
#[test]
fn incomplete_replayed_exhausted_and_cancelled_frames_are_terminal() {
    for mode in 0..5 {
        let mut host = Host::new(32);
        let mut frame = InputFrame::new();
        frame.begin(0x1000, &mut host).unwrap();
        match mode {
            0 => assert!(frame.finish().is_err()),
            1 => assert!(frame.begin(0x1000, &mut host).is_err()),
            2 => {
                frame.next_wave(&mut host).unwrap();
                assert!(frame.next_wave(&mut host).is_err());
            }
            3 => frame.cancel(),
            _ => {
                frame.next_wave(&mut host).unwrap();
                frame.cancel();
            }
        }
        cleared(&frame);
    }
    let mut host = Host::new(0);
    host.words[5] = 0;
    host.words[8] = 0;
    let mut frame = InputFrame::new();
    frame.begin(0x1000, &mut host).unwrap();
    assert!(frame.custom().is_ok());
    assert_eq!(host.copies.len(), 1);
    frame.finish().unwrap();
    cleared(&frame);
}
#[test]
fn maximum_metadata_is_bounded_without_allocating_the_message() {
    let mut host = Host::new(0);
    host.words[3] = 1024;
    host.words[4] = 1024 * 8 * 65536;
    host.words[7] = 0x10000;
    host.words[5] = 8192;
    host.words[6] = 8192;
    host.custom = std::vec![0xa5; 1024];
    let mut frame = InputFrame::new();
    frame.begin(0x1000, &mut host).unwrap();
    assert_eq!(host.copies.len(), 2);
    frame.cancel();
    cleared(&frame);
}
fn decode(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn copied_ingress_independent_oracle_reverse_and_scoped_workers() {
    use brynja_crypto_cpu::static_execution::{Authority, Kernel};
    let mut cases = 0;
    for line in include_str!("parallel-waves-vectors.txt").lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        for threaded in [false, true] {
            let input_bits: usize = fields[4].parse().unwrap();
            let mut host = Host::new(input_bits);
            host.words[2] = fields[1].parse().unwrap();
            host.words[3] = fields[2].parse().unwrap();
            host.words[5] = fields[3].parse().unwrap();
            if host.words[5] == 0 {
                host.words[8] = 0;
            }
            host.input = decode(fields[7]);
            host.custom = decode(fields[6]);
            let expected = decode(fields[8]);
            host.words[6] = if expected.is_empty() {
                0
            } else {
                ((expected.len() - 1) * 8 + fields[5].parse::<usize>().unwrap()) as u64
            };
            let mut frame = InputFrame::new();
            let request = frame.begin(0x1000, &mut host).unwrap();
            let authority = Authority::new(Kernel::X86Keccak).unwrap();
            let mut root = parallel_waves::Waves::new(
                &authority,
                request.identity,
                request.block,
                request.input_bits,
                frame.custom().unwrap(),
                request.output_bits,
            )
            .unwrap();
            let mut loaded = 0;
            while loaded < input_bits {
                let chunk = frame.next_wave(&mut host).unwrap();
                root.wave(|offset, plan, slots| {
                    assert_eq!(offset, chunk.offset());
                    if threaded {
                        std::thread::scope(|scope| {
                            for (lane, slot) in slots.iter_mut().enumerate() {
                                let count = plan.leaf_bits(lane).unwrap();
                                let start = lane * request.block;
                                let part = &chunk.bytes()[start..start + count.div_ceil(8)];
                                scope.spawn(move || {
                                    let worker = Authority::new(Kernel::X86Keccak).unwrap();
                                    slot.run(&worker, Bits::new(part, last(count)).unwrap())
                                        .unwrap();
                                });
                            }
                        });
                    } else {
                        for (lane, slot) in slots.iter_mut().enumerate().rev() {
                            let count = plan.leaf_bits(lane).unwrap();
                            let start = lane * request.block;
                            let worker = Authority::new(Kernel::X86Keccak).unwrap();
                            slot.run(
                                &worker,
                                Bits::new(
                                    &chunk.bytes()[start..start + count.div_ceil(8)],
                                    last(count),
                                )
                                .unwrap(),
                            )
                            .unwrap();
                        }
                    }
                    Ok(())
                })
                .unwrap();
                loaded += chunk.bit_len();
            }
            frame.finish().unwrap();
            cleared(&frame);
            root.finish().unwrap();
            let mut output = std::vec![0xa5; expected.len()];
            root.declassify_to(&mut output).unwrap();
            assert_eq!(output, expected);
        }
        cases += 1;
    }
    assert_eq!(cases, 532);
    std::println!("COPIED_INGRESS_ORACLE: {cases} cases x two scheduling orders");
}
