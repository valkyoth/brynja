extern crate std;
use super::{Probe, actual::transpose as probe};

const CASES: [(usize, bool, Probe); 3] = [
    (8, true, probe::<8, true>),
    (16, true, probe::<16, true>),
    (8, false, probe::<8, false>),
];

// Returns only the register that can contain a secret word (RAX or X4).
// All other working registers contain public counters and are checked in asm.
unsafe fn capture(function: Probe, out: *mut u8, input: *const u8, width: usize, swap: u32) -> u64 {
    let mut snapshot = 0_u64;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Exact SysV C arguments and live disjoint buffers from the caller.
    // R12/R13 are preserved; volatile clobbers and the call's stack use declared.
    unsafe {
        core::arch::asm!(
            "mov rax, -1", "call r13", "mov [r12], rax",
            in("r13") function, in("r12") &mut snapshot,
            in("rdi") out, in("rsi") input, in("rdx") width, in("ecx") swap,
            clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Exact AAPCS64 C call; X20/21 preserved and volatile/LR clobbers
    // declared. Snapshot immediately follows return, without intervening Rust.
    unsafe {
        core::arch::asm!(
            "mov x4, #-1", "blr x21", "str x4, [x20]",
            in("x21") function, in("x20") &mut snapshot,
            in("x0") out, in("x1") input, in("x2") width, in("w3") swap,
            clobber_abi("C"),
        );
    }
    snapshot
}

fn reference(out: &mut [u8], input: &[u8], words: usize, pack: bool, width: usize, swap: u32) {
    for lane in 0..width {
        for word in 0..words {
            let packed = word * 32 + lane * 8;
            let ordinary = (lane * words + word) * 8;
            let (src, dst) = if pack {
                (ordinary, packed)
            } else {
                (packed, ordinary)
            };
            for byte in 0..8 {
                out[dst + byte] = input[src + if swap == 0 { byte } else { 7 - byte }];
            }
        }
    }
}

#[test]
fn transposition_bounds_and_register_cleanup() {
    let mut seed = 0x6a09_e667_f3bc_c908_u64;
    let mut cases = 0;
    for (words, pack, function) in CASES {
        for width in 0..=4 {
            for swap in [0, 1, u32::MAX] {
                for offset in 0..32 {
                    let mut source = [0_u8; 576];
                    for byte in &mut source {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        *byte = seed.to_le_bytes()[0];
                    }
                    let before = source;
                    let mut destination = [0xa5; 576];
                    let mut expected = destination;
                    let length = words * 32;
                    let start = 16 + offset;
                    reference(
                        &mut expected[start..start + length],
                        &source[start..start + length],
                        words,
                        pack,
                        width,
                        swap,
                    );
                    // SAFETY: Both views cover the exact required length and
                    // remain distinct/live, including intentionally unaligned cases.
                    let residue = unsafe {
                        capture(
                            function,
                            destination[start..].as_mut_ptr(),
                            source[start..].as_ptr(),
                            width,
                            swap,
                        )
                    };
                    assert_eq!(residue, 0, "secret-bearing working register not cleared");
                    assert_eq!(
                        destination, expected,
                        "transpose/endianness/sentinel mismatch"
                    );
                    assert_eq!(source, before, "source mutated");
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 1440);
    std::println!("SHA512_TRANSFER: 1440 layouts; register cleanup and canaries: PASS");
}

#[path = "../../src/guard_memory.rs"]
mod guard_pages;

#[test]
fn guarded_transfers() -> std::io::Result<()> {
    for (words, pack, function) in CASES {
        for source_end in [false, true] {
            for destination_end in [false, true] {
                let length = words * 32;
                let mut source = guard_pages::Pages::new()?;
                let mut destination = guard_pages::Pages::new()?;
                source.bytes::<512>(source_end).fill(0x7b);
                destination.bytes::<512>(destination_end).fill(0xa5);
                let src = if words == 8 {
                    source.read::<256>(source_end).as_slice()
                } else {
                    source.read::<512>(source_end).as_slice()
                };
                let mut expected = [0xa5; 512];
                reference(&mut expected[..length], src, words, pack, 4, 1);
                source.readonly()?;
                let src = if words == 8 {
                    source.read::<256>(source_end).as_ptr()
                } else {
                    source.read::<512>(source_end).as_ptr()
                };
                let dst = if words == 8 {
                    destination.bytes::<256>(destination_end).as_mut_ptr()
                } else {
                    destination.bytes::<512>(destination_end).as_mut_ptr()
                };
                // SAFETY: Exactly sized, disjoint live page views; width=4.
                assert_eq!(unsafe { capture(function, dst, src, 4, 1,) }, 0);
                let result = if words == 8 {
                    destination.read::<256>(destination_end).as_slice()
                } else {
                    destination.read::<512>(destination_end).as_slice()
                };
                assert_eq!(result, &expected[..length]);
            }
        }
    }
    std::println!("SHA512_TRANSFER_BOUNDS: 12 guarded placements; readonly input: PASS");
    Ok(())
}
