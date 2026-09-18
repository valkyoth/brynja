extern crate std;
use super::{Probe, actual::transpose as probe};

const CASES: [(bool, Probe); 2] = [(true, probe::<true>), (false, probe::<false>)];

// Observe the sole secret-bearing register immediately at the actual C return.
unsafe fn capture(function: Probe, out: *mut u8, input: *const u8, width: usize) -> u64 {
    let mut snapshot = 0_u64;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Exact SysV arguments and live disjoint buffers supplied by caller.
    // R12/R13 are preserved; volatile clobbers and stack use are declared.
    unsafe {
        core::arch::asm!(
            "mov rax, -1", "call r13", "mov [r12], rax",
            in("r13") function, in("r12") &mut snapshot,
            in("rdi") out, in("rsi") input, in("rdx") width,
            clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Exact AAPCS64 arguments; X20/21 preserved and volatile/LR clobbers
    // declared. No Rust executes between the kernel return and snapshot.
    unsafe {
        core::arch::asm!(
            "mov x4, #-1", "blr x21", "str x4, [x20]",
            in("x21") function, in("x20") &mut snapshot,
            in("x0") out, in("x1") input, in("x2") width,
            clobber_abi("C"),
        );
    }
    snapshot
}

fn reference(out: &mut [u8], input: &[u8], pack: bool, width: usize) {
    for lane in 0..width {
        for word in 0..25 {
            let packed = word * 32 + lane * 8;
            let ordinary = lane * 200 + word * 8;
            let (src, dst) = if pack {
                (ordinary, packed)
            } else {
                (packed, ordinary)
            };
            out[dst..dst + 8].copy_from_slice(&input[src..src + 8]);
        }
    }
}

#[test]
fn transposition_bounds_and_register_cleanup() {
    let mut seed = 0x6a09_e667_f3bc_c908_u64;
    let mut cases = 0;
    for (pack, function) in CASES {
        for width in 0..=4 {
            for offset in 0..32 {
                let mut source = [0_u8; 864];
                for byte in &mut source {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    *byte = seed.to_le_bytes()[0];
                }
                let before = source;
                let mut destination = [0xa5; 864];
                let mut expected = destination;
                let start = 16 + offset;
                reference(
                    &mut expected[start..start + 800],
                    &source[start..start + 800],
                    pack,
                    width,
                );
                // SAFETY: Disjoint 800-byte views cover the complete layouts,
                // including intentional unaligned offsets, with width <= 4.
                let residue = unsafe {
                    capture(
                        function,
                        destination[start..].as_mut_ptr(),
                        source[start..].as_ptr(),
                        width,
                    )
                };
                assert_eq!(residue, 0, "secret-bearing working register not cleared");
                assert_eq!(destination, expected, "mapping or canary mismatch");
                assert_eq!(source, before, "source mutated");
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 320);
    std::println!("KECCAK_TRANSFER: 320 layouts; register cleanup and canaries: PASS");
}

#[path = "../../src/guard_memory.rs"]
mod guard_pages;

#[test]
fn guarded_transfers() -> std::io::Result<()> {
    for (pack, function) in CASES {
        for source_end in [false, true] {
            for destination_end in [false, true] {
                let mut source = guard_pages::Pages::new()?;
                let mut destination = guard_pages::Pages::new()?;
                for (i, byte) in source.bytes::<800>(source_end).iter_mut().enumerate() {
                    *byte = i.to_le_bytes()[0];
                }
                destination.bytes::<800>(destination_end).fill(0xa5);
                let mut expected = [0xa5; 800];
                reference(&mut expected, source.read::<800>(source_end), pack, 4);
                source.readonly()?;
                let src = source.read::<800>(source_end).as_ptr();
                let dst = destination.bytes::<800>(destination_end).as_mut_ptr();
                // SAFETY: Exact disjoint page views, readonly source, width=4.
                assert_eq!(unsafe { capture(function, dst, src, 4) }, 0);
                assert_eq!(*destination.read::<800>(destination_end), expected);
            }
        }
    }
    std::println!("KECCAK_TRANSFER_BOUNDS: 8 guarded placements; readonly input: PASS");
    Ok(())
}
