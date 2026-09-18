extern crate std;
use super::{Probe, actual::transpose as probe};

const CASES: [(usize, bool, usize, usize, Probe); 4] = [
    (4, true, 16, 128, probe::<4, true>),
    (16, true, 64, 512, probe::<16, true>),
    (4, false, 128, 16, probe::<4, false>),
    (32, true, 128, 128, probe::<32, true>),
];

unsafe fn capture(function: Probe, out: *mut u8, input: *const u8, lane: usize) -> u64 {
    let mut snapshot = 0_u64;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Exact SysV arguments and live disjoint buffers from the caller.
    // R12/R13 are preserved; volatile clobbers and stack use declared.
    unsafe {
        core::arch::asm!(
            "mov rax, -1", "call r13", "mov [r12], rax",
            in("r13") function, in("r12") &mut snapshot,
            in("rdi") out, in("rsi") input, in("rdx") lane,
            clobber_abi("C"),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Exact AAPCS64 arguments. X20/21 preserved; volatile/LR clobbers
    // declared. Capture the sole secret-bearing register immediately on return.
    unsafe {
        core::arch::asm!(
            "mov x4, #-1", "blr x21", "str x4, [x20]",
            in("x21") function, in("x20") &mut snapshot,
            in("x0") out, in("x1") input, in("x2") lane,
            clobber_abi("C"),
        );
    }
    snapshot
}

fn reference(out: &mut [u8], input: &[u8], words: usize, pack: bool, lane: usize) {
    for word in 0..words {
        let (src, dst) = if words == 32 {
            (word * 4, word * 4)
        } else if pack {
            (word * 4, word * 32 + lane * 4)
        } else {
            (word * 32 + lane * 4, word * 4)
        };
        out[dst..dst + 4].copy_from_slice(&input[src..src + 4]);
    }
}

#[test]
fn mappings_and_return_registers() {
    let mut seed = 0x6a09_e667_f3bc_c908_u64;
    let mut count = 0;
    for (words, pack, src_len, dst_len, function) in CASES {
        for lane in 0..if words == 32 { 1 } else { 8 } {
            for offset in 0..32 {
                let mut source = [0_u8; 576];
                for byte in &mut source {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    *byte = seed.to_le_bytes()[0];
                }
                let before = source;
                let mut output = [0xa5; 576];
                let mut expected = output;
                let start = 16 + offset;
                reference(
                    &mut expected[start..start + dst_len],
                    &source[start..start + src_len],
                    words,
                    pack,
                    lane,
                );
                // SAFETY: Disjoint exact live layouts, lane < 8 (zero for copy).
                let residue = unsafe {
                    capture(
                        function,
                        output[start..].as_mut_ptr(),
                        source[start..].as_ptr(),
                        lane,
                    )
                };
                assert_eq!(residue, 0, "transfer retained a secret register");
                assert_eq!(output, expected, "mapping/canary mismatch");
                assert_eq!(source, before, "input changed");
                count += 1;
            }
        }
    }
    assert_eq!(count, 800);
    std::println!("MD5_TRANSFER: 800 layouts; register cleanup and canaries: PASS");
}

#[path = "../../src/guard_memory.rs"]
mod guard_pages;

fn address(page: &mut guard_pages::Pages, length: usize, end: bool) -> *mut u8 {
    match length {
        16 => page.bytes::<16>(end).as_mut_ptr(),
        64 => page.bytes::<64>(end).as_mut_ptr(),
        128 => page.bytes::<128>(end).as_mut_ptr(),
        512 => page.bytes::<512>(end).as_mut_ptr(),
        _ => panic!("unsupported guarded layout"),
    }
}
fn view(page: &guard_pages::Pages, length: usize, end: bool) -> &[u8] {
    match length {
        16 => page.read::<16>(end),
        64 => page.read::<64>(end),
        128 => page.read::<128>(end),
        512 => page.read::<512>(end),
        _ => panic!("unsupported guarded layout"),
    }
}

#[test]
fn guarded_transfers() -> std::io::Result<()> {
    let mut count = 0;
    for (words, pack, src_len, dst_len, function) in CASES {
        for lane in (0..if words == 32 { 1 } else { 8 }).step_by(7) {
            for src_end in [false, true] {
                for dst_end in [false, true] {
                    let mut source = guard_pages::Pages::new()?;
                    let mut output = guard_pages::Pages::new()?;
                    for (i, byte) in source.bytes::<512>(src_end).iter_mut().enumerate() {
                        *byte = i.to_le_bytes()[0];
                    }
                    output.bytes::<512>(dst_end).fill(0xa5);
                    let mut expected = [0xa5; 512];
                    reference(
                        &mut expected[..dst_len],
                        view(&source, src_len, src_end),
                        words,
                        pack,
                        lane,
                    );
                    let src = view(&source, src_len, src_end).as_ptr();
                    let dst = address(&mut output, dst_len, dst_end);
                    source.readonly()?;
                    // SAFETY: Exact live disjoint layouts, source readonly;
                    // lane=0/7 (only zero for the fixed 128-byte copy).
                    assert_eq!(unsafe { capture(function, dst, src, lane) }, 0);
                    assert_eq!(view(&output, dst_len, dst_end), &expected[..dst_len]);
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 28);
    std::println!("MD5_TRANSFER_BOUNDS: 28 guarded placements; readonly input: PASS");
    Ok(())
}
