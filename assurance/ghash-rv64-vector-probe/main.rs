//! Standalone QEMU capability test. Not part of a Brynja crate or a dispatch path.
use std::arch::global_asm;

global_asm!(include_str!("probe.S"));

unsafe extern "C" {
    fn probe_capabilities() -> i32;
    fn probe_vlenb() -> usize;
    fn probe_zvkg(h: *const u32, x: *const u32, len: *const u32, out: *mut u32) -> usize;
    fn probe_zvbc(x: *const u64, y: *const u64, out: *mut u64) -> usize;
}

// Little-endian memory holds each 16-byte block in GHASH wire order.
fn words(block: u128) -> [u32; 4] {
    let bytes = block.to_be_bytes();
    std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}

fn main() {
    let model = std::env::args().nth(1).expect("expected emulator model");
    let expected = match model.as_str() {
        // (V, scalar Zbc, vector Zvkg, vector Zvbc)
        "scalar" => (false, true, false, false),
        "vector" => (true, false, false, false),
        "zvkg" => (true, false, true, false),
        "zvbc" => (true, false, false, true),
        "both" => (true, false, true, true),
        _ => panic!("unknown emulator model"),
    };
    // SAFETY: no caller pointers or preconditions; negative means unavailable.
    let bits = unsafe { probe_capabilities() };
    assert!((0..16).contains(&bits), "extension query unavailable");
    let got = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0);
    assert_eq!(got, expected);
    let width: usize = std::env::args().nth(2).unwrap().parse().unwrap();
    if got.0 {
        // SAFETY: base V detected in this controlled guest; no memory access.
        assert_eq!(unsafe { probe_vlenb() } * 8, width);
    } else {
        assert_eq!(width, 0);
    }
    if got.2 {
        let h = words(0x66e94bd4ef8a2c3b884cfa59ca342b2e);
        let x = words(0x0388dace60b6a392f328c2b971b2fe78);
        let len = words(128);
        let mut out = [0_u32; 8];
        // SAFETY: Zvkg and V were detected. Arrays are aligned and live;
        // assembly checks VL=4 before accessing one group at a time.
        assert_eq!(
            unsafe { probe_zvkg(h.as_ptr(), x.as_ptr(), len.as_ptr(), out.as_mut_ptr()) },
            4
        );
        assert_eq!(out[..4], words(0x5e2ec746917062882c85b0685353deb7));
        assert_eq!(out[4..], words(0xf38cbb1ad69223dcc3457ae5b6b0f885));
    }
    if got.3 {
        let mut out = [0_u64; 2];
        // SAFETY: Zvbc and V were detected. One aligned u64 per operand;
        // assembly checks VL=1 and stores one low and one high half.
        assert_eq!(
            unsafe { probe_zvbc(&0x8000_0000_0000_0003, &3, out.as_mut_ptr()) },
            1
        );
        assert_eq!(out, [0x8000_0000_0000_0005, 1]);
    }
    println!("vector probe passed: {model}");
}
