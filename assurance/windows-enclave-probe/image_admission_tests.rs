//! Synthetic parser tests: certificate bytes are deliberately NOT real signatures.
mod image_admission;
use image_admission::{Policy, admit, inspect, prepare_windows_imports};
fn put16(b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}
fn fixture() -> Vec<u8> {
    let mut b = vec![0; 4624];
    b[..2].copy_from_slice(b"MZ");
    put32(&mut b, 60, 128);
    b[128..132].copy_from_slice(b"PE\0\0");
    put16(&mut b, 132, 0x8664);
    put16(&mut b, 134, 1);
    put16(&mut b, 148, 240);
    put16(&mut b, 150, 0x2022);
    let o = 152;
    put16(&mut b, o, 0x20b);
    put64(&mut b, o + 24, 0x180000000);
    put32(&mut b, o + 56, 8192);
    put32(&mut b, o + 60, 512);
    put16(&mut b, o + 70, 0x41e0);
    put32(&mut b, o + 108, 16);
    for (i, rva, size) in [(1, 4352, 60), (4, 4608, 16), (10, 4608, 320)] {
        put32(&mut b, o + 112 + 8 * i, rva);
        put32(&mut b, o + 116 + 8 * i, size);
    }
    let s = o + 240;
    b[s..s + 6].copy_from_slice(b".rdata");
    put32(&mut b, s + 8, 4096);
    put32(&mut b, s + 12, 4096);
    put32(&mut b, s + 16, 4096);
    put32(&mut b, s + 20, 512);
    put32(&mut b, s + 36, 0x40000040);
    for (i, name, lookup) in [(0, 5504, 5632), (1, 5536, 5696)] {
        let t = 768 + 20 * i;
        put32(&mut b, t, lookup);
        put32(&mut b, t + 12, name);
        put32(&mut b, t + 16, lookup);
        put64(&mut b, (lookup - 4096 + 512) as usize, 5792);
        let t = 1664 + 80 * i;
        put32(&mut b, t, 2);
        put32(&mut b, t + 72, name);
    }
    b[1920..1941].copy_from_slice(b"ucrtbase_enclave.dll\0");
    b[1952..1964].copy_from_slice(b"vertdll.dll\0");
    b[2210..2222].copy_from_slice(b"CallEnclave\0");
    put32(&mut b, 1024, 320);
    put64(&mut b, 1024 + 248, 0x180001400);
    let c = 1536;
    for (offset, value) in [
        (0, 80),
        (4, 76),
        (12, 2),
        (16, 5248),
        (20, 80),
        (56, 1),
        (60, 1),
        (72, 1),
        (76, 1),
    ] {
        put32(&mut b, c + offset, value);
    }
    b[c + 24] = 0x42;
    b[c + 40] = 0x50;
    put64(&mut b, c + 64, 0x10000000);
    put32(&mut b, 4608, 16);
    put16(&mut b, 4612, 0x200);
    put16(&mut b, 4614, 2);
    b
}
fn policy(b: &[u8]) -> Policy {
    Policy {
        identity: inspect(b).unwrap(),
        digest: *brynja_hash_sha2::sha256(b).unwrap().as_bytes(),
    }
}
#[test]
fn reviewed_identity_and_whole_file_are_both_required() {
    let b = fixture();
    let mut p = policy(&b);
    assert_eq!(admit(&b, &p), Ok(()));
    for i in 0..b.len() {
        let mut changed = b.clone();
        changed[i] ^= 1;
        assert!(admit(&changed, &p).is_err(), "unbound byte {i}");
    }
    p.identity.version += 1;
    assert!(admit(&b, &p).is_err());
    p = policy(&b);
    p.identity.minimum_import_security[0] = 1;
    assert!(admit(&b, &p).is_err());
    p = policy(&b);
    p.identity.family[0] ^= 1;
    assert!(admit(&b, &p).is_err());
}
#[test]
fn malformed_images_reject_without_panics() {
    let b = fixture();
    for n in 0..b.len() {
        assert!(inspect(&b[..n]).is_err(), "truncation {n}");
    }
    for (offset, value) in [
        (60, u32::MAX),
        (134, 0),
        (148, 0),
        (152 + 70, 0),
        (152 + 108, 17),
        (152 + 56, 0),
        (152 + 60, 0),
        (392 + 12, 0),
        (392 + 16, u32::MAX),
        (392 + 20, 0),
        (392 + 36, 0xa0000000),
        (152 + 112 + 8, 0),
        (152 + 116 + 8, 40),
        (768 + 4, 1),
        (768 + 8, 1),
        (768 + 12, 0),
        (768 + 20 + 12, 5504),
        (768 + 40, 1),
        (768, 0),
        (768 + 16, 0),
        (2048, u32::MAX),
        (2210, 0),
        (1024, 263),
        (1024 + 248, 0),
        (1536, 79),
        (1536 + 4, 81),
        (1536 + 8, 1),
        (1536 + 12, 1),
        (1536 + 16, u32::MAX),
        (1536 + 20, 79),
        (1536 + 56, 0),
        (1536 + 60, 0),
        (1536 + 64, 0),
        (1536 + 72, 2),
        (1536 + 76, 0),
        (1664, 0),
        (1664, 4),
        (1664 + 8, 1),
        (1664 + 40, 1),
        (1664 + 56, 1),
        (1664 + 76, 1),
        (1744 + 72, 5504),
        (152 + 144, 4609),
        (152 + 148, 8),
        (4608, 7),
        (4612, 0),
    ] {
        let mut bad = b.clone();
        put32(&mut bad, offset, value);
        assert!(
            inspect(&bad).is_err(),
            "accepted offset {offset} value {value}"
        );
    }
    for index in [9, 11, 13, 14] {
        let mut bad = b.clone();
        put32(&mut bad, 152 + 112 + 8 * index, 4096);
        assert!(inspect(&bad).is_err());
    }
    // Deterministic malformed offsets, bounded loops, no candidate execution.
    let mut seed = 0x3955e714u32;
    for _ in 0..4096 {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        let mut bad = b.clone();
        let offset = (seed as usize) % (b.len() - 4);
        put32(&mut bad, offset, seed);
        let _ = inspect(&bad);
    }
}
#[test]
fn signer_independent_import_ids_are_not_windows_authority() {
    let mut b = fixture();
    put32(&mut b, 1664, 4);
    b[1664 + 56] = 1;
    assert!(inspect(&b).is_err());
    let length = prepare_windows_imports(&mut b).unwrap();
    assert_eq!(length, 4608);
    assert_eq!(&b[152 + 144..152 + 152], &[0; 8]);
    assert!(inspect(&b[..length]).is_err()); // Unsigned intermediate is never admitted.
    put32(&mut b, 152 + 144, 4608);
    put32(&mut b, 152 + 148, 16);
    assert!(inspect(&b).is_ok()); // Structural only; this fixture is not a signature.
    b[1920] = b'X';
    assert!(prepare_windows_imports(&mut b).is_err());
}
#[test]
fn duplicate_or_overlapping_sections_reject() {
    let mut b = fixture();
    put16(&mut b, 134, 2);
    let section = b[392..432].to_vec();
    b[432..472].copy_from_slice(&section);
    assert!(inspect(&b).is_err());
    put32(&mut b, 432 + 12, 8192);
    put32(&mut b, 152 + 56, 12288);
    assert!(inspect(&b).is_err()); // Distinct virtual ranges, same file bytes.
}
