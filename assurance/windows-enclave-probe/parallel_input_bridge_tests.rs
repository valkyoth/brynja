// Appended to the existing process-only wave tests by the private builder.
// This fake copy implementation does not establish OS/enclave protection.
static INPUT_ID: AtomicUsize = AtomicUsize::new(0);
mod expected {
    include!("parallel_wave_expected.rs");
}

#[unsafe(no_mangle)]
unsafe extern "C" fn PrivateInputCopy(
    kind: usize,
    address: usize,
    destination: *mut u8,
    length: usize,
) -> usize {
    // SAFETY: private adapter supplies its exclusive, live destination slice.
    let output = unsafe { core::slice::from_raw_parts_mut(destination, length) };
    match kind {
        0 => {
            assert_eq!(length, 128);
            assert!((1..=4).contains(&address));
            INPUT_ID.store(address, Ordering::Relaxed);
            let words = [
                parallel_input::MAGIC,
                1,
                address as u64,
                32,
                2307,
                0,
                512,
                0x10000,
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
            ];
            for (word, bytes) in words.iter().zip(output.as_chunks_mut::<8>().0) {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
        }
        2 => {
            let offset = address.checked_sub(0x10000).unwrap();
            assert!(offset + length <= 289);
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = ((offset + index) % 256) as u8;
            }
            if offset + length == 289 {
                output[length - 1] &= 7;
            }
        }
        _ => panic!("unexpected fake-copy kind"),
    }
    1
}
#[unsafe(no_mangle)]
unsafe extern "C" fn PrivateInputOutput(source: *const u8, length: usize) -> usize {
    assert_eq!(length, 64);
    let identity = INPUT_ID.load(Ordering::Relaxed);
    // SAFETY: private adapter supplies a live bounded public-output slice.
    usize::from(
        unsafe { core::slice::from_raw_parts(source, length) } == expected::EXPECTED[identity - 1],
    )
}
