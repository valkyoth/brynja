//! Deliberately invalid, test-only sanitizer controls. Never a library dependency.
//! Each mode must fail under its sanitizer before AES tests may be accepted.
fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("bounds") => {
            let bytes = vec![0x42u8; std::hint::black_box(16)];
            let offset = std::hint::black_box(bytes.len());
            // Intentional heap-buffer-overflow; ASan must diagnose this read.
            let value = unsafe { bytes.as_ptr().add(offset).read_volatile() };
            std::hint::black_box(value);
        }
        Some("leak") => {
            // Exit the allocating thread so conservative scanning of its live
            // stack cannot keep the intentionally leaked allocation reachable.
            std::thread::spawn(|| {
                let bytes = Box::new([0x42u8; 64]);
                std::hint::black_box(&*bytes);
                std::mem::forget(bytes);
            })
            .join()
            .expect("sanitizer control thread");
        }
        _ => panic!("expected bounds or leak control"),
    }
}
