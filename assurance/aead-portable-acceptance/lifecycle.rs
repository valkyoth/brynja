use gmac_consumer::crypto::{aes_gcm::Aes256Gcm, gmac::Aes256Gmac};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn scope_exit_before_first_use_clears_both_schedules() {
    let (mut gcm, mut gmac) = ([0xa5; 240], [0xa5; 240]);
    {
        let _receiver = Aes256Gcm::<16>::for_open(&[1; 32], &mut gcm).unwrap();
        let _verifier = Aes256Gmac::<16>::for_verify(&[2; 32], &mut gmac).unwrap();
    }
    assert_eq!(gcm, [0; 240]);
    assert_eq!(gmac, [0; 240]);
}

#[test]
fn caller_unwind_drops_both_live_owners() {
    let (mut gcm, mut gmac) = ([0xa5; 240], [0xa5; 240]);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _receiver = Aes256Gcm::<16>::for_open(&[1; 32], &mut gcm).unwrap();
        let _verifier = Aes256Gmac::<16>::for_verify(&[2; 32], &mut gmac).unwrap();
        std::panic::panic_any(123u8);
    }));
    assert_eq!(result.unwrap_err().downcast_ref::<u8>(), Some(&123));
    assert_eq!(gcm, [0; 240]);
    assert_eq!(gmac, [0; 240]);
}
