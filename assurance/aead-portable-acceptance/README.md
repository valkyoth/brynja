# Portable AES-GCM and GMAC archive acceptance

From the repository root run `python3 scripts/aes-gcm/check-portable-acceptance.py`.
This offline command needs Go, both supported Rust endpoints and their
`thumbv7em-none-eabi` targets. It uses unpacked Cargo archives, not published
crates or workspace path dependencies. The test harness re-exports the selected
public import (`brynja_crypto` or `brynja::crypto`) as `gmac_consumer::crypto`.

The following example is compiled and executed with both opt-ins. It receives
two **separate** keys and a prefix/counter already reserved under each key.
An application must persist its reservations before sending. GMAC authenticates
cleartext; importing tag bytes does not verify them. GCM plaintext is returned
in caller-owned memory, not in an automatically clearing secret-output type.

```rust
use gmac_consumer::crypto::{aes_gcm::Aes128Gcm, gmac::Aes128Gmac};

fn round_trip(aead_key: &[u8; 16], mac_key: &[u8; 16], prefix: [u8; 4], reserved: u64) {
    let (mut aead_schedule, mut mac_schedule) = ([0; 176], [0; 176]);
    let mut aead = Aes128Gcm::<16>::from_reserved_range(
        aead_key, &mut aead_schedule, prefix, reserved, 1,
    ).unwrap();
    let mut mac = Aes128Gmac::<16>::from_reserved_range(
        mac_key, &mut mac_schedule, prefix, reserved, 1,
    ).unwrap();
    let mut record = *b"hello";
    let mut scratch = [0; 5];
    let (iv, tag) = aead.seal_next_in_place(b"header", &mut record, &mut scratch).unwrap();
    aead.open_in_place(&iv, b"header", &tag, &mut record, &mut scratch).unwrap();
    assert_eq!(&record, b"hello");
    let (iv, tag) = mac.authenticate_next(&record).unwrap();
    mac.verify(&iv, &record, &tag).unwrap();
    assert!(mac.verify(&iv, b"other", &tag).is_err());
    drop((mac, aead));
    assert_eq!(scratch, [0; 5]);
    assert_eq!(mac_schedule, [0; 176]);
    assert_eq!(aead_schedule, [0; 176]);
}
```

Both APIs are one-shot. No streaming context or cancellation token is
promised. The tests inspect caller-visible scratch, schedules and rejection
destinations, including Drop during host unwinding. They do not establish
spill erasure, timing, physical fault resistance or native execution on
Cortex-M. The shared GCM transaction proofs and fault-path unit tests remain
separate evidence, not proofs of these exact linked binaries.
