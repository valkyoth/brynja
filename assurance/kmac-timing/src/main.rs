use std::{hint::black_box, time::Instant};

use brynja_mac_kmac::Kmac128;

const TAG_BYTES: usize = 4_096;
const BATCHES: usize = 48;
const REPETITIONS: usize = 64;
const MAX_RATIO_PER_MILLE: u128 = 1_250;

fn main() -> Result<(), &'static str> {
    let key = [0x5A; 16];
    let mut tag_bytes = [0_u8; TAG_BYTES];
    let mut state = Kmac128::new(&key, b"timing-evidence").map_err(|_| "constructor")?;
    state
        .update(b"fixed public message")
        .map_err(|_| "update")?;
    let tag = state.finalize_tag(&mut tag_bytes).map_err(|_| "finalize")?;
    let mut first = [0_u8; TAG_BYTES];
    first.copy_from_slice(tag.as_bytes());
    let mut last = first;
    if let Some(byte) = first.first_mut() {
        *byte ^= 1;
    }
    if let Some(byte) = last.last_mut() {
        *byte ^= 1;
    }

    for _ in 0..8 {
        run_batch(&tag, black_box(&first));
        run_batch(&tag, black_box(&last));
    }
    let mut first_ns = 0_u128;
    let mut last_ns = 0_u128;
    for batch in 0..BATCHES {
        if batch.is_multiple_of(2) {
            first_ns = first_ns.saturating_add(measure(&tag, &first));
            last_ns = last_ns.saturating_add(measure(&tag, &last));
        } else {
            last_ns = last_ns.saturating_add(measure(&tag, &last));
            first_ns = first_ns.saturating_add(measure(&tag, &first));
        }
    }
    let smaller = first_ns.min(last_ns);
    let larger = first_ns.max(last_ns);
    if smaller == 0 || larger.saturating_mul(1_000) > smaller.saturating_mul(MAX_RATIO_PER_MILLE) {
        return Err("first/last mismatch timing ratio exceeds bound");
    }
    println!("KMAC tag comparison timing: first={first_ns}ns last={last_ns}ns ratio-bound=1.250");
    Ok(())
}

fn measure(tag: &brynja_mac_kmac::KmacTag<'_>, candidate: &[u8]) -> u128 {
    let started = Instant::now();
    run_batch(tag, black_box(candidate));
    started.elapsed().as_nanos()
}

fn run_batch(tag: &brynja_mac_kmac::KmacTag<'_>, candidate: &[u8]) {
    for _ in 0..REPETITIONS {
        black_box(tag.verify_candidate(black_box(candidate)).expose_public());
    }
}
