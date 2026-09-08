// Compiled only inside a temporary instrumented SHA-2 crate, never shipped.
use crate::*;
use core::sync::atomic::{AtomicUsize, Ordering};

static COUNTS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
pub(crate) fn tick(index: usize) {
    COUNTS[index].fetch_add(1, Ordering::Relaxed);
}
fn reset() {
    for counter in &COUNTS {
        counter.store(0, Ordering::Relaxed);
    }
}
fn counts() -> [usize; 4] {
    core::array::from_fn(|i| COUNTS[i].load(Ordering::Relaxed))
}

#[test]
fn final_work_counts() -> Result<(), Sha512TError> {
    let mut message = [0_u8; 1024];
    let mut destination = [0xa5; 64];
    let mut cases = 0;
    for t in 1..512 {
        if t == 384 {
            continue;
        }
        let p = Sha512TBits::new(t)?;
        for length in [0, 1, 111, 112, 127, 128, 129, 1024] {
            for pattern in [0, 0xa5, 0xff] {
                message.fill(pattern);
                let data = &message[..length];
                let blocks = length / 128 + if length % 128 < 112 { 1 } else { 2 };
                reset();
                let ordinary = sha512_t(p, data)?;
                assert_eq!(
                    counts(),
                    [blocks + 1, 0, (blocks + 1) * 80, 0],
                    "ordinary work"
                );
                reset();
                destination.fill(0xa5);
                let secret =
                    hardened_sha512_t_secret(p, data, &mut destination[..p.output_bytes()])?;
                assert_eq!(counts(), [1, blocks, 80, blocks * 80], "hardened work");
                assert_eq!(secret.as_bytes(), ordinary.as_bytes());
                drop(secret);
                assert!(destination[..p.output_bytes()].iter().all(|b| *b == 0));
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 12240);
    Ok(())
}
