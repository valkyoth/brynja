use core::ops::RangeInclusive;

pub(super) struct Layout {
    pub head: usize,
    first_end: u32,
    count: u32,
    pub tail: Option<RangeInclusive<u32>>,
}

impl Layout {
    // The caller supplies the inclusive range from reserve() for this exact
    // nonempty slice. A SIMD group is identified by its *last* counter:
    // the first group end must be representable before any group can exist.
    pub fn new(first: u32, last: u32, skip: usize, len: usize) -> Self {
        let head = if skip == 0 {
            0
        } else {
            len.min(64usize.saturating_sub(skip))
        };
        let rest = len.saturating_sub(head);
        let tail_len = rest % 256;
        // The remainder is at most 255, including on 16-bit usize targets.
        let tail_blocks = u32::from(tail_len.to_le_bytes()[0]).div_ceil(64);
        let tail = tail_blocks
            .checked_sub(1)
            .and_then(|offset| last.checked_sub(offset))
            .map(|start| start..=last);
        let first_end = first
            .checked_add(u32::from(head != 0))
            .and_then(|n| n.checked_add(3));
        let (first_end, count) = first_end
            .zip(last.checked_sub(tail_blocks))
            .and_then(|(a, b)| Some((a, (b.checked_sub(a)? / 4).checked_add(1)?)))
            .unwrap_or((3, 0));
        // Fail closed on an inconsistent internal reservation rather than
        // silently shortening zip() and returning unprocessed output.
        assert_eq!(
            usize::try_from(count).ok(),
            Some(rest / 256),
            "incomplete SIMD reservation"
        );
        Self {
            head,
            first_end,
            count,
            tail,
        }
    }

    pub fn groups(&self) -> impl Iterator<Item = [u32; 4]> + '_ {
        (0..self.count).map(|i| match self.lanes(i) {
            Some(lanes) => lanes,
            // An internal invariant violation must never emit a partial group.
            None => unreachable!("group outside the admitted counter range"),
        })
    }

    // Called only with an index in 0..count; construction bounds even the
    // last group's end by the inclusive reservation.
    fn lanes(&self, i: u32) -> Option<[u32; 4]> {
        let end = self.first_end.checked_add(i.checked_mul(4)?)?;
        Some([
            end.checked_sub(3)?,
            end.checked_sub(2)?,
            end.checked_sub(1)?,
            end,
        ])
    }
}

#[cfg(test)]
#[test]
#[should_panic(expected = "incomplete SIMD reservation")]
fn incomplete_counter_group_is_not_admitted() {
    let _ = Layout::new(u32::MAX - 2, u32::MAX, 0, 256);
}

#[cfg(kani)]
#[kani::proof]
fn admitted_partition_maps_each_byte_once() {
    use crate::chacha20::{ChaCha20, END};
    let start: u64 = kani::any();
    kani::assume(start < END);
    let len: usize = kani::any();
    kani::assume(len != 0 && len as u64 <= END - start);
    let mut owner = ChaCha20 {
        key: &[0; 32],
        nonce: [0; 12],
        position: start,
    };
    let (range, skip) = owner
        .reserve(core::num::NonZeroUsize::new(len).unwrap())
        .unwrap();
    let plan = Layout::new(*range.start(), *range.end(), skip, len);
    let head = plan.head;
    assert_eq!(head as u64, (len as u64).min((64 - start % 64) % 64));
    let rest = len - head;
    let count = rest / 256;
    let tail = rest % 256;
    assert_eq!(u64::from(plan.count), count as u64);
    let first_aligned = start + head as u64;
    if rest > 0 {
        assert_eq!(first_aligned % 64, 0);
    }
    if let Some(r) = &plan.tail {
        assert_ne!(tail, 0);
        assert_eq!(
            u64::from(*r.start()) * 64,
            first_aligned + count as u64 * 256
        );
        assert_eq!(u64::from(*r.end()), (start + len as u64 - 1) / 64);
    } else {
        assert_eq!(tail, 0);
    }
    let i: u32 = kani::any();
    if i < plan.count {
        let lanes = plan.lanes(i).unwrap();
        let lane: usize = kani::any();
        kani::assume(lane < 4);
        assert_eq!(
            u64::from(lanes[lane]) * 64,
            first_aligned + i as u64 * 256 + lane as u64 * 64
        );
    }
}
