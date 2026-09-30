//! Fixed private protocol metadata validation. No host secret-byte processing.
use super::Error;

pub(super) fn inside(base: usize, bytes: usize, address: usize, length: usize) -> bool {
    address
        .checked_sub(base)
        .and_then(|offset| offset.checked_add(length))
        .is_some_and(|end| end <= bytes)
}
pub(super) fn disjoint(a: usize, n: usize, b: usize, m: usize) -> bool {
    if a <= b {
        b.checked_sub(a).is_some_and(|d| d >= n)
    } else {
        a.checked_sub(b).is_some_and(|d| d >= m)
    }
}
pub(super) fn regions<const N: usize>(
    low: usize,
    addresses: [usize; N],
    widths: [usize; N],
) -> bool {
    for (i, (&a, &n)) in addresses.iter().zip(widths.iter()).enumerate() {
        if !inside(low, 65536, a, n) {
            return false;
        }
        for (&b, &m) in addresses.iter().zip(widths.iter()).take(i) {
            if !disjoint(a, n, b, m) {
                return false;
            }
        }
    }
    true
}

pub(super) fn header(input: &[u8], sequence: u64) -> Result<[u8; 32], Error> {
    if input.len() > 1024 || sequence == 0 {
        return Err(Error::Bounds);
    }
    let source = if input.is_empty() {
        0
    } else {
        input.as_ptr() as usize
    };
    source.checked_add(input.len()).ok_or(Error::Bounds)?;
    let mut result = [0; 32];
    for (word, bytes) in [
        4,
        sequence,
        u64::try_from(input.len()).map_err(|_| Error::Bounds)?,
        u64::try_from(source).map_err(|_| Error::Bounds)?,
    ]
    .into_iter()
    .zip(result.chunks_exact_mut(8))
    {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    Ok(result)
}

#[derive(Default)]
pub(super) struct Context {
    pub(super) base: usize,
    pub(super) operation: usize,
    pub(super) length: usize,
    pub(super) epoch: u64,
    pub(super) generation: u64,
    pub(super) low: usize,
    pub(super) slot: usize,
    pub(super) phase: u8,
    pub(super) slot_phase: u8,
    pub(super) locked: bool,
    pub(super) slot_locked: bool,
    pub(super) error: bool,
}
impl Context {
    pub(super) fn inspect(
        &self,
        returned: usize,
        outer: [usize; 7],
        guards: [usize; 13],
        inner: [usize; 10],
        input: [usize; 11],
        rehash: [usize; 9],
    ) -> Result<(), Error> {
        let expected = match self.operation {
            0 => 1,
            1 => 2,
            2 => 3,
            3 => 4,
            4 => 5,
            8 => 8,
            _ => return Err(Error::Protocol),
        };
        self.inspect_common(
            returned,
            outer,
            guards,
            inner,
            expected,
            matches!(self.operation, 1 | 8),
        )?;
        self.inspect_input(input)?;
        self.inspect_rehash(rehash)
    }
    pub(super) fn inspect_common(
        &self,
        returned: usize,
        outer: [usize; 7],
        guards: [usize; 13],
        inner: [usize; 10],
        expected: usize,
        work_cleared: bool,
    ) -> Result<(), Error> {
        let [low, high, sp, redzone, flags, enter, clear] = outer;
        let [
            guard_low,
            guard_high,
            guard_a,
            guard_b,
            g4,
            g5,
            g6,
            g7,
            g8,
            g9,
            g10,
            g11,
            g12,
        ] = guards;
        let [
            status,
            slot_guard,
            slot,
            alive,
            has_digest,
            cleared,
            freed,
            error,
            borrow_revoked,
            operation,
        ] = inner;
        let destroying = self.operation == 3;
        if returned != 95
            || low != self.low
            || high.checked_sub(low) != Some(65536)
            || !inside(low, 65536, sp, 1)
            || !inside(low, 65536, redzone, 256)
            || !disjoint(sp, 1, redzone, 256)
            || (flags, enter, clear) != (31, 1, 1)
            || self.phase != 2
            || self.locked
            || self.error
            || low.checked_sub(4096) != Some(guard_low)
            || guard_high != high
            || (guard_a, guard_b) != (1, 1)
            || [g4, g5, g6, g7, g8, g9, g10, g11, g12] != [0; 9]
            || status != expected
            || self.slot.checked_sub(4096) != Some(slot_guard)
            || slot != self.slot
            || alive != usize::from(!destroying)
            || has_digest != usize::from(work_cleared)
            || cleared != if destroying { 4096 } else { 0 }
            || freed != usize::from(destroying)
            || error != 0
            || borrow_revoked != 1
            || operation != self.operation
            || self.slot_phase != if destroying { 2 } else { 1 }
            || self.slot_locked == destroying
        {
            return Err(Error::Protocol);
        }
        Ok(())
    }
    fn inspect_input(&self, value: [usize; 11]) -> Result<(), Error> {
        if self.operation != 1 {
            return if value == [0; 11] {
                Ok(())
            } else {
                Err(Error::Protocol)
            };
        }
        let [
            attempt,
            header,
            payload,
            copied,
            a,
            b,
            c,
            d,
            length,
            cleared,
            epoch,
        ] = value;
        if (attempt, header, payload, copied)
            != (
                1,
                1,
                usize::from(self.length != 0),
                usize::from(self.length != 0),
            )
            || length != self.length
            || self.length > 1024
            || cleared != 1
            || u64::try_from(epoch).ok() != Some(self.epoch)
            || self.epoch == 0
            || !regions(self.low, [a, b, c, d], [32, 1024, 1170, 32])
        {
            return Err(Error::Protocol);
        }
        Ok(())
    }
    fn inspect_rehash(&self, value: [usize; 9]) -> Result<(), Error> {
        let [a, b, c, cleared, previous, next, epoch, status, exported] = value;
        if self.operation != 8 {
            return if [a, b, c, cleared, previous, next, epoch, status] == [0; 8]
                && exported == usize::from(self.operation == 2)
            {
                Ok(())
            } else {
                Err(Error::Protocol)
            };
        }
        if exported != 0
            || cleared != 1
            || status != 8
            || self.generation == 0
            || self.epoch == 0
            || u64::try_from(epoch).ok() != Some(self.epoch)
            || u64::try_from(previous).ok() != Some(self.generation)
            || self.generation.checked_add(1).is_none()
            || u64::try_from(next).ok() != self.generation.checked_add(1)
            || !regions(self.low, [a, b, c], [1170, 32, 32])
        {
            return Err(Error::Protocol);
        }
        Ok(())
    }
}
