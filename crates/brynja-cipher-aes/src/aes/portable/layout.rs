// Production public index calculations, shared verbatim with bounded proofs.
// Callers supply state indices 0..16 and rounds 0..=10/12/14 for AES-128/192/256. Checked reads
// in portable.rs remain the runtime boundary; these are not admission APIs.
pub(super) fn round_key_index(round: usize, byte: usize) -> usize {
    round.wrapping_mul(16).wrapping_add(byte)
}

pub(super) const fn valid_wide_parameters(key: usize, schedule: usize, rounds: usize) -> bool {
    matches!((key, schedule, rounds), (24, 208, 12) | (32, 240, 14))
}

// The caller supplies a generated, aligned word offset >= distance and byte < 4.
// Checked accesses remain mandatory; these functions are not admission APIs.
pub(super) fn prior_word_index(offset: usize, distance: usize, byte: usize) -> usize {
    offset.wrapping_sub(distance).wrapping_add(byte)
}

pub(super) fn word_byte_index(offset: usize, byte: usize) -> usize {
    offset.wrapping_add(byte)
}

pub(super) fn shift_source(index: usize, inverse: bool) -> usize {
    let row = index % 4;
    let column = index / 4;
    let source = if inverse {
        column.wrapping_add(4).wrapping_sub(row) % 4
    } else {
        column.wrapping_add(row) % 4
    };
    source.wrapping_mul(4).wrapping_add(row)
}
