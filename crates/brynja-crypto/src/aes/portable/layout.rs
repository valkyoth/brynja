// Production public index calculations, shared verbatim with bounded proofs.
// Callers supply state indices 0..16 and round indices 0..=10. Checked reads
// in portable.rs remain the runtime boundary; these are not admission APIs.
pub(super) fn round_key_index(round: usize, byte: usize) -> usize {
    round.wrapping_mul(16).wrapping_add(byte)
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
