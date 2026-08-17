const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const ROTATION_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const PI_DESTINATIONS: [usize; 25] = [
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
];

pub(super) fn permute(state: &mut [u64; 25]) {
    for constant in ROUND_CONSTANTS {
        let mut columns = [0_u64; 5];
        for (x, parity) in columns.iter_mut().enumerate() {
            *parity = state
                .iter()
                .skip(x)
                .step_by(5)
                .fold(0_u64, |combined, lane| combined ^ lane);
        }
        let [c0, c1, c2, c3, c4] = columns;
        let theta = [
            c4 ^ c1.rotate_left(1),
            c0 ^ c2.rotate_left(1),
            c1 ^ c3.rotate_left(1),
            c2 ^ c4.rotate_left(1),
            c3 ^ c0.rotate_left(1),
        ];
        for row in state.chunks_exact_mut(5) {
            for (lane, adjustment) in row.iter_mut().zip(theta) {
                *lane ^= adjustment;
            }
        }

        let mut rearranged = [0_u64; 25];
        for ((lane, rotation), destination) in
            state.iter().zip(ROTATION_OFFSETS).zip(PI_DESTINATIONS)
        {
            if let Some(target) = rearranged.get_mut(destination) {
                *target = lane.rotate_left(rotation);
            }
        }

        for (target, source) in state.chunks_exact_mut(5).zip(rearranged.chunks_exact(5)) {
            if let ([a0, a1, a2, a3, a4], [b0, b1, b2, b3, b4]) = (target, source) {
                *a0 = b0 ^ ((!b1) & b2);
                *a1 = b1 ^ ((!b2) & b3);
                *a2 = b2 ^ ((!b3) & b4);
                *a3 = b3 ^ ((!b4) & b0);
                *a4 = b4 ^ ((!b0) & b1);
            }
        }
        if let Some(first) = state.first_mut() {
            *first ^= constant;
        }
    }
}

pub(crate) const fn byte_location(position: usize) -> (usize, u32) {
    let shift = match position % 8 {
        0 => 0,
        1 => 8,
        2 => 16,
        3 => 24,
        4 => 32,
        5 => 40,
        6 => 48,
        _ => 56,
    };
    (position / 8, shift)
}

pub(super) fn xor_byte(state: &mut [u64; 25], position: usize, byte: u8) {
    let (lane, shift) = byte_location(position);
    if let Some(target) = state.get_mut(lane) {
        *target ^= u64::from(byte) << shift;
    }
}

pub(super) fn byte(state: &[u64; 25], position: usize) -> u8 {
    let (lane, _) = byte_location(position);
    let value = match state.get(lane) {
        Some(value) => *value,
        None => 0,
    };
    value.to_le_bytes().get(position % 8).copied().unwrap_or(0)
}
