pub fn decode<const LENGTH: usize>(hex: &str) -> [u8; LENGTH] {
    let mut bytes = [0_u8; LENGTH];
    for (target, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        if let [high, low] = pair {
            *target = nibble(*high)
                .saturating_mul(16)
                .saturating_add(nibble(*low));
        }
    }
    bytes
}

const fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte.saturating_sub(b'0'),
        b'a'..=b'f' => byte.saturating_sub(b'a').saturating_add(10),
        _ => 0,
    }
}

pub fn patterned<const LENGTH: usize>() -> [u8; LENGTH] {
    let mut output = [0_u8; LENGTH];
    let mut value = 0_u8;
    for byte in &mut output {
        *byte = value;
        value = value.wrapping_add(1);
    }
    output
}
