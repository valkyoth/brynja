use crate::owner::Sha1Owner;

// FIPS 180-4 §§4.1.1, 4.2.1, 6.1.2. All round additions are modulo 2^32.
// Indexes and branches depend only on public fixed round numbers, never data.
pub(crate) fn compress(owner: &mut Sha1Owner) {
    for (destination, source) in owner.schedule.iter_mut().zip(owner.block.iter()) {
        *destination = *source;
    }
    for index in 16_usize..80 {
        let word = (read(&owner.schedule, index.saturating_sub(3))
            ^ read(&owner.schedule, index.saturating_sub(8))
            ^ read(&owner.schedule, index.saturating_sub(14))
            ^ read(&owner.schedule, index.saturating_sub(16)))
        .rotate_left(1);
        write(&mut owner.schedule, index, word);
    }
    let mut a = read(&owner.chaining_state, 0);
    let mut b = read(&owner.chaining_state, 1);
    let mut c = read(&owner.chaining_state, 2);
    let mut d = read(&owner.chaining_state, 3);
    let mut e = read(&owner.chaining_state, 4);
    for round in 0..80 {
        let (function, constant) = match round {
            0..=19 => ((b & c) ^ (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) ^ (b & d) ^ (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let next = a
            .rotate_left(5)
            .wrapping_add(function)
            .wrapping_add(e)
            .wrapping_add(constant)
            .wrapping_add(read(&owner.schedule, round));
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = next;
    }
    add(&mut owner.chaining_state, 0, a);
    add(&mut owner.chaining_state, 1, b);
    add(&mut owner.chaining_state, 2, c);
    add(&mut owner.chaining_state, 3, d);
    add(&mut owner.chaining_state, 4, e);
    owner.clear_block();
}

fn read(bytes: &[u8], index: usize) -> u32 {
    let mut word = 0_u32;
    for byte in bytes.iter().skip(index.saturating_mul(4)).take(4) {
        word = (word << 8) | u32::from(*byte);
    }
    word
}

fn write(bytes: &mut [u8], index: usize, word: u32) {
    for (byte, shift) in bytes
        .iter_mut()
        .skip(index.saturating_mul(4))
        .take(4)
        .zip([24, 16, 8, 0])
    {
        *byte = u8::try_from((word >> shift) & 0xff).unwrap_or(0);
    }
}

fn add(bytes: &mut [u8], index: usize, word: u32) {
    write(bytes, index, read(bytes, index).wrapping_add(word));
}
