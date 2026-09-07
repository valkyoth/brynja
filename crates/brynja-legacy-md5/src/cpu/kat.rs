// Distinct short-message answers independently checked against RFC 1321's
// reference digest convention. Distinct slots detect lane permutation faults.
type Kat = ([[u32; 4]; 8], [[u8; 64]; 8], [[u32; 4]; 8]);
pub(super) fn inputs(iv: [u32; 4]) -> Kat {
    let messages: [&[u8]; 8] = [
        b"",
        b"a",
        b"abc",
        b"message digest",
        b"b",
        b"ab",
        b"abcd",
        b"xyz",
    ];
    let answers: [u128; 8] = [
        0xd41d8cd98f00b204e9800998ecf8427e,
        0x0cc175b9c0f1b6a831c399e269772661,
        0x900150983cd24fb0d6963f7d28e17f72,
        0xf96b697d7cb7938d525a2f31aaf161d0,
        0x92eb5ffee6ae2fec3ad71c777531578f,
        0x187ef4436122d1cc2f40dc2b92f0eba0,
        0xe2fc714c4727ee9395f324cd2e7f331f,
        0xd16fb36f0911f878998c136191af705e,
    ];
    let mut blocks = [[0; 64]; 8];
    let mut expected = [[0; 4]; 8];
    for ((block, message), (words, answer)) in blocks
        .iter_mut()
        .zip(messages)
        .zip(expected.iter_mut().zip(answers))
    {
        for (dst, src) in block.iter_mut().zip(message) {
            *dst = *src;
        }
        if let Some(last) = block.get_mut(message.len()) {
            *last = 0x80;
        }
        if let Some(length) = block.get_mut(56) {
            *length = u8::try_from(message.len().saturating_mul(8)).unwrap_or(0);
        }
        for (word, bytes) in words
            .iter_mut()
            .zip(answer.to_be_bytes().as_chunks::<4>().0.iter())
        {
            let [a, b, c, d] = bytes;
            *word = u32::from_le_bytes([*a, *b, *c, *d]);
        }
    }
    ([iv; 8], blocks, expected)
}
