// RFC 8439 §§2.1–2.3. Byte-backed working storage lets Drop clear the named
// arrays; this makes no claim about scalar temporaries, registers or spills.
type Word = [u8; 4];
struct State([Word; 16]);

impl Drop for State {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(self.0.as_flattened_mut());
    }
}

fn quarter(a: &mut Word, b: &mut Word, c: &mut Word, d: &mut Word) {
    let (mut x, mut y, mut z, mut w) = (
        u32::from_le_bytes(*a),
        u32::from_le_bytes(*b),
        u32::from_le_bytes(*c),
        u32::from_le_bytes(*d),
    );
    x = x.wrapping_add(y);
    w = (w ^ x).rotate_left(16);
    z = z.wrapping_add(w);
    y = (y ^ z).rotate_left(12);
    x = x.wrapping_add(y);
    w = (w ^ x).rotate_left(8);
    z = z.wrapping_add(w);
    y = (y ^ z).rotate_left(7);
    (*a, *b, *c, *d) = (
        x.to_le_bytes(),
        y.to_le_bytes(),
        z.to_le_bytes(),
        w.to_le_bytes(),
    );
}

fn generate(key: &[u8; 32], nonce: &[u8; 12], counter: u32, work: &mut State) {
    let mut initial = State([[0; 4]; 16]);
    for (slot, word) in initial.0.iter_mut().zip(
        b"expand 32-byte k"
            .as_chunks::<4>()
            .0
            .iter()
            .chain(key.as_chunks::<4>().0)
            .chain(core::iter::once(&counter.to_le_bytes()))
            .chain(nonce.as_chunks::<4>().0),
    ) {
        *slot = *word;
    }
    work.0.copy_from_slice(&initial.0);
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = &mut work.0;
    for _ in 0..10 {
        quarter(a, e, i, m);
        quarter(b, f, j, n);
        quarter(c, g, k, o);
        quarter(d, h, l, p);
        quarter(a, f, k, p);
        quarter(b, g, l, m);
        quarter(c, h, i, n);
        quarter(d, e, j, o);
    }
    for (out, start) in work.0.iter_mut().zip(&initial.0) {
        *out = u32::from_le_bytes(*out)
            .wrapping_add(u32::from_le_bytes(*start))
            .to_le_bytes();
    }
}

impl super::Admitted<'_> {
    // Generate each admitted block exactly once, even when the last is u32::MAX.
    pub(super) fn xor(self, key: &[u8; 32], nonce: &[u8; 12]) {
        let mut work = State([[0; 4]; 16]);
        let mut bytes = self.data.iter_mut();
        let mut offset = self.skip;
        for counter in self.counters {
            generate(key, nonce, counter, &mut work);
            for (stream, out) in work.0.as_flattened().iter().skip(offset).zip(&mut bytes) {
                *out ^= *stream;
            }
            offset = 0;
        }
        debug_assert!(bytes.as_slice().is_empty());
    }
}
