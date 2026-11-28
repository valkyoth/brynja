//! Experimental owner for public test data. Not a production backend.
use super::*;
use brynja_core::clear_owned_region;
#[cfg(test)]
use brynja_core::{accumulate_secret_byte_difference, secret_difference_is_zero};

const LONG: usize = 1024;
const CLAMP: u128 = 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;
type Table = [[__m256i; 5]; 5];

struct Powers<'a>(&'a mut [[[u8; 8]; 5]; 4]);
impl Drop for Powers<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0.as_flattened_mut().as_flattened_mut());
    }
}

struct TableGuard<'a>(&'a mut Table);
impl Drop for TableGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: this initialized array contains only 25 packed 32-byte
        // integer vectors. All-zero bits are valid. The view is bounded by
        // the object's size and exclusively borrowed for the clear.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                std::ptr::from_mut(self.0).cast::<u8>(),
                std::mem::size_of::<Table>(),
            )
        };
        let _ = clear_owned_region(bytes);
    }
}

// Do not retain either powers or the expanded table between updates.
#[target_feature(enable = "avx2")]
fn groups(mut h: F, blocks: &[[u8; 64]], r: F) -> F {
    let mut storage = [[[0; 8]; 5]; 4];
    let powers = Powers(&mut storage);
    powers.0[3] = r.map(u64::to_le_bytes);
    powers.0[2] = mul(r, r).map(u64::to_le_bytes);
    powers.0[1] = mul(powers.0[2].map(u64::from_le_bytes), r).map(u64::to_le_bytes);
    powers.0[0] = mul(
        powers.0[2].map(u64::from_le_bytes),
        powers.0[2].map(u64::from_le_bytes),
    )
    .map(u64::to_le_bytes);
    let mut table = [[_mm256_setzero_si256(); 5]; 5];
    let guard = TableGuard(&mut table);
    for (j, row) in guard.0.iter_mut().enumerate() {
        for (i, weight) in row.iter_mut().enumerate() {
            *weight = pack(std::array::from_fn(|lane| {
                u64::from_le_bytes(powers.0[lane][(j + 5 - i) % 5]) * if i > j { 5 } else { 1 }
            }));
        }
    }
    drop(powers);
    for block in blocks {
        h = group(h, block, guard.0);
    }
    h
}

#[derive(Default)]
struct Workspace {
    acc: [[u8; 8]; 5],
    tail: [u8; 16],
}

struct Owner<'a> {
    key: &'a mut [u8; 32],
    ws: &'a mut Workspace,
    used: usize,
    len: u64,
}

impl<'a> Owner<'a> {
    // Exact RFC import only. Callers in this fixture provide a clean workspace.
    fn start(key: &'a mut [u8; 32], ws: &'a mut Workspace) -> Self {
        assert!(std::is_x86_feature_detected!("avx2"), "AVX2 required");
        // Initialize explicitly: a forgotten prior owner cannot inject a stale accumulator.
        ws.acc = [[0; 8]; 5];
        ws.tail = [0; 16];
        Self {
            key,
            ws,
            used: 0,
            len: 0,
        }
    }

    fn r(&self) -> F {
        limbs(u128::from_le_bytes(self.key[..16].try_into().unwrap()) & CLAMP)
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), &'static str> {
        self.len = self
            .len
            .checked_add(u64::try_from(input.len()).map_err(|_| "length")?)
            .ok_or("length")?;
        if self.used != 0 {
            let take = input.len().min(16 - self.used);
            self.ws.tail[self.used..self.used + take].copy_from_slice(&input[..take]);
            self.used += take;
            input = &input[take..];
            if self.used < 16 {
                return Ok(());
            }
            self.ws.acc = mul(
                add(self.ws.acc.map(u64::from_le_bytes), block(&self.ws.tail)),
                self.r(),
            )
            .map(u64::to_le_bytes);
            let _ = clear_owned_region(&mut self.ws.tail);
            self.used = 0;
        }
        let mut h = self.ws.acc.map(u64::from_le_bytes);
        let r = self.r();
        if input.len() >= LONG {
            let (whole, rest) = input.as_chunks::<64>();
            // SAFETY: start checked AVX2 and there is no unchecked constructor.
            h = unsafe { groups(h, whole, r) };
            input = rest;
        }
        let (whole, rest) = input.as_chunks::<16>();
        for bytes in whole {
            h = mul(add(h, block(bytes)), r);
        }
        self.ws.acc = h.map(u64::to_le_bytes);
        self.ws.tail[..rest.len()].copy_from_slice(rest);
        self.used = rest.len();
        Ok(())
    }

    fn tag(&self) -> [u8; 16] {
        let mut h = self.ws.acc.map(u64::from_le_bytes);
        if self.used != 0 {
            h = mul(add(h, block(&self.ws.tail[..self.used])), self.r());
        }
        let q = h.iter().fold(5, |q, d| (d + q) >> 26);
        let low = h
            .iter()
            .rev()
            .fold(0u128, |x, &d| (x << 26) | u128::from(d));
        low.wrapping_add(u128::from(5 * q))
            .wrapping_add(u128::from_le_bytes(self.key[16..].try_into().unwrap()))
            .to_le_bytes()
    }

    fn finalize(self) -> [u8; 16] {
        self.tag()
    }

    #[cfg(test)]
    fn verify(self, expected: &[u8; 16]) -> bool {
        let mut computed = self.tag();
        let mut diff = 0;
        for (a, b) in computed.iter().zip(expected) {
            accumulate_secret_byte_difference(&mut diff, a, b);
        }
        let valid = secret_difference_is_zero(&diff).expose_public();
        let _ = clear_owned_region(std::slice::from_mut(&mut diff));
        let _ = clear_owned_region(&mut computed);
        valid
    }
}

impl Drop for Owner<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.key);
        let _ = clear_owned_region(self.ws.acc.as_flattened_mut());
        let _ = clear_owned_region(&mut self.ws.tail);
    }
}

pub(crate) fn candidate(key: &[u8; 32], msg: &[u8], chunk: usize) -> [u8; 16] {
    let mut key = *key;
    let mut ws = Workspace::default();
    let mut mac = Owner::start(&mut key, &mut ws);
    for part in msg.chunks(chunk) {
        mac.update(part).unwrap();
    }
    mac.finalize()
}

fn baseline(key: &[u8; 32], msg: &[u8], chunk: usize) -> [u8; 16] {
    let mut key = *key;
    let mut mac = brynja_mac_poly1305::OneTimeKey::from_rfc8439_key(&mut key).start();
    for part in msg.chunks(chunk) {
        mac.update(part).unwrap();
    }
    mac.finalize()
}

#[cfg(test)]
mod tests;

pub(crate) fn throughput() {
    use std::{hint::black_box, time::Instant};
    let key = std::array::from_fn(|i| (i as u8).wrapping_mul(31));
    println!("bytes,chunk,pair,records,portable_ns,owner_ns");
    for (size, chunk) in [16, 63, 64, 65, 256, 1023, 1024, 1025, 1500, 4096, 16384]
        .map(|n| (n, n))
        .into_iter()
        .chain([(16384, 1500), (16384, 17)])
    {
        let msg: Vec<_> = (0..size).map(|i| (i as u8).wrapping_mul(117)).collect();
        assert_eq!(candidate(&key, &msg, chunk), baseline(&key, &msg, chunk));
        let reps = 524288 / size;
        let batch = |tag: fn(&[u8; 32], &[u8], usize) -> [u8; 16]| {
            let start = Instant::now();
            for _ in 0..reps {
                black_box(tag(black_box(&key), black_box(&msg), black_box(chunk)));
            }
            start.elapsed().as_nanos()
        };
        batch(baseline);
        batch(candidate);
        for pair in 0..12 {
            let (p, v) = if pair % 2 == 0 {
                (batch(baseline), batch(candidate))
            } else {
                let v = batch(candidate);
                (batch(baseline), v)
            };
            println!("{size},{chunk},{pair},{reps},{p},{v}");
        }
    }
}
