//! Shared update window with acknowledged counter control. Synthetic public inputs only.

use brynja_crypto::ghash::Ghash;
use std::fs::File;
use std::hint::black_box;
use std::io::{Read, Write};

const BLOCKS: usize = 4096;

fn control(command: &[u8], ctl: &mut File, ack: &mut File) {
    ctl.write_all(command).unwrap();
    let mut response = [0; 16];
    let n = ack.read(&mut response).unwrap();
    assert!(matches!(&response[..n], b"ack\n" | b"ack\n\0"));
}

fn draw(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

#[inline(never)]
fn batch(g: &mut Ghash<'_>, block: &[u8; 16], count: usize) {
    for _ in 0..count {
        g.update(black_box(block)).unwrap();
    }
}

pub fn run() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 6);
    let mode = args[1].as_str();
    assert!(matches!(mode, "empty" | "identical" | "subkey" | "block"));
    assert!(matches!(args[2].as_str(), "0" | "1"));
    let mut seed = 0x4924_a107_a076_f821 ^ args[3].parse::<u64>().unwrap();
    let mut varied = [0; 16];
    for chunk in varied.chunks_exact_mut(8) {
        chunk.copy_from_slice(&draw(&mut seed).to_le_bytes());
    }
    let mut key = [0x39; 16];
    let mut block = [0xa7; 16];
    if args[2] == "1" && mode == "subkey" {
        key = varied;
    }
    if args[2] == "1" && mode == "block" {
        block = varied;
    }
    let count = if mode == "empty" { 0 } else { BLOCKS };
    let mut ctl = File::options().write(true).open(&args[4]).unwrap();
    let mut ack = File::open(&args[5]).unwrap();
    let mut work = [0; 16];
    let mut out = [0; 16];
    let one = (1u128 << 127).to_be_bytes();
    let mut kat = Ghash::new(&one, &mut work, 16);
    kat.update(&block).unwrap();
    assert_eq!(kat.native_blocks(), Ok(1));
    assert_eq!(kat.finish(&mut out).unwrap().expose(), &block);
    let mut warm = Ghash::new(black_box(&key), &mut work, (16 * BLOCKS) as u64);
    batch(&mut warm, &block, BLOCKS);
    black_box(warm.finish(&mut out).unwrap().expose());

    let mut g = Ghash::new(black_box(&key), &mut work, (count * 16) as u64);
    control(b"enable\n", &mut ctl, &mut ack);
    batch(&mut g, &block, count);
    control(b"disable\n", &mut ctl, &mut ack);
    assert_eq!(g.native_blocks(), Ok(count as u64));
    black_box(g.finish(&mut out).unwrap().expose());
    println!("completed {count} native blocks");
}
