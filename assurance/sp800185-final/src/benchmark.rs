use std::{hint::black_box, time::Instant};

use brynja_hash_parallel::{
    parallel_hash_xof128, parallel_hash_xof256, parallel_hash128, parallel_hash256,
};
use brynja_hash_parallel_std::{CancellationToken, ParallelHashExecutor};

/// Fixed public data only; descriptive timings never grant backend admission.
pub fn run() -> Result<(), &'static str> {
    let input = [0x5a_u8; 16_384];
    let mut workspace = [0_u8; 1024];
    let mut expected = [0_u8; 64];
    let mut actual = [0_u8; 64];
    macro_rules! measure {
        ($function:ident) => {
            for workers in [1, 2, 4] {
                let executor = ParallelHashExecutor::new(workers, 16).map_err(|_| "executor")?;
                let mut sequential = 0_u128;
                let mut threaded = 0_u128;
                for round in 0..10 {
                    // Alternate order to reduce systematic warm-cache bias.
                    for native in [round % 2 == 0, round % 2 != 0] {
                        let started = Instant::now();
                        if native {
                            executor.$function(black_box(&input), 1024, b"performance", &mut actual,
                                &CancellationToken::new()).map_err(|_| "native")?;
                            let elapsed = started.elapsed().as_nanos();
                            black_box(&actual);
                            if round >= 2 { threaded += elapsed; }
                        } else {
                            $function(black_box(&input), &mut workspace, b"performance", &mut expected)
                                .map_err(|_| "sequential")?;
                            let elapsed = started.elapsed().as_nanos();
                            black_box(&expected);
                            if round >= 2 { sequential += elapsed; }
                        }
                    }
                    if expected != actual { return Err("benchmark output mismatch"); }
                }
                println!("benchmark: {} workers={workers} bytes=16384 block=1024 samples=8 sequential_ns={sequential} threaded_ns={threaded}", stringify!($function));
            }
        };
    }
    measure!(parallel_hash128);
    measure!(parallel_hash256);
    measure!(parallel_hash_xof128);
    measure!(parallel_hash_xof256);
    Ok(())
}
