use core::hint::black_box;
use core::sync::atomic::{Ordering, compiler_fence};

/// Passes a value through an explicit compiler and optimization barrier.
///
/// This prevents the surrounding evidence harness from treating the value as
/// compile-time known and orders compiler-visible memory operations. It does
/// not create synchronization, erase copies, or prove constant-time machine
/// code. Later cryptographic milestones must inspect their optimized output.
#[inline(never)]
pub fn compiler_barrier<T>(value: T) -> T {
    compiler_fence(Ordering::SeqCst);
    let protected = black_box(value);
    compiler_fence(Ordering::SeqCst);
    protected
}
