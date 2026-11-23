//! Linux RV64 scalar carry-less multiplication, independently admitted from AES.
#![allow(unsafe_code)]

use std::arch::is_riscv_feature_detected;

#[path = "ghash_admission.rs"]
mod admission;
#[cfg(feature = "ghash-runtime-execution")]
#[path = "ghash_runtime.rs"]
pub(super) mod runtime;
#[cfg(brynja_ghash_rv64_evidence)]
pub use admission::RequiredProduct as RequiredRv64;

// One capability: either extension supplies both CLMUL and CLMULH.
const FEATURE_COUNT: usize = 1;
fn host_features() -> [bool; FEATURE_COUNT] {
    [is_riscv_feature_detected!("zbc") || is_riscv_feature_detected!("zbkc")]
}

/// Caller must establish RV64 Zbc or Zbkc on the executing CPU.
unsafe fn multiply(x: u128, h: u128) -> u128 {
    fn reflected_halves(wire: u128) -> (u64, u64) {
        let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = wire.to_be_bytes();
        (
            u64::from_be_bytes([a, b, c, d, e, f, g, h]).reverse_bits(),
            u64::from_be_bytes([i, j, k, l, m, n, o, p]).reverse_bits(),
        )
    }
    let product = |a: u64, b: u64| {
        let (lo, hi): (u64, u64);
        // SAFETY: multiply's admission covers exactly these instructions.
        // No memory or stack access. lo is early-clobber because the second
        // instruction still needs both inputs. Keep the assembler extension
        // local; the rest of the binary needs neither optional extension.
        unsafe {
            core::arch::asm!(".option push", ".option arch, +zbc",
                "clmul {lo}, {a}, {b}", "clmulh {hi}, {a}, {b}", ".option pop",
                a=in(reg) a, b=in(reg) b, lo=out(reg) lo, hi=lateout(reg) hi,
                options(pure, nomem, nostack));
        }
        u128::from(lo) | (u128::from(hi) << 64)
    };
    let (a, b) = reflected_halves(x);
    let (c, d) = reflected_halves(h);
    let ll = product(a, c);
    let hh = product(b, d);
    let cross = product(a ^ b, c ^ d) ^ ll ^ hh;
    let low = ll ^ (cross << 64);
    let high = hh ^ (cross >> 64);
    // x^128 = x^7 + x^2 + x + 1. The second fold cannot overflow.
    let fold = |v: u128| v ^ (v << 1) ^ (v << 2) ^ (v << 7);
    (low ^ fold(high) ^ fold((high >> 127) ^ (high >> 126) ^ (high >> 121))).reverse_bits()
}

#[test]
#[ignore = "requires RV64 scalar carry-less multiplication"]
fn every_basis_pair_and_dense_inputs() -> Result<(), admission::Error> {
    let mut candidate = admission::Candidate::detect();
    candidate.select(admission::Mode::Require)?;
    crate::ghash_field_cases::basis_and_dense(|x, h| candidate.product(x, h))
}

#[test]
#[ignore = "requires RV64 scalar carry-less multiplication"]
fn nist_framed_recurrence() -> Result<(), admission::Error> {
    let mut candidate = admission::Candidate::detect();
    candidate.select(admission::Mode::Require)?;
    crate::ghash_field_cases::framed(|x, h| candidate.product(x, h))
}

#[cfg(brynja_cpu_evidence)]
#[test]
#[ignore = "checks the requested emulated CPU; never supplies capabilities"]
fn check_emulated_extensions() -> Result<(), &'static str> {
    let actual = (
        is_riscv_feature_detected!("zbc"),
        is_riscv_feature_detected!("zbkc"),
    );
    let expected = match std::env::var("BRYNJA_GHASH_RV64_MODEL").as_deref() {
        Ok("both") => (true, true),
        Ok("zbkc") => (false, true),
        Ok("neither") => (false, false),
        _ => return Err("missing emulated extension selection"),
    };
    assert_eq!(actual, expected);
    let aes = (
        is_riscv_feature_detected!("zkne"),
        is_riscv_feature_detected!("zknd"),
    );
    if actual == (false, false) {
        assert_eq!(aes, (true, true));
        let mut candidate = admission::Candidate::detect();
        assert_eq!(
            candidate.select(admission::Mode::Prefer),
            Ok(admission::Route::Portable)
        );
        assert_eq!(
            candidate.select(admission::Mode::Require),
            Err(admission::Error::Unavailable)
        );
        assert_eq!(candidate.product(0, 0), Err(admission::Error::Unavailable));
    } else {
        assert_eq!(aes, (false, false));
    }
    Ok(())
}
