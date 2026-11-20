// Production AES field arithmetic; also compiled directly by bounded proofs.
// Polynomial multiplication modulo x^8+x^4+x^3+x+1. Exactly eight steps.
pub(super) fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0;
    for _ in 0..8 {
        result ^= a & 0u8.wrapping_sub(b & 1);
        a = xtime(a);
        b >>= 1;
    }
    result
}
pub(super) fn xtime(a: u8) -> u8 {
    let reduction = 0x1b;
    #[cfg(all(test, brynja_fault_evidence, brynja_fault_profile_research))]
    let reduction = super::field_fault_fixture::reduction(a, reduction);
    (a << 1) ^ (reduction & 0u8.wrapping_sub(a >> 7))
}

pub(super) fn inverse(a: u8) -> u8 {
    // a^254, with zero mapping to zero. Fixed multiplication chain: no
    // secret-dependent special case for zero and no lookup table.
    let a2 = multiply(a, a);
    let a4 = multiply(a2, a2);
    let a8 = multiply(a4, a4);
    let a16 = multiply(a8, a8);
    let a32 = multiply(a16, a16);
    let a64 = multiply(a32, a32);
    let a128 = multiply(a64, a64);
    multiply(
        multiply(multiply(a2, a4), multiply(a8, a16)),
        multiply(multiply(a32, a64), a128),
    )
}
pub(super) fn sbox(a: u8) -> u8 {
    let x = inverse(a);
    let affine = 0x63;
    #[cfg(all(test, brynja_fault_evidence, brynja_fault_profile_research))]
    let affine =
        super::field_fault_fixture::affine(super::field_fault_fixture::Site::Forward, affine);
    x ^ x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3) ^ x.rotate_left(4) ^ affine
}
pub(super) fn inv_sbox(a: u8) -> u8 {
    let affine = 0x05;
    #[cfg(all(test, brynja_fault_evidence, brynja_fault_profile_research))]
    let affine =
        super::field_fault_fixture::affine(super::field_fault_fixture::Site::Inverse, affine);
    inverse(a.rotate_left(1) ^ a.rotate_left(3) ^ a.rotate_left(6) ^ affine)
}
