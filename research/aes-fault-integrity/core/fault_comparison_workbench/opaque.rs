//! Candidate fixed-work leaves. Callers, decisions and fault sites unqualified.

/// # Safety
/// Output covers two live writable bytes disjoint from all inputs. Each input
/// covers sixteen live readable bytes; inputs may alias each other. This leaf
/// uses only baseline instructions on its compiled architecture. No secret
/// dereference outside offsets 0..16 occurs. Working registers/flags are cleared
/// on normal return only; callers, interruption and compiler copies are excluded.
#[inline(never)]
pub(super) unsafe extern "C" fn forward(
    output: *mut u8,
    observed: *const u8,
    primary: *const u8,
    secondary: *const u8,
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Fixed public index runs 0..15; two output stores at 0/1. Early
    // clobbers exclude all pointers. No calls, stack use or data-dependent jumps.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_FAULT_COMPARE_FORWARD_BEGIN",
            "xor ecx, ecx", "xor r9d, r9d", "xor r10d, r10d",
            "2:",
            "movzx eax, byte ptr [{observed} + rcx]",
            "movzx edx, byte ptr [{primary} + rcx]",
            "xor dl, al", "or r9b, dl",
            "movzx r8d, byte ptr [{secondary} + rcx]",
            "xor r8b, al", "or r10b, r8b",
            "inc ecx", "cmp ecx, 16", "jb 2b",
            "mov byte ptr [{output}], r9b", "mov byte ptr [{output} + 1], r10b",
            "# BRYNJA_FAULT_COMPARE_FORWARD_ERASE",
            "xor eax, eax", "xor ecx, ecx", "xor edx, edx",
            "xor r8d, r8d", "xor r9d, r9d", "xor r10d, r10d",
            "# BRYNJA_FAULT_COMPARE_FORWARD_END",
            output=in(reg) output, observed=in(reg) observed, primary=in(reg) primary, secondary=in(reg) secondary,
            out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Same 16-byte public loop and two output stores. Early clobbers
    // exclude every pointer. No calls or stack accesses in the opaque boundary.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_FAULT_COMPARE_FORWARD_BEGIN",
            "mov x4, xzr", "mov x7, xzr", "mov x8, xzr",
            "2:",
            "ldrb w5, [{observed}, x4]", "ldrb w6, [{primary}, x4]",
            "eor w6, w6, w5", "orr w7, w7, w6",
            "ldrb w6, [{secondary}, x4]", "eor w6, w6, w5", "orr w8, w8, w6",
            "add x4, x4, #1", "cmp x4, #16", "b.lo 2b",
            "strb w7, [{output}]", "strb w8, [{output}, #1]",
            "// BRYNJA_FAULT_COMPARE_FORWARD_ERASE",
            "mov x4, xzr", "mov x5, xzr", "mov x6, xzr", "mov x7, xzr", "mov x8, xzr", "cmp xzr, xzr",
            "// BRYNJA_FAULT_COMPARE_FORWARD_END",
            output=in(reg) output, observed=in(reg) observed, primary=in(reg) primary, secondary=in(reg) secondary,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, options(nostack),
        );
    }
}

/// # Safety
/// Identical pointer/length/disjointness requirements to `forward`. Visits
/// offsets 15 down to 0. No memory access occurs at offset 16 or below zero.
/// The resulting masks are private observations, NOT release authorization.
#[inline(never)]
pub(super) unsafe extern "C" fn reverse(
    output: *mut u8,
    observed: *const u8,
    primary: *const u8,
    secondary: *const u8,
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Decrement precedes each load, starting at 16 and ending at zero;
    // the branch uses only the public index. Early clobbers exclude all pointers.
    unsafe {
        core::arch::asm!(
            "# BRYNJA_FAULT_COMPARE_REVERSE_BEGIN",
            "mov ecx, 16", "mov r9d, 255", "mov r10d, 255",
            "2:", "dec ecx",
            "movzx eax, byte ptr [{observed} + rcx]", "not al",
            "movzx edx, byte ptr [{primary} + rcx]", "xor dl, al", "and r9b, dl",
            "movzx r8d, byte ptr [{secondary} + rcx]", "xor r8b, al", "and r10b, r8b",
            "test ecx, ecx", "jnz 2b",
            "mov byte ptr [{output}], r9b", "mov byte ptr [{output} + 1], r10b",
            "# BRYNJA_FAULT_COMPARE_REVERSE_ERASE",
            "xor eax, eax", "xor ecx, ecx", "xor edx, edx",
            "xor r8d, r8d", "xor r9d, r9d", "xor r10d, r10d",
            "# BRYNJA_FAULT_COMPARE_REVERSE_END",
            output=in(reg) output, observed=in(reg) observed, primary=in(reg) primary, secondary=in(reg) secondary,
            out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Public countdown is decremented before each byte load. Accumulator
    // masks remain bounded to eight bits; only byte stores escape this boundary.
    unsafe {
        core::arch::asm!(
            "// BRYNJA_FAULT_COMPARE_REVERSE_BEGIN",
            "mov x4, #16", "mov w7, #255", "mov w8, #255",
            "2:", "sub x4, x4, #1",
            "ldrb w5, [{observed}, x4]", "mvn w5, w5",
            "ldrb w6, [{primary}, x4]", "eor w6, w6, w5", "and w7, w7, w6",
            "ldrb w6, [{secondary}, x4]", "eor w6, w6, w5", "and w8, w8, w6",
            "cbnz x4, 2b",
            "strb w7, [{output}]", "strb w8, [{output}, #1]",
            "// BRYNJA_FAULT_COMPARE_REVERSE_ERASE",
            "mov x4, xzr", "mov x5, xzr", "mov x6, xzr", "mov x7, xzr", "mov x8, xzr", "cmp xzr, xzr",
            "// BRYNJA_FAULT_COMPARE_REVERSE_END",
            output=in(reg) output, observed=in(reg) observed, primary=in(reg) primary, secondary=in(reg) secondary,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, options(nostack),
        );
    }
}
