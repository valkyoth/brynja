"""Canonical backend inventory for the CPU-boundary policy."""

BACKENDS = {
    "x86-sha": (
        "X86Sha", "x86_64", "src/x86_sha.rs", ("sha",),
        ("x86_64", "sha-usable-on-current-logical-cpu"),
        "implemented-unadmitted-native-correctness-observed",
    ),
    "x86-sha512-scalar": (
        "ScalarOnlySha512", "x86_64", "absent", (),
        ("x86_64", "no-admitted-single-stream-sha512-kernel"),
        "scalar-only-reviewed",
    ),
    "x86-aes-gcm": (
        "X86AesGcm", "x86_64", "src/x86_aes_gcm.rs", ("aes", "pclmulqdq"),
        ("x86_64", "aes-and-pclmulqdq-usable-on-current-logical-cpu"), "reserved",
    ),
    "x86-avx2": (
        "X86Avx2", "x86_64", "src/x86_avx2_keccak.rs", ("avx2",),
        ("x86_64", "osxsave-and-xcr0-ymm-state", "avx2-usable-on-current-logical-cpu"),
        "implemented-unadmitted-local-correctness-observed",
    ),
    "x86-avx512": (
        "X86Avx512", "x86_64", "src/x86_avx512.rs", ("avx512f",),
        ("x86_64", "osxsave-and-xcr0-zmm-state", "avx512f-usable-on-current-logical-cpu"),
        "reserved",
    ),
    "aarch64-sha2": (
        "Aarch64Sha2", "aarch64", "src/aarch64_sha2.rs", ("neon", "sha2"),
        ("aarch64", "neon-and-sha2-usable-on-current-logical-cpu"),
        "implemented-unadmitted-native-correctness-observed",
    ),
    "aarch64-sha512": (
        "Aarch64Sha512", "aarch64", "src/aarch64_sha2.rs", ("neon", "sha3"),
        ("aarch64", "neon-and-sha3-usable-on-current-logical-cpu"),
        "implemented-unadmitted-native-correctness-observed",
    ),
    "aarch64-aes-gcm": (
        "Aarch64AesGcm", "aarch64", "src/aarch64_aes_gcm.rs",
        ("neon", "aes", "pmull"),
        ("aarch64", "neon-aes-and-pmull-usable-on-current-logical-cpu"), "reserved",
    ),
    "aarch64-sha3-keccak": (
        "Aarch64Sha3", "aarch64", "src/aarch64_sha3_keccak.rs", ("neon", "sha3"),
        ("aarch64", "neon-and-sha3-usable-on-current-logical-cpu"),
        "implemented-unadmitted-qemu-correctness-observed",
    ),
    "riscv-vector": (
        "RiscVVector", "riscv", "src/riscv_vector.rs", ("zvknha",),
        ("riscv64", "ratified-vector-crypto", "vector-state-enabled",
         "zvknha-usable-on-current-hart"),
        "reserved",
    ),
    "riscv-scalar-crypto": (
        "RiscVScalarCrypto", "riscv", "src/riscv64_zknh.rs", ("zknh",),
        ("riscv64", "zknh-usable-on-current-hart"),
        "implemented-unadmitted-native-isa-unavailable",
    ),
    "riscv-sha512": (
        "RiscVScalarCrypto", "riscv", "src/riscv64_zknh.rs", ("zknh",),
        ("riscv64", "zknh-usable-on-current-hart"),
        "implemented-unadmitted-native-isa-unavailable",
    ),
    "riscv-keccak-scalar": (
        "ScalarOnlyKeccak", "riscv", "absent", (),
        ("riscv64", "no-ratified-keccak-instruction-in-pinned-authorities"),
        "scalar-only-reviewed",
    ),
}
