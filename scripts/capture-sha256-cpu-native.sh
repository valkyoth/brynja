#!/usr/bin/env bash
set -euo pipefail

lane="${1:-}"
output="${2:-target/cpu-evidence-native/$lane}"
case "$lane" in
    local-amd-x86_64)
        backend=x86-sha
        architecture=x86_64
        operating_system=linux
        expected_vendor=AuthenticAMD
        required_instruction=sha256rnds2
        ;;
    aws-intel-x86_64)
        backend=x86-sha
        architecture=x86_64
        operating_system=linux
        expected_vendor=GenuineIntel
        required_instruction=sha256rnds2
        ;;
    apple-m2-aarch64)
        backend=aarch64-sha2
        architecture=aarch64
        operating_system=macos
        expected_vendor=Apple
        required_instruction=sha256h
        ;;
    aws-aarch64)
        backend=aarch64-sha2
        architecture=aarch64
        operating_system=linux
        expected_vendor=
        required_instruction=sha256h
        ;;
    riscv64-cloud)
        backend=riscv-scalar-crypto
        architecture=riscv64
        operating_system=linux
        expected_vendor=
        required_instruction=sha256sum0
        ;;
    *)
        echo "native SHA-256 capture requires one registered v0.22.2 lane" >&2
        exit 64
        ;;
esac

workspace="$(git rev-parse --show-toplevel)"
cd "$workspace"
if test -n "$(git status --porcelain=v1 --untracked-files=all)"; then
    echo "native SHA-256 capture requires a clean worktree" >&2
    exit 65
fi
case "$output" in
    /*) ;;
    *) output="$workspace/$output" ;;
esac
if test -e "$output" || test -L "$output"; then
    echo "native SHA-256 capture refuses an existing output path: $output" >&2
    exit 73
fi
mkdir -p "$(dirname "$output")"
mkdir "$output"

host_arch="$(uname -m)"
host_os="$(uname -s)"
if test "$architecture" = x86_64 && test "$host_arch" != x86_64; then
    echo "native SHA-256 capture lane requires x86_64" >&2
    exit 66
fi
if test "$architecture" = aarch64 && test "$host_arch" != aarch64 && test "$host_arch" != arm64; then
    echo "native SHA-256 capture lane requires AArch64" >&2
    exit 66
fi
if test "$architecture" = riscv64 && test "$host_arch" != riscv64; then
    echo "native SHA-256 capture lane requires RISC-V 64-bit" >&2
    exit 66
fi
if test "$operating_system" = linux && test "$host_os" != Linux; then
    echo "native SHA-256 capture lane requires Linux" >&2
    exit 66
fi
if test "$operating_system" = macos && test "$host_os" != Darwin; then
    echo "native SHA-256 capture lane requires macOS" >&2
    exit 66
fi

if test "$host_os" = Linux; then
    vendor="$(awk -F ': *' '/^vendor_id/ { print $2; exit }' /proc/cpuinfo)"
    if test -n "$expected_vendor" && test "$vendor" != "$expected_vendor"; then
        echo "native SHA-256 capture observed unexpected CPU vendor: $vendor" >&2
        exit 66
    fi
    flags="$(awk -F ': *' '/^(flags|Features)/ { print $2; exit }' /proc/cpuinfo)"
    if test "$architecture" = x86_64; then
        printf '%s\n' "$flags" | grep -Eq '(^|[[:space:]])(sha_ni|sha)([[:space:]]|$)' || {
            echo "native SHA-256 capture did not observe x86 SHA instructions" >&2
            exit 66
        }
    elif test "$architecture" = aarch64; then
        printf '%s\n' "$flags" | grep -Eq '(^|[[:space:]])sha2([[:space:]]|$)' || {
            echo "native SHA-256 capture did not observe AArch64 SHA2" >&2
            exit 66
        }
        printf '%s\n' "$flags" | grep -Eq '(^|[[:space:]])(asimd|neon)([[:space:]]|$)' || {
            echo "native SHA-256 capture did not observe AArch64 SIMD" >&2
            exit 66
        }
    else
        isa="$(awk -F ': *' '/^isa/ { print tolower($2); exit }' /proc/cpuinfo)"
        printf '%s\n' "$isa" | grep -Eq '(^|_)zknh([0-9]+p[0-9]+)?(_|$)' || {
            echo "native SHA-256 capture did not observe exact RISC-V Zknh" >&2
            exit 66
        }
    fi
    {
        uname -a
        command -v lscpu >/dev/null 2>&1 && lscpu
        awk 'BEGIN { seen=0 } /^$/ { if (seen) exit } { print; seen=1 }' /proc/cpuinfo
        command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt || true
    } >"$output/host.txt"
else
    vendor=Apple
    if test "$(sysctl -n hw.optional.arm.FEAT_SHA256 2>/dev/null || printf 0)" != 1; then
        echo "native SHA-256 capture did not observe Apple SHA-256 instructions" >&2
        exit 66
    fi
    {
        uname -a
        for key in machdep.cpu.brand_string hw.machine hw.model hw.logicalcpu \
            hw.optional.neon hw.optional.arm.FEAT_SHA256 kern.osversion; do
            sysctl "$key" 2>/dev/null || true
        done
    } >"$output/host.txt"
fi

source_commit="$(git rev-parse --verify HEAD)"
source_tree="$(git rev-parse 'HEAD^{tree}')"
rustc -Vv >"$output/rustc.txt"
cargo -Vv >"$output/cargo.txt"

if test "$architecture" = riscv64; then
    RUSTFLAGS='--cfg brynja_cpu_evidence -C target-feature=+zknh' \
        cargo test --locked -p brynja-hash-sha2 --features cpu \
        --test sha256_accelerated -- --test-threads=1 \
        >"$output/candidate-tests.log" 2>&1
else
    BRYNJA_CPU_EVIDENCE_EXPECTED_BACKEND="$backend" \
    RUSTFLAGS='--cfg brynja_cpu_evidence' \
        cargo test --locked -p brynja-crypto-cpu-std --test sha256_runtime \
        -- --test-threads=1 >"$output/candidate-tests.log" 2>&1
fi

temporary="$(mktemp -d "${TMPDIR:-/tmp}/brynja-native-codegen-XXXXXX")"
cleanup() {
    rm -rf "$temporary"
}
trap cleanup EXIT INT TERM
host_target="$(rustc -vV | sed -n 's/^host: //p')"
CARGO_TARGET_DIR="$temporary/target" cargo rustc --quiet --locked --release \
    -p brynja-crypto-cpu --target "$host_target" --lib -- --emit=asm
assembly="$(find "$temporary/target" -type f -name '*.s' -print)"
assembly_count="$(printf '%s\n' "$assembly" | sed '/^$/d' | wc -l | tr -d ' ')"
if test "$assembly_count" -ne 1; then
    echo "native SHA-256 capture expected exactly one assembly file" >&2
    exit 67
fi
if ! scripts/check-sha256-assembly-instruction.sh \
    "$architecture" "$required_instruction" "$assembly"; then
    echo "native SHA-256 capture omitted $required_instruction" >&2
    exit 67
fi
if test "$architecture" = riscv64; then
    for instruction in sha256sig0 sha256sig1 sha256sum0 sha256sum1; do
        scripts/check-sha256-assembly-instruction.sh \
            "$architecture" "$instruction" "$assembly" || {
            echo "native SHA-256 capture omitted $instruction" >&2
            exit 67
        }
    done
fi
hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}
{
    echo "target=$host_target"
    echo "required_instruction=$required_instruction"
    echo "assembly_sha256=$(hash_file "$assembly")"
    echo "status=pass"
} >"$output/codegen.log"
cleanup
trap - EXIT INT TERM

{
    echo "schema=brynja-sha256-native-candidate-v1"
    echo "source_commit=$source_commit"
    echo "source_tree=$source_tree"
    echo "lane=$lane"
    echo "backend=$backend"
    echo "architecture=$architecture"
    echo "os=$operating_system"
    echo "captured_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "tree_state=clean"
    echo "status=pass"
    echo "authority=non-authorizing-native-candidate-observation"
} >"$output/manifest.txt"

if test -n "$(git status --porcelain=v1 --untracked-files=all)"; then
    echo "native SHA-256 capture source changed during execution" >&2
    exit 65
fi
(
    cd "$output"
    for file in cargo.txt candidate-tests.log codegen.log host.txt manifest.txt rustc.txt; do
        printf '%s  %s\n' "$(hash_file "$file")" "$file"
    done >SHA256SUMS
)
python3 scripts/validate-cpu-evidence-run.py "$output"
echo "native SHA-256 candidate capture wrote $output"
