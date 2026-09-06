#!/usr/bin/env bash
set -euo pipefail
temporary="$(mktemp -d /tmp/brynja-sha1-cpu-codegen.XXXXXX)"
trap 'rm -rf -- "$temporary"' EXIT
for compiler in 1.90.0 1.98.1; do
    for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
        output="$temporary/$compiler-$target"
        CARGO_TARGET_DIR="$output" RUSTFLAGS='--cfg brynja_sha1_cpu_evidence' \
            cargo "+$compiler" rustc --locked --release -p brynja-legacy-sha1 \
            --features cpu,cpu-evidence --target "$target" --lib -- --emit=asm
        mapfile -t files < <(find "$output" -name '*.s' -type f)
        test "${#files[@]}" -eq 1
        if test "$target" = x86_64-unknown-linux-gnu; then
            instructions=(sha1msg1 sha1msg2 sha1nexte sha1rnds4)
        else
            instructions=(sha1c sha1p sha1m sha1h sha1su0 sha1su1)
        fi
        for instruction in "${instructions[@]}"; do
            grep -Eq "^[[:space:]]+$instruction([.][[:alnum:]]+)?[[:space:]]" "${files[0]}" || {
                echo "$compiler/$target omitted $instruction" >&2
                exit 1
            }
        done
    done
done
echo 'SHA-1 schedule and round instructions present at both compiler endpoints; no admission or cleanup qualification'
