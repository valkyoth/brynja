#!/usr/bin/env bash
set -euo pipefail
temporary="$(mktemp -d /tmp/brynja-md5-cpu-codegen.XXXXXX)"
trap 'rm -rf -- "$temporary"' EXIT
for compiler in 1.90.0 1.98.1; do
    for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
        output="$temporary/$compiler-$target"
        CARGO_TARGET_DIR="$output" RUSTFLAGS='--cfg brynja_md5_cpu_evidence' \
            cargo "+$compiler" rustc --locked --release -p brynja-legacy-md5 \
            --features cpu,cpu-evidence --target "$target" --lib -- --emit=asm
        mapfile -t files < <(find "$output" -name '*.s' -type f)
        test "${#files[@]}" -eq 1
        if test "$target" = x86_64-unknown-linux-gnu; then
            instructions=(vpaddd vpsllvd vpsrlvd)
        else
            instructions=(add ushl)
        fi
        for instruction in "${instructions[@]}"; do
            grep -Eq "^[[:space:]]+$instruction([.][[:alnum:]]+)?[[:space:]]" "${files[0]}" || {
                echo "$compiler/$target omitted $instruction" >&2
                exit 1
            }
        done
    done
done
echo 'MD5 vector arithmetic and shift instructions present at both compiler endpoints; no admission or cleanup qualification'
