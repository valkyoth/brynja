#!/usr/bin/env sh
set -eu

fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-shell-syntax.XXXXXX")"
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

posix_script="$fixture_dir/valid-sh.sh"
bash_script="$fixture_dir/valid-bash.sh"
invalid_script="$fixture_dir/invalid-bash.sh"
missing_shebang="$fixture_dir/missing-shebang.sh"

printf '%s\n' '#!/usr/bin/env sh' 'value="valid"' > "$posix_script"
printf '%s\n' '#!/usr/bin/env bash' 'values=(valid bash)' > "$bash_script"
printf '%s\n' '#!/usr/bin/env bash' 'values=(' > "$invalid_script"
printf '%s\n' 'value="no interpreter"' > "$missing_shebang"

scripts/check_shell_syntax.sh "$posix_script" "$bash_script"

if scripts/check_shell_syntax.sh "$invalid_script" >/dev/null 2>&1; then
    echo "shell syntax validator accepted invalid Bash syntax" >&2
    exit 1
fi

if scripts/check_shell_syntax.sh "$missing_shebang" >/dev/null 2>&1; then
    echo "shell syntax validator accepted a missing shebang" >&2
    exit 1
fi

echo "shell syntax validation respects each script interpreter"
