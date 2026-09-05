#!/usr/bin/env bash
set -euo pipefail

release_tmp="$(mktemp "${TMPDIR:-/tmp}/brynja-release-plan.XXXXXX")"
version_tmp="$(mktemp "${TMPDIR:-/tmp}/brynja-version-plan.XXXXXX")"
trap 'rm -f "$release_tmp" "$version_tmp"' EXIT HUP INT TERM

cp docs/RELEASE_PLAN.md "$release_tmp"
cp docs/VERSION_PLAN.md "$version_tmp"
python3 scripts/release/check-release-plan.py "$release_tmp" "$version_tmp"
python3 scripts/release/test-catalogue-plan.py
python3 scripts/release/test-expansion-plan.py
python3 scripts/release/test-roadmap-schedule.py

sed -i '0,/Status: planned/{/Status: planned/d;}' "$release_tmp"
if python3 scripts/release/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted a missing Status field" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/Plan scope: Preserve/s//Plan scope: Alter/' "$release_tmp"
if python3 scripts/release/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted scope drift" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/### v0\.2\.0 - /s/- /- Altered /' "$release_tmp"
if python3 scripts/release/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted title drift" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/Run pentest for this release candidate and commit the updated report\./s//Run review./' "$release_tmp"
if python3 scripts/release/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted a missing historical checkpoint exit" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/v0\.11\.0 development milestone reached/{s/development milestone reached/internal release reached/;}' "$release_tmp"
if python3 scripts/release/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted an invalid internal-stop exit" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/v0\.15\.0 scheduled release checkpoint reached/{s/scheduled release checkpoint reached/internal implementation stop reached/;}' "$release_tmp"
if python3 scripts/release/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted an invalid scheduled-checkpoint exit" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/- implement the Plan scope exactly/{/- implement the Plan scope exactly/d;}' "$release_tmp"
sed -i '0,/- make policy executable/{/- make policy executable/d;}' "$release_tmp"
sed -i '0,/- record that no normative/{/- record that no normative/d;}' "$release_tmp"
if python3 scripts/release/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted too few deliverables" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/### v0\.162\.0 /{/### v0\.162\.0 /d;}' "$release_tmp"
if python3 scripts/release/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted a missing version" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/### v0\.3\.2 /{/### v0\.3\.2 /d;}' "$release_tmp"
if python3 scripts/release/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted a missing patch milestone" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/### v0\.11\.2 /{/### v0\.11\.2 /d;}' "$release_tmp"
if python3 scripts/release/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted a missing sanitization milestone" >&2
    exit 1
fi

python3 - <<'PY'
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, "scripts/release")
spec = importlib.util.spec_from_file_location("release_plan", "scripts/release/check-release-plan.py")
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)
entries = plan.version_entries(Path("docs/VERSION_PLAN.md"))
plan.validate_api_closure(entries)

def rejected(candidate):
    try:
        plan.validate_api_closure(candidate)
    except ValueError:
        return
    raise AssertionError("operation-direction validator accepted a regression")

cases = 0
for prerequisite, consumer in plan.API_CLOSURE_EDGES:
    rejected([row for row in entries if row[0] != prerequisite])
    moved = list(entries)
    left = next(i for i, row in enumerate(moved) if row[0] == prerequisite)
    right = next(i for i, row in enumerate(moved) if row[0] == consumer)
    moved[left], moved[right] = moved[right], moved[left]
    rejected(moved)
    cases += 2

for version, tokens in plan.API_SCOPE_CONTRACTS.items():
    for token in tokens:
        # Mutate the shared scope, as if BOTH plans had weakened together.
        rejected([(v, title, scope.replace(token, "omitted")) if v == version
                  else (v, title, scope) for v, title, scope in entries])
        cases += 1
print(f"public API roadmap closure rejects {cases} dependency and paired-operation regressions")
PY
