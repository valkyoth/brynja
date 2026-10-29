#!/usr/bin/env python3
"""Selection, approval, command execution and evidence-reuse regressions."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shlex
import subprocess
import tempfile
import tomllib
from pathlib import Path
from unittest.mock import patch

import verification_commands as commands
import verification_plan as plans
import miri_dependencies


def rejects(function, *args) -> None:
    try:
        function(*args)
    except (ValueError, PermissionError):
        return
    raise AssertionError("unsafe verification plan accepted")


def sample(*, blocked=False, public=False, groups=()) -> dict:
    return {
        "fingerprint": "a" * 64, "approval_required": blocked,
        "stage": "public" if public else "internal", "groups": list(groups),
        "verifiers": {k: list(groups) for k in ("asan", "miri", "kani")},
    }


def approval_tests() -> None:
    plans.authorize(sample(), None)
    plans.authorize(sample(public=True), None)
    rejects(plans.authorize, sample(blocked=True), None)
    rejects(plans.authorize, sample(blocked=True), "b" * 64)
    plans.authorize(sample(blocked=True), "a" * 64)
    rejects(plans.authorize, sample(), "b" * 64)
    assert not plans.environment_issues({"RUSTUP_TOOLCHAIN": "1.98.1", "CARGO_HOME": "/cache", "CARGO_TARGET_DIR": "/build"}, "1.98.1")
    for name in ("RUSTFLAGS", "MIRIFLAGS", "ASAN_OPTIONS", "RUSTC_WRAPPER", "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS"):
        assert plans.environment_issues({name: "override"}, "1.98.1")
    assert plans.environment_issues({"RUSTUP_TOOLCHAIN": "nightly"}, "1.98.1")


def selection_tests() -> None:
    catalog = commands.repository_commands()
    assert len(catalog) > 150
    selected = commands.selected(catalog, ["sha2"])
    assert "python3 scripts/sha2/check-sha2-execution.py" in selected
    assert "python3 scripts/sha2/check-general-sha512-t.py" in selected
    assert "python3 scripts/md5/check-md5-differential.py" not in selected
    assert "python3 scripts/sha3/check-sha3-bit-differential.py" not in selected
    assert "python3 scripts/release/test-verification-plan.py" in selected
    # Large generated metadata is never an exemption from its validators.
    for name in ('check-protocol-surfaces', 'test-protocol-surfaces',
                 'check-standards-ledger', 'check-requirements'):
        assert 'python3 scripts/standards/' + name + '.py' in commands.selected(catalog, [])
    for name in ('check-zeroization-evidence.py', 'test-zeroization-evidence.py'):
        assert 'python3 scripts/zeroization/' + name in commands.selected(catalog, [])
    assert commands.selected(catalog, [], full=True) == catalog
    for name in ('test-mir-cleanup-flow', 'test-secret-owner-compiler',
                 'check-secret-owner-compiler', 'check-api-profiles', 'test-api-profiles'):
        assert 'python3 scripts/cryptography/' + name + '.py' in commands.selected(catalog, [])
    assert commands.owners("python3 scripts/kmac/check-kmac.py") == set()
    from scope_review_metadata import BASE_COMMANDS as review_commands, SCRIPT_COMMANDS
    for command in review_commands:
        assert command in catalog
        assert command in commands.selected(catalog, [])
        assert commands.owners(command) == set()
        with patch.object(commands, 'catalog', return_value=[c for c in catalog if c != command]):
            rejects(commands.repository_commands)
    for checks in SCRIPT_COMMANDS.values():
        assert set(checks) <= review_commands
    # Never infer 'unchanged' from an unregistered script/package/command.
    for command in ("python3 scripts/new/new.py", "cargo test -p unknown",
                    "cargo run --manifest-path assurance/unknown/Cargo.toml", "unknown"):
        rejects(commands.owners, command)
    matrix = commands.matrix_commands()
    selected_matrix = [c for c, _ in matrix if commands.selected([c], ["sha2"])]
    # Bind to the independently checked coverage matrix, not a stale count.
    # Exact membership also catches substitution of one compiler for another.
    coverage = tomllib.loads((plans.ROOT / 'assurance/zeroization-matrix.toml').read_text())
    expected = {'+' + version for version in coverage['coverage']['compilers']}
    selected_versions = {shlex.split(c)[1] for c in selected_matrix}
    assert selected_versions == expected
    assert '+1.99.0' in selected_versions
    for version in expected:
        per_version = [c for c in selected_matrix if shlex.split(c)[1] == version]
        assert any('sha256-public-api' in c for c in per_version)
        assert any('sha2-public-api' in c for c in per_version)
        assert any('general-sha512-t' in c for c in per_version)
    assert any("general-sha512-t" in c for c in selected_matrix)
    assert not any("legacy-md5" in c or "sha3-public-api" in c for c in selected_matrix)
    assert plans.scope.closure({"sha3"}) == ("sha3", "kmac", "tuplehash", "parallelhash", "hmac")
    assert "sha2" in plans.scope.closure({"static_cpu"})
    assert "md5" not in plans.scope.closure({"sha2"})
    assert "md5" in plans.scope.select(["security/md5-cpu-admissions.toml"])[1]
    assert "sha1" in plans.scope.select(["security/sha1-cpu-admissions.toml"])[1]
    assert "static_cpu" in plans.scope.select(["security/cpu-backend-admissions.toml"])[1]
    sanitizer = commands.catalog(plans.ROOT / "scripts/zeroization/check-zeroization-sanitizer.sh")
    for group in ('sha2', 'sha3', 'parallelhash', 'static_cpu'):
        chosen = commands.selected(sanitizer, [group])
        assert not any('brynja-legacy-' in command for command in chosen)
    assert any('brynja-legacy-md5' in command for command in commands.selected(sanitizer, ['md5']))
    assert "sha3" in plans.scope.select(["scripts/hash/final-acceptance.py"])[1]
    assert plans.scope.select(["assurance/unregistered/oracle.py"])[0]
    assert plans.scope.select(["scripts/unregistered/check.py"])[0]
    for name in ('check-constant-time-evidence.py', 'test-constant-time-evidence.py'):
        assert 'python3 scripts/constant-time/' + name in commands.selected(catalog, [])
    for command in ('python3 scripts/cryptography/check-windows-enclave-lifecycle.py',
                    'cargo test -p brynja-strict'):
        assert commands.owners(command) == {'static_cpu', 'sha2', 'sha3', 'kmac', 'tuplehash', 'parallelhash'}


def miri_dependency_tests():
    raw = (plans.ROOT / 'Cargo.lock').read_bytes()
    # SHA-3 now consumes CPU authorities. Current CPU changes must select it.
    assert 'sha3' in plans.scope.closure(
        {'static_cpu'}, downstream=miri_dependencies.graph(raw, raw))
    # Construct an explicitly pre-integration graph. Removing only SHA-3's
    # edge no longer models portable-only owners: ParallelHash now has its
    # own optional hosted edge and CPU test dependencies.
    for name in miri_dependencies.PORTABLE_ROOTS:
        start = raw.index(('name = "' + name + '"\n').encode())
        end = raw.find(b'[[package]]', start)
        end = len(raw) if end < 0 else end
        record = raw[start:end]
        portable = record.replace(b' "brynja-crypto-cpu",\n', b'').replace(b' "brynja-crypto-cpu-std",\n', b'')
        raw = raw[:start] + portable + raw[end:]
    edges = miri_dependencies.graph(raw, raw)
    assert plans.scope.closure({'static_cpu'}, downstream=edges) == ('sha2', 'static_cpu', 'hmac', 'legacy_hmac')
    assert plans.scope.closure({'sha3'}, downstream=edges) == ('sha3', 'kmac', 'tuplehash', 'parallelhash', 'hmac')
    assert 'sha3' in plans.scope.closure({'core'}, downstream=edges)
    import tomllib
    data = tomllib.loads(raw.decode())
    # Add a new optional-or-required CPU edge through each portable family.
    for name in miri_dependencies.PORTABLE_ROOTS:
        needle = ('name = "' + name + '"\n').encode()
        start = raw.index(needle)
        end = raw.find(b'[[package]]', start)
        record = raw[start:end]
        assert b'dependencies = [' in record
        changed = raw[:start] + record.replace(b'dependencies = [', b'dependencies = [\n "brynja-crypto-cpu",', 1) + raw[end:]
        for before, after in ((raw, changed), (changed, raw)):
            assert 'sha3' in plans.scope.closure({'static_cpu'}, downstream=miri_dependencies.graph(before, after))
    rejects(miri_dependencies.graph, raw, raw.replace(b'name = "brynja-hash-sha3"', b'name = "missing-root"'))
    rejects(miri_dependencies.graph, raw, b'broken TOML =')
    for broken in (None, b'broken TOML ='):
        issues = []
        with patch.object(miri_dependencies.inputs, 'snapshot', return_value=(raw, broken)):
            full, groups = miri_dependencies.select(plans.ROOT, 'v0.24.33', issues)
        assert full and groups == plans.scope.GROUPS and issues
    assert data['version'] == 4


def parser_tests() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "catalog.sh"
        for text in ("cargo test; true", "if true; then", "cargo test | true",
                     "cargo $(echo test)", "cargo test\ncargo test", "echo ignored"):
            path.write_text(text)
            rejects(commands.catalog, path)
        path.write_text("#!/bin/sh\nset -eu\ncargo test --workspace\n")
        assert commands.catalog(path) == ["cargo test --workspace"]


def runner_tests() -> None:
    spec = importlib.util.spec_from_file_location("verification_runner", plans.ROOT / "scripts/release/run-verification.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    executed = []

    def run(phase, plan, *args, environment=None):
        executed.clear()
        with (patch.object(runner.plans, "build", return_value=plan),
              patch.object(runner.sys, "argv", ["runner", phase, *args]),
              patch.object(runner, "execute", side_effect=lambda *c: executed.append(c)),
              patch.dict(runner.os.environ, environment or {}, clear=True),
              contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
            return runner.main()

    for phase in ("repository", "asan", "miri", "kani", "matrix"):
        assert run(phase, sample(blocked=True)) == 3
        assert not executed
        assert run(phase, sample(blocked=True), "--approve-full", "b" * 64) == 1
        assert not executed
    assert run("repository", sample(blocked=True), "--approve-full", "a" * 64) == 0
    assert any("scripts/md5/check-md5-differential.py" in c[0] for c in executed)
    assert run("repository", sample(groups=("sha2",))) == 0
    assert any("sha2-execution" in c[0] for c in executed)
    assert not any("md5-differential" in c[0] for c in executed)
    assert run("miri", sample(groups=("sha2",))) == 0
    from miri_tasks import commands as miri_commands
    assert executed == [(shlex.join(argv),) for argv in miri_commands(plans.ROOT, ["sha2"], "routine")]
    assert run("miri", sample()) == 0 and not executed
    assert run("matrix", sample()) == 0 and not executed
    assert run("kani", sample(groups=("sha2",))) == 0
    assert executed == [("scripts/assurance/check-kani.sh --required-groups sha2",)]
    assert run("asan", sample(groups=("sha2",))) == 0
    assert executed and not any("brynja-legacy-md5" in c[0] for c in executed)
    miri_only = {**sample(blocked=True), 'full_phases': ['miri'],
                 'verifiers': {'miri': list(plans.scope.GROUPS), 'asan': [], 'kani': []}}
    for phase in ('asan', 'matrix'):
        assert run(phase, miri_only, '--approve-full', 'a' * 64) == 0
        assert not executed
    assert run('kani', miri_only, '--approve-full', 'a' * 64) == 0
    assert executed == [('scripts/assurance/check-kani.sh --policy-only',)]
    assert run('miri', miri_only, '--approve-full', 'a' * 64) == 0
    assert len(executed) == 697
    assert run("repository", sample(public=True)) == 0
    assert any("md5-differential" in c[0] for c in executed)
    with patch.object(commands, "matrix_commands", side_effect=ValueError("unknown matrix")):
        assert run("repository", sample()) == 1 and not executed
    with patch.object(commands, "catalog", side_effect=ValueError("unknown sanitizer")):
        assert run("repository", sample()) == 1 and not executed
    # CI must ignore stale repository variables, never grant release approval,
    # and never turn unresolved scope into an automatic full campaign.
    stale = {"BRYNJA_FULL_VERIFICATION_APPROVAL": "b" * 64}
    with patch.object(runner.push_ci, 'run', return_value=0) as diagnostics:
        assert run('plan', sample(), '--check', '--ci', environment=stale) == 0
        diagnostics.assert_called_once_with(check=True)
        diagnostics.reset_mock()
        assert run('repository', sample(blocked=True), '--ci', environment=stale) == 0
        diagnostics.assert_called_once_with(check=False)
        assert not executed  # Never fall through to the release catalog.
        diagnostics.reset_mock()
        assert run('repository', sample(), '--ci', '--base', 'a' * 40) == 1
        diagnostics.assert_not_called()
        for environment in ({'BRYNJA_DETACHED_JOB': '/old', 'BRYNJA_DETACHED_RECEIPT': 'hash'},
                            {'BRYNJA_DETACHED_RECEIPTS': '/registry'}):
            assert run('repository', sample(), '--ci', environment=environment) == 1
            diagnostics.assert_not_called()
    # A CI invocation cannot leak authorization into later release execution.
    assert run("repository", sample(blocked=True), environment=stale) == 1 and not executed
    assert run("repository", sample(blocked=True)) == 3 and not executed
    for phase, extra in (("asan", ()), ("miri", ()), ("kani", ()), ("matrix", ()),
                         ("command", ()), ("repository", ("--approve-full", "a" * 64))):
        try:
            run(phase, sample(), "--ci", *extra)
        except SystemExit as error:
            assert error.code == 2 and not executed
        else:
            raise AssertionError("CI option admitted a release-only operation")
    with patch.object(runner.push_ci, "run", side_effect=subprocess.CalledProcessError(1, "test")):
        # The run helper mocks execution; check real main separately so failed
        # tests remain failures, not diagnostic success or evidence reuse.
        with (patch.object(runner.plans, "build", return_value=sample()),
              patch.object(runner.sys, "argv", ["runner", "repository", "--ci"]),
              contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
            assert runner.main() == 1
    executed.clear()
    with (patch.object(runner.subprocess, "check_output", return_value="1.90.0-x86_64-unknown-linux-gnu (default)\n"),
          patch.object(runner, "execute", side_effect=executed.append)):
        runner.prepare_matrix([("cargo +1.90.0 test -p brynja-hash-sha2", None),
                               ("cargo +1.98.1 test -p brynja-hash-sha2", None)])
    assert executed == ["rustup toolchain install 1.98.1 --profile minimal"]


def nested_fixture_tests() -> None:
    root = plans.ROOT
    outer = root / "assurance/sha2-execution"
    nested = root / "assurance/general-sha512-t"
    args = ((outer / "Cargo.lock").read_bytes(), (root / "Cargo.lock").read_bytes(),
            (outer / "Cargo.toml").read_bytes(),
            ((nested / "Cargo.lock").read_bytes(), (nested / "Cargo.toml").read_bytes()))
    plans.inputs.fixture_lock(*args)
    rejects(plans.inputs.fixture_lock, *args[:3])
    corrupt = args[0].replace(b'name = "brynja-core"', b'name = "unreviewed"')
    rejects(plans.inputs.fixture_lock, corrupt, *args[1:])


def entrypoint_tests() -> None:
    # Release preflight and ordinary CI are distinct entrypoints.
    tag = (plans.ROOT / "scripts/tag_gate.sh").read_text()
    preflight = "python3 scripts/release/run-verification.py plan --check"
    assert tag.index(preflight) < tag.index("\nscripts/checks.sh")
    for phase in ("asan", "kani"):
        assert f"python3 scripts/release/run-verification.py {phase}" in tag
    ci = (plans.ROOT / ".github/workflows/ci.yml").read_text()
    assert ci.index(preflight + " --ci") < ci.index("- name: Install Rust toolchain")
    assert "BRYNJA_FULL_VERIFICATION_APPROVAL" not in ci
    assert "run: scripts/checks.sh --ci\n" in ci
    assert "--ci" not in tag
    assert "exec python3 scripts/release/run-verification.py repository" in (plans.ROOT / "scripts/checks.sh").read_text()


def fingerprint_tests() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "release-crates.toml").write_text("[release]\n")
        path = root / "source.rs"
        path.write_text("first")
        with patch.object(plans.inputs, "git", return_value=b"object"):
            original = plans.fingerprint(root, "v0.24.33", ["source.rs"])
            path.write_text("second")
            assert original != plans.fingerprint(root, "v0.24.33", ["source.rs"])
            path.write_text("first")
            with patch.dict(os.environ, {"RUSTFLAGS": "-C opt-level=1"}):
                assert original != plans.fingerprint(root, "v0.24.33", ["source.rs"])
            assert original != plans.fingerprint(root, "v0.24.32", ["source.rs"])
            with patch.object(plans, "FINGERPRINT_INPUT_LIMIT", 4):
                rejects(plans.fingerprint, root, "v0.24.33", ["source.rs"])
            rejects(plans.fingerprint, root, "v0.24.33", ["../escape"])
            path.unlink()
            assert original != plans.fingerprint(root, "v0.24.33", ["source.rs"])
            if os.name != "nt":
                path.symlink_to(root / "release-crates.toml")
                rejects(plans.fingerprint, root, "v0.24.33", ["source.rs"])


def kani_dispatch_tests() -> None:
    if os.name == "nt":
        return  # Native shell trace is exercised by the Linux repository CI job.
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fake = root / "rustup"
        fake.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
if args == ["toolchain", "list"]:
    print("1.90.0-x86_64-unknown-linux-gnu")
elif args[-1:] == ["--version"]:
    print(os.environ.get("KANI_BANNER", "Kani Rust Verifier 0.68.0 (cargo plugin)\\nCBMC 6.11.0"))
else:
    with pathlib.Path(os.environ["TRACE"]).open("a") as output:
        output.write(json.dumps(args) + "\\n")
    if os.environ.get("FAIL_PACKAGE", "missing") in args:
        sys.exit(42)
''')
        fake.chmod(0o700)
        trace = root / "trace"
        env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], TRACE=str(trace))
        def run(*args, fail="", banner="Kani Rust Verifier 0.68.0 (cargo plugin)\nCBMC 6.11.0"):
            trace.write_text("")
            result = subprocess.run(["bash", "scripts/assurance/check-kani.sh", *args],
                                    cwd=plans.ROOT, env=dict(env, FAIL_PACKAGE=fail, KANI_BANNER=banner),
                                    capture_output=True, text=True, timeout=30)
            return result.returncode, [json.loads(line) for line in trace.read_text().splitlines()]
        status, calls = run("--required-groups", "sha2")
        assert status == 0 and len(calls) == 2
        assert calls[0] == ["run", "1.90.0-x86_64-unknown-linux-gnu", "cargo", "kani", "-p",
                            "brynja-hash-sha2", "--features", "batch-execution"]
        assert calls[1] == ["run", "1.90.0-x86_64-unknown-linux-gnu", "cargo", "kani", "-p",
                            "brynja-hash-sha2", "--features", "batch512-execution", "--harness",
                            "batch512::control::proofs::batch_budget_is_atomic_and_never_wraps"]
        for banner in ("cargo-kani 0.67.0", "Kani Rust Verifier 0.67.0 (cargo plugin)\nCBMC 6.11.0",
                       "Kani Rust Verifier 0.68.0 (cargo plugin)",
                       "Kani Rust Verifier 0.68.0 (cargo plugin)\nCBMC 0.0.0"):
            status, calls = run("--required-groups", "sha2", banner=banner)
            assert status != 0 and not calls
        status, calls = run("--required")
        assert status == 0 and len(calls) == 9
        status, calls = run("--required-groups", "sha3")
        assert status == 0 and len(calls) == 2
        assert calls[1] == ["run", "1.90.0-x86_64-unknown-linux-gnu", "cargo", "kani", "-p",
                            "brynja-hash-sha3", "--features", "batch-execution", "--harness",
                            "batch::control::proofs::batch_budget_is_atomic_and_never_wraps"]
        status, calls = run("--required-groups", "sha2", fail="brynja-hash-sha2")
        assert status == 42 and len(calls) == 1
        status, calls = run("--required-groups", "unknown")
        assert status == 2 and not calls
        status, calls = run("--required-groups")
        assert status == 2 and not calls


def main() -> None:
    from verification_policy_tests import run as policy_tests
    policy_tests()
    approval_tests()
    selection_tests()
    miri_dependency_tests()
    parser_tests()
    runner_tests()
    nested_fixture_tests()
    entrypoint_tests()
    fingerprint_tests()
    kani_dispatch_tests()
    compiler_matrix_scope_tests()
    additive_review_scope_tests()
    # Keep push-selection regressions in qualification too, without duplicating
    # the expensive release catalog in push CI.
    spec = importlib.util.spec_from_file_location('push_ci_tests', plans.ROOT / 'scripts/release/test-push-ci.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()
    print("Incremental verification: ownership, checkpoint, nested-fixture, approval and no-launch regressions PASS")


def additive_review_scope_tests():
    old = b'REVIEWED_SOURCE_PATHS = {"crates/brynja-hash-sha3/src/lib.rs"}\nX = 1\n'
    name = 'crates/brynja-hash-sha3/src/hardened/cshake/setup.rs'
    new = old.replace(b'}', (', "' + name + '"}').encode())
    assert plans.inputs.added_review_sources(old, new) == {name}
    assert plans.inputs.added_review_sources(new, old) is None
    assert plans.inputs.added_review_sources(old, new.replace(b'X = 1', b'X = 2')) is None
    assert plans.inputs.added_review_sources(old, new.replace(b'X = 1', b'REVIEWED_SOURCE_PATHS = set()')) is None
    assert plans.inputs.added_review_sources(old, old.replace(b'}', b', 42}')) is None
    assert plans.inputs.added_review_sources(old, old.replace(b'}', b', "crates/brynja-hash-sha3/src/lib.rs"}')) is None
    def selected(raw):
        path = 'scripts/cryptography/api_profile_contracts.py'
        with patch.object(plans.inputs, 'git', side_effect=lambda root,*args:
                          path.encode() if args[0] == 'diff' else b''), \
             patch.object(plans.inputs, 'snapshot', side_effect=lambda r,b,p:
                          (old,raw) if p == path else (None,None)):
            return plans.scope.select_repository('v0.24.49')
    assert selected(new) == (False, ('sha3', 'kmac', 'tuplehash', 'parallelhash', 'hmac'))
    assert selected(new.replace(name.encode(), b'crates/unknown/src/lib.rs'))[0]
    assert 'core' in selected(new.replace(b'X = 1', b'X = 2'))[1]


def compiler_matrix_scope_tests():
    old = b'[coverage]\ncompilers=["1.98.1"]\n[dynamic]\ntoolchain="pinned"\n'
    new = old.replace(b'["1.98.1"]', b'["1.98.1","1.99.0"]')
    matrix = 'assurance/zeroization-matrix.toml'
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'release-crates.toml').write_text('[release]\nversion="0.24.50"\nstage="internal"\n')
        (root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="1.98.1"\n')
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(plans.scope, 'select_repository', return_value=(False, ('sha3', 'kmac'))), \
             patch.object(plans.miri_dependencies, 'select', return_value=(False, ('sha3', 'kmac'))), \
             patch.object(plans, 'changed_paths', return_value=[matrix]), \
             patch.object(plans.inputs, 'snapshot', side_effect=lambda r,b,p:
                          (old,new) if p == matrix else (None,None)), \
             patch.object(plans.inputs, 'git', return_value=b'a' * 40), \
             patch.object(plans, 'fingerprint', return_value='f' * 64):
            plan = plans.build(root, 'v0.24.49')
        assert plan['approval_required']
        assert plan['full_phases'] == ['matrix']
        assert all(g == ['sha3', 'kmac'] for g in plan['verifiers'].values())
        rejects(plans.authorize, plan, None)
        plans.authorize(plan, 'f' * 64)
        assert not plans.requires_full(plan, 'miri')
        assert not plans.requires_full(plan, 'asan')
        assert not plans.requires_full(plan, 'kani')


if __name__ == "__main__":
    main()
