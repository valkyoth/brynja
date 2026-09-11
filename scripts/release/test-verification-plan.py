#!/usr/bin/env python3
"""Selection, approval, command execution and evidence-reuse regressions."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
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
    for name in ('check-zeroization-evidence.py', 'test-zeroization-evidence.py'):
        assert 'python3 scripts/zeroization/' + name in commands.selected(catalog, [])
    assert commands.selected(catalog, [], full=True) == catalog
    for name in ('test-mir-cleanup-flow', 'test-secret-owner-compiler',
                 'check-secret-owner-compiler', 'check-api-profiles', 'test-api-profiles'):
        assert 'python3 scripts/cryptography/' + name + '.py' in commands.selected(catalog, [])
    assert commands.owners("python3 scripts/kmac/check-kmac.py") == {"kmac"}
    # Never infer 'unchanged' from an unregistered script/package/command.
    for command in ("python3 scripts/new/new.py", "cargo test -p unknown",
                    "cargo run --manifest-path assurance/unknown/Cargo.toml", "unknown"):
        rejects(commands.owners, command)
    matrix = commands.matrix_commands()
    selected_matrix = [c for c, _ in matrix if commands.selected([c], ["sha2"])]
    assert len({c.split()[1] for c in selected_matrix}) == 12
    assert any("general-sha512-t" in c for c in selected_matrix)
    assert not any("legacy-md5" in c or "sha3-public-api" in c for c in selected_matrix)
    assert plans.scope.closure({"sha3"}) == ("sha3", "kmac", "tuplehash", "parallelhash")
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


def miri_dependency_tests():
    raw = (plans.ROOT / 'Cargo.lock').read_bytes()
    # SHA-3 now consumes CPU authorities. Current CPU changes must select it.
    assert 'sha3' in plans.scope.closure(
        {'static_cpu'}, downstream=miri_dependencies.graph(raw, raw))
    # Retain a pre-integration fixture to prove when portable reuse is sound.
    start = raw.index(b'name = "brynja-hash-sha3"\n')
    end = raw.index(b'[[package]]', start)
    record = raw[start:end]
    assert record.count(b' "brynja-crypto-cpu",\n') == 1
    raw = raw[:start] + record.replace(b' "brynja-crypto-cpu",\n', b'') + raw[end:]
    edges = miri_dependencies.graph(raw, raw)
    assert plans.scope.closure({'static_cpu'}, downstream=edges) == ('sha2', 'static_cpu')
    assert plans.scope.closure({'sha3'}, downstream=edges) == ('sha3', 'kmac', 'tuplehash', 'parallelhash')
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
    assert executed == [("scripts/zeroization/check-zeroization-miri.sh --selected sha2",)]
    assert run("miri", sample()) == 0 and not executed
    assert run("matrix", sample()) == 0 and not executed
    assert run("kani", sample(groups=("sha2",))) == 0
    assert executed == [("scripts/assurance/check-kani.sh --required-groups sha2",)]
    assert run("asan", sample(groups=("sha2",))) == 0
    assert executed and not any("brynja-legacy-md5" in c[0] for c in executed)
    assert run("repository", sample(public=True)) == 0
    assert any("md5-differential" in c[0] for c in executed)
    with patch.object(commands, "matrix_commands", side_effect=ValueError("unknown matrix")):
        assert run("repository", sample()) == 1 and not executed
        assert run("repository", sample(), "--ci") == 1 and not executed
    with patch.object(commands, "catalog", side_effect=ValueError("unknown sanitizer")):
        assert run("repository", sample()) == 1 and not executed
        assert run("repository", sample(), "--ci") == 1 and not executed
    # CI must ignore stale repository variables, never grant release approval,
    # and never turn unresolved scope into an automatic full campaign.
    stale = {"BRYNJA_FULL_VERIFICATION_APPROVAL": "b" * 64}
    assert run("plan", sample(groups=("sha2",)), "--check", "--ci", environment=stale) == 0
    assert not executed
    assert run("repository", sample(groups=("sha2",)), "--ci", environment=stale) == 0
    assert any("sha2-execution" in c[0] for c in executed)
    assert not any("md5-differential" in c[0] for c in executed)
    for public in (False, True):
        assert run("repository", sample(blocked=True, public=public, groups=plans.scope.GROUPS),
                   "--ci", environment=stale) == 0
        assert [c[0] for c in executed] == commands.selected(commands.repository_commands(), [])
        assert any("cargo test --workspace --all-features" == c[0] for c in executed)
        assert not any("check-zeroization-miri.sh" in c[0] or "--required-groups" in c[0] for c in executed)
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
    with patch.object(runner, "execute", side_effect=subprocess.CalledProcessError(1, "test")):
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
    print("cargo-kani 0.67.0")
else:
    with pathlib.Path(os.environ["TRACE"]).open("a") as output:
        output.write(json.dumps(args) + "\\n")
    if os.environ.get("FAIL_PACKAGE", "missing") in args:
        sys.exit(42)
''')
        fake.chmod(0o700)
        trace = root / "trace"
        env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], TRACE=str(trace))
        def run(*args, fail=""):
            trace.write_text("")
            result = subprocess.run(["bash", "scripts/assurance/check-kani.sh", *args],
                                    cwd=plans.ROOT, env=dict(env, FAIL_PACKAGE=fail),
                                    capture_output=True, text=True, timeout=30)
            return result.returncode, [json.loads(line) for line in trace.read_text().splitlines()]
        status, calls = run("--required-groups", "sha2")
        assert status == 0 and len(calls) == 1 and calls[0][-1] == "brynja-hash-sha2"
        status, calls = run("--required")
        assert status == 0 and len(calls) == 7
        status, calls = run("--required-groups", "sha2", fail="brynja-hash-sha2")
        assert status == 42 and len(calls) == 1
        status, calls = run("--required-groups", "unknown")
        assert status == 2 and not calls
        status, calls = run("--required-groups")
        assert status == 2 and not calls


def main() -> None:
    approval_tests()
    selection_tests()
    miri_dependency_tests()
    parser_tests()
    runner_tests()
    nested_fixture_tests()
    entrypoint_tests()
    fingerprint_tests()
    kani_dispatch_tests()
    print("Incremental verification: ownership, checkpoint, nested-fixture, approval and no-launch regressions PASS")


if __name__ == "__main__":
    main()
