"""Negative controls for archive evidence (no Cargo processes needed)."""
import importlib.util
import hashlib
import json
import copy
import os
from pathlib import Path
import shutil
from subprocess import CompletedProcess
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("gcm_archives", Path(__file__).with_name("check-packaged-api.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
spec = importlib.util.spec_from_file_location("combined", Path(__file__).with_name("check-portable-acceptance.py"))
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)
spec = importlib.util.spec_from_file_location("paired", Path(__file__).with_name("check-paired-archives.py"))
paired = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paired)
spec = importlib.util.spec_from_file_location("native_pairs", Path(__file__).with_name("run-native-pairs.py"))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

spec = importlib.util.spec_from_file_location("installed", Path(__file__).with_name("check-installed-consumer.py"))
installed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installed)


class InstalledEvidenceTests(unittest.TestCase):
    def test_failed_linked_screen_never_runs_or_reports_success(self):
        binary = Path("prefix/bin/consumer")
        linked = {"digest": Mock(return_value="before"), "load": Mock(return_value="image"),
                  "review": Mock(side_effect=ValueError("missing paired hash start"))}
        with patch.object(installed.pkg, "run") as run, patch("builtins.print") as emit:
            with self.assertRaisesRegex(ValueError, "missing paired"):
                installed.run_installed(binary, Path("."), {}, "1.90.0", "direct", "gmac-execution", 10, linked)
            linked["load"].assert_called_once_with(binary)
            linked["review"].assert_called_once_with("image", "1.90.0")
            run.assert_not_called()
            emit.assert_not_called()

    def test_changed_installed_binary_fails_even_after_matching_answers(self):
        binary = Path("prefix/bin/consumer")
        linked = {"digest": Mock(side_effect=["before", "after"]), "load": Mock(), "review": Mock(return_value=30)}
        with patch.object(installed.pkg, "run", return_value=CompletedProcess([], 0, "INSTALLED_CONSUMER_PASS [10, 10, 10]\n")) as run, patch("builtins.print") as emit:
            with self.assertRaisesRegex(ValueError, "changed during replay"):
                installed.run_installed(binary, Path("."), {}, "1.90.0", "direct", "gmac-execution", 10, linked)
            run.assert_called_once_with([str(binary)], Path("."), {})
            self.assertEqual([args.args for args in linked["digest"].call_args_list], [(binary,), (binary,)])
            emit.assert_not_called()


class NativeBundleTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.base = Path(scratch.name)
        self.source = self.base / "incoming"
        self.source.mkdir()
        self.file = self.source / "case.txt"
        self.file.write_bytes(b"public test data")
        self.entries = {"case.txt": native.sha(self.file)}
        self.dest = self.base / "private"
        self.sign()

    def sign(self, raw=None):
        manifest = self.source / "inputs.json"
        manifest.write_text(json.dumps(self.entries) if raw is None else raw)
        self.pin = native.sha(manifest)

    def rejected(self, reason=None):
        # No tool invocation and not even an empty evidence directory on rejection.
        with patch.object(native, "ROOT", self.source), patch.object(native.subprocess, "run") as execute, \
                patch.object(native.platform, "system", return_value="Linux"), \
                patch.object(native.platform, "machine", return_value="aarch64"):
            failure = (self.assertRaisesRegex(ValueError, reason) if reason
                       else self.assertRaises((ValueError, FileNotFoundError)))
            with failure:
                native.run("linux-arm64", self.base / "results", self.pin)
            execute.assert_not_called()
            self.assertFalse((self.base / "results").exists())

    def test_copy_isolated_from_later_source_changes(self):
        native.verified_copy(self.source, self.dest, self.pin)
        self.file.write_bytes(b"changed after admission")
        self.assertEqual((self.dest / "case.txt").read_bytes(), b"public test data")

    def test_wrong_pin_modified_and_missing_files(self):
        self.pin = "0"*64
        self.rejected()
        self.sign()
        self.file.write_bytes(b"changed before admission")
        self.rejected()
        self.file.unlink()
        self.rejected()

    def test_unlisted_files_and_empty_directories(self):
        extra = self.source / "extra"
        extra.touch()
        self.rejected()
        extra.unlink()
        extra.mkdir()
        self.rejected()

    def test_rejects_links_without_following_them(self):
        self.file.rename(self.base / "other")
        self.file.symlink_to(self.base / "other")
        self.rejected()  # target hashes correctly
        self.file.unlink()
        self.file.symlink_to(self.base / "absent")
        self.rejected()
        self.file.unlink()
        other = self.base / "directory"
        other.mkdir()
        (other / "case.txt").write_bytes(b"public test data")
        self.file.symlink_to(other, target_is_directory=True)
        self.entries = {"case.txt/case.txt": native.sha(other / "case.txt")}
        self.sign()
        self.rejected()

    def test_nonregular_file(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no filesystem FIFO on this platform")
        self.file.unlink()
        os.mkfifo(self.file)
        self.rejected()

    def test_unsafe_and_ambiguous_manifest_names(self):
        for name in ("../outside", "/absolute", "C:/absolute", "C:relative", "dir\\file",
                     "foo//bar", "foo/./bar", "trailing.", "NUL.txt", "alternate:stream",
                     "INPUTS.JSON", "CASE.txt", "case.txt/nested", ".cargo/config",
                     "child/.CaRgO/config.toml"):
            with self.subTest(name=name):
                self.entries = {"case.txt": native.sha(self.file), name: "0"*64}
                self.sign()
                self.rejected("unsafe manifest|ambiguous manifest|file used as directory")
        self.sign('{"case.txt":"first","case.txt":"second"}')
        self.rejected("duplicate manifest")

    def test_manifest_itself_may_not_be_a_link(self):
        path = self.source / "inputs.json"
        path.rename(self.base / "external-manifest")
        path.symlink_to(self.base / "external-manifest")
        self.rejected("link or unexpected")

    def test_configuration_rechecked_before_each_command(self):
        (self.source / "cases.json").write_bytes(b"{}")
        self.entries["cases.json"] = native.sha(self.source / "cases.json")
        self.sign()
        for inject_home in (False, True):
            def first_command(args, *, cwd, env, **kwargs):
                self.assertNotEqual(cwd, self.source)
                config_root = Path(env["CARGO_HOME"]) if inject_home else cwd / ".cargo"
                config_root.mkdir()
                (config_root / "config.toml").touch()
                return CompletedProcess(args, 0, stdout="host: aarch64-unknown-linux-gnu\n")
            with patch.object(native, "ROOT", self.source), \
                    patch.object(native.platform, "system", return_value="Linux"), \
                    patch.object(native.platform, "machine", return_value="aarch64"), \
                    patch.object(native.subprocess, "run", side_effect=first_command) as execute:
                with self.assertRaisesRegex(ValueError, "ambient"):
                    native.run("linux-arm64", self.base / f"out-{inject_home}", self.pin)
                self.assertEqual(execute.call_count, 1)

    def test_both_ambient_config_names_and_both_trees(self):
        for parent in (self.source, self.base):
            cargo = parent / ".cargo"
            cargo.mkdir()
            for name in ("config", "config.toml"):
                config = cargo / name
                config.touch()
                self.rejected()
                config.unlink()
            cargo.rmdir()
        self.dest.mkdir()
        (self.dest / ".cargo").mkdir()
        (self.dest / ".cargo/config").touch()
        with self.assertRaisesRegex(ValueError, "ambient"):
            native.verified_copy(self.source, self.dest / "bundle", self.pin)


class ArchiveTests(unittest.TestCase):
    def test_cargo_artifact_is_exactly_the_non_test_consumer_example(self):
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory) / "gcmvs"
            expected.touch()
            msg = dict(reason="compiler-artifact", package_id="consumer", executable=str(expected),
                       target=dict(name="gcmvs", kind=["example"]), profile=dict(test=False))
            def result(*messages):
                return paired.executable("\n".join(map(json.dumps, messages)), "consumer", "gcmvs", expected)
            self.assertEqual(result(msg), expected)
            for edit in (dict(package_id="dependency"), dict(profile=dict(test=True)),
                         dict(target=dict(name="gcmvs", kind=["bin"])), dict(executable=str(expected)+".old")):
                with self.subTest(edit=edit), self.assertRaises(ValueError):
                    result(msg | edit)
            with self.assertRaises(ValueError):
                result(msg, msg)
            expected.unlink()
            expected.symlink_to(Path(__file__).resolve())
            with self.assertRaises(ValueError):
                result(msg)

    def test_linked_comparison_resolves_register_origin_not_comments(self):
        check = paired.linked
        def count(instructions, target):
            assembly = "example:\tfile format elf64-x86-64\n10 <verify>:\n" + "\n".join(
                f" {16+i:x}: {s}" for i, s in enumerate(instructions))
            image = check["Image"](assembly, "100 R_X86_64_RELATIVE *ABS*+0x" + target)
            return check["compare_sites"](image, 16, 0x30, 0x40)
        load = "movq 0x80(%rip), %r15 # 0x100 <fake_label>"
        call, decide = "callq *%r15", "callq 0x40 <decide>"
        self.assertEqual(count([load, call, decide], "30"), 1)
        self.assertEqual(count([load, call, decide], "31"), 0)
        self.assertEqual(count([load, "xorl %r15d, %r15d", call, decide], "30"), 0)
        self.assertEqual(count([decide, load, call], "30"), 0)
        self.assertEqual(count(["callq 0x31 <accumulate_secret_byte_difference>", decide], "30"), 0)

    def test_linked_frame_requires_connected_native_product(self):
        check = paired.linked
        names = ["frame", "AesPair as HashRoute::start", "brynja_crypto::ghash::Ghash::finish",
                 check["UPDATE"], check["PRODUCT"], check["MULTIPLY"]]
        ops = [["callq 0x20", "callq 0x30", "callq 0x40"], [], [],
               ["callq 0x50"], ["jmpq *0x80(%rip) # 0x100"], ["pclmulqdq"]*4 + ["retq"]]
        def screen(bodies, dest="60"):
            assembly = ["example:\tfile format elf64-x86-64"]
            for n, (name, body) in enumerate(zip(names, bodies), 1):
                assembly.append(f"{16*n:x} <{name}>:")
                assembly.extend(f" {16*n+i:x}: {s}" for i, s in enumerate(body))
            image = check["Image"]("\n".join(assembly), "100 R_X86_64_RELATIVE *ABS*+0x" + dest)
            check["field_route"](image, 16)
        screen(ops)
        with self.assertRaises(ValueError):
            screen(ops, "30")  # multiply is present elsewhere but is no longer reached
        for idx, replacement in ((0, ops[0][1:]), (3, []), (5, ops[5][1:]), (5, ["jne 0x62"] + ops[5])):
            with self.subTest(idx=idx), self.assertRaises(ValueError):
                screen(ops[:idx] + [replacement] + ops[idx+1:])

    def test_linked_aes_requires_matching_width_and_forward_rounds(self):
        c = paired.linked
        def screen(width="128", final="aesenclast"):
            text = ("example:\tfile format elf64-x86-64\n10 <material>:\n 10: callq 0x20\n"
                    f"20 <{c['PORT']}paired::Aes128ExpandedKey as Forward::encrypt>:\n 20: callq 0x30\n"
                    f"30 <brynja_crypto_cpu::aes::Session::encrypt{width}>:\n 30: callq 0x40\n"
                    f"40 <{c['TRANSFORM']}>:\n 40: aesenc\n 45: {final}\n")
            return c["aes_width"](c["Image"](text, ""), 16)
        self.assertEqual(screen(), ("128", 64))
        for args in (("256", "aesenclast"), ("128", "aesdeclast")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                screen(*args)

        def thunk(inverse):
            name = "brynja_cipher_aes::aes::execution::Aes192ExpandedKey"
            text = ("example:\tfile format elf64-x86-64\n10 <material>:\n 10: callq 0x20\n"
                    f"20 <{c['PORT']}paired::Aes192ExpandedKey as Forward::encrypt>:\n 20: callq 0x30\n"
                    f"30 <{name}::encrypt_block>:\n 30: pushq %rbx\n 31: movq %rdi, %rbx\n"
                    f" 32: {inverse}\n 33: callq 0x40\n 34: movq %rbx, %rax\n 35: popq %rbx\n 36: retq\n"
                    f"40 <{name}::secret>:\n 40: callq 0x50\n50 <brynja_crypto_cpu::aes::Session::encrypt192>:\n"
                    f" 50: callq 0x60\n60 <{c['TRANSFORM']}>:\n 60: aesenc\n 61: aesenclast\n")
            return c["aes_width"](c["Image"](text, ""), 16)
        self.assertEqual(thunk("xorl %r8d, %r8d"), ("192", 96))
        with self.assertRaisesRegex(ValueError, "direction thunk"):
            thunk("movl $1, %r8d")

    def test_linked_leaf_rejects_substituted_operation_and_early_exit(self):
        c = paired.linked
        wanted = [("orb", "%al, (%rdi)"), ("retq", "")]
        def screen(instructions):
            text = "example:\tfile format elf64-x86-64\n10 <leaf>:\n" + "\n".join(
                f" {16+i:x}: {s}" for i, s in enumerate(instructions))
            c["check_leaf"](c["Image"](text, ""), "leaf", wanted)
        screen(["orb %al, (%rdi)", "retq", "int3"])
        for bad in (["xorb %al, (%rdi)", "retq"], ["jne 0x12", "orb %al, (%rdi)", "retq"]):
            with self.assertRaises(ValueError):
                screen(bad)

    def test_archive_graph_allows_only_the_required_native_edge(self):
        # Build the direct-consumer subgraph from the portable reference lock.
        lock = tomllib.loads((runner.FIXTURE / "Cargo.lock").read_text())
        packages = {p["name"]: p for p in lock["package"]}
        cpu, crypto = "brynja-crypto-cpu", "brynja-crypto"
        versions = {name: p["version"] for name, p in packages.items()}
        versions[cpu] = "0.2.0"
        root = Path("/archive-test")
        graph = {"resolve": {"root": "consumer", "nodes": []}, "packages": []}
        nodes = {}

        def add(name, deps, features, path):
            node = {"id": name, "deps": [{"pkg": d} for d in deps], "features": features}
            nodes[name] = node
            graph["resolve"]["nodes"].append(node)
            graph["packages"].append({"id": name, "name": name, "manifest_path": str(path),
                                      "features": {"default": []}})

        def visit(name):
            if name in nodes:
                return
            deps = list(packages.get(name, {}).get("dependencies", []))
            flags = ["default"]
            if name == crypto:
                flags = ["gmac", "gmac-execution"]
                deps.append(cpu)
            elif name == cpu:
                flags += ["aes-static-execution", "ghash-runtime-execution"]
            elif name == "brynja-cipher-aes":
                flags += ["__mode", "__mode-execution"]
                deps.append(cpu)
            add(name, deps, flags, root / "unpacked" / f"{name}-{versions[name]}" / "Cargo.toml")
            for dep in deps:
                visit(dep)

        add("consumer", [crypto], ["native"], root / "consumer/Cargo.toml")
        visit(crypto)

        def validate(candidate):
            runner.check_graph(candidate, root / "consumer", versions, crypto,
                               paired=True, features=("gmac-execution",))

        validate(graph)
        for target, field, value in ((crypto, "features", ["gmac", "gmac-execution", "hazmat-aes-block"]),
                                     ("brynja-cipher-aes", "features", ["default", "hazmat-aes-block"]),
                                     ("brynja-cipher-aes", "features", ["default", "__mode", "__mode-execution", "hazmat-aes-block"]),
                                     ("brynja-cipher-aes", "features", ["default", "__mode", "__mode-execution", "aes-static-execution"]),
                                     (cpu, "features", ["default", "aes-static-execution"]),
                                     (cpu, "deps", [{"pkg": "brynja-core"}]),
                                     (crypto, "deps", [d for d in nodes[crypto]["deps"] if d["pkg"] != cpu])):
            mutant = copy.deepcopy(graph)
            next(n for n in mutant["resolve"]["nodes"] if n["id"] == target)[field] = value
            with self.assertRaises(ValueError):
                validate(mutant)
        with self.assertRaises(ValueError):
            runner.check_graph(graph, root / "consumer", versions, crypto, features=("gmac",))
        # Even a changed reference lock cannot authorize a CPU crate for a
        # portable consumer. Remove the native features to isolate that guard.
        nodes[crypto]["features"] = ["gmac"]
        nodes["brynja-cipher-aes"]["features"] = ["default", "__mode"]
        nodes["brynja-cipher-aes"]["deps"] = [{"pkg": "brynja-core"}]
        nodes[cpu]["features"] = ["default"]
        packages[crypto]["dependencies"].append(cpu)
        lock["package"].append({"name": cpu, "version": versions[cpu]})
        with patch.object(runner.tomllib, "loads", return_value=lock), self.assertRaisesRegex(
            ValueError, "archive dependency graph"
        ):
            runner.check_graph(graph, root / "consumer", versions, crypto, features=("gmac",))

    def test_paired_adapter_rejects_missing_or_ambiguous_constructor(self):
        for family, source, constructor in (
            ("aes-gcm", "aes-gcm-consumer/examples/gcmvs.rs", "::for_open("),
            ("gmac", "gmac-consumer/src/lib.rs", "::for_verify("),
        ):
            original = (runner.ROOT / "assurance" / source).read_text()
            native = paired.paired_source(original, family)
            self.assertEqual(native.count("(&pair, "), 3)
            self.assertEqual(native.count("AesPair::require()"), 1)
            self.assertIn("execution::{AesPair", native)
            for changed in (original.replace(constructor, "::other("), original + constructor):
                with self.assertRaisesRegex(ValueError, "one expected call"):
                    paired.paired_source(changed, family)

    def test_paired_controls_use_data_and_change_only_the_intended_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "go.tsv"
            for family, rest, kinds in (
                ("aes-gcm", ["aa", "cc", "bb", "44"], ["seal", "seal-in-place", "open", "open-disjoint", "reject", "reject-disjoint"]),
                ("gmac", ["aa", "44"], ["seal", "open", "reject"]),
            ):
                records = [[k, "11", "22", *rest] for k in kinds]
                empty = [[*f[:3], *[""] * (len(rest) - 1), "44"] for f in records]
                path.write_text("".join("\t".join(f) + "\n" for f in empty + records))
                actual = [row.rstrip("\n").split("\t") for row in paired.controls(path, family)]
                expected = []
                for f in records:
                    k = f[0]
                    altered = f.copy()
                    if k.startswith("seal"):
                        altered[-1] = "04"
                    else:
                        altered[0] = k.replace("open", "reject") if k.startswith("open") else k.replace("reject", "open")
                    expected.append(altered)
                    if family == "aes-gcm" and not k.startswith("reject"):
                        altered = f.copy()
                        if k.startswith("seal"):
                            altered[4] = "0c"
                        else:
                            altered[5] = "0b"
                        expected.append(altered)
                self.assertCountEqual(actual, expected)
                path.write_text("".join("\t".join(f) + "\n" for f in empty + records[:-1]))
                with self.assertRaisesRegex(ValueError, "incomplete nonempty"):
                    list(paired.controls(path, family))

    def test_native_registration_tracks_archive_and_all_eight_results(self):
        registry = tomllib.loads((runner.ROOT / "verification/checks.toml").read_text())
        check, = (c for c in registry["checks"] if c["id"] == "x86-packaged-pair")
        groups = [registry["groups"][group] for group in check["inputs"]]
        paths = {Path(p) for group in groups for p in group.get("paths", [])}
        self.assertIn("references/local/gcmtestvectors.zip",
                      {p for group in groups for p in group.get("optional_paths", [])})
        for name in combined.INPUTS | {check["command"][1], "assurance/aead-portable-acceptance/SHA256SUMS",
                                      "scripts/gmac/check-consumer.py", "scripts/aes-gcm/check-gcmvs.py",
                                      "assurance/aes-kernel-candidate/probe.rs", "scripts/aes-gcm/paired_linked.py"}:
            self.assertTrue(any(Path(name).is_relative_to(p) for p in paths), name)
        markers = {f"{v} {r} {f}: paired Go and NIST archives passed"
                   for v in ("1.90.0", "1.100.0") for r in ("direct", "facade") for f in ("aes-gcm", "gmac")}
        self.assertEqual(set(check["success"]["unique_lines"]), markers | {"X86_PAIRED_AEAD_ARCHIVES_COMPLETE"})
        self.assertEqual(check["platform"], "linux-x86_64")
        self.assertIn("X86_PAIRED_AEAD_LINKED_COMPLETE", check["success"]["contains"])
        self.assertIn("llvm-objdump", {t["program"] for g in groups for t in g.get("tools", [])})

    def test_replay_rejects_a_consumer_that_ignores_the_verify_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "rows"
            data.write_text("seal\t00\nopen\t00\nreject\t01\n")
            for missed in ("open", "reject"):
                with self.subTest(missed=missed):
                    def consumer(cmd, *, input=None, **kwargs):
                        if input is None:
                            return CompletedProcess(cmd, 0, "generate=1 verify=1 reject=1", "")
                        ignored = {"open": "reject\t00\n", "reject": "open\t01\n"}[missed]
                        if input == ignored:
                            return CompletedProcess(cmd, 0, "", "")
                        return CompletedProcess(cmd, 1, "", "GMAC case 1 failed")
                    with patch.object(combined.pkg.cargo_environment, "check") as guard, \
                         patch.object(combined.subprocess, "run", side_effect=consumer) as runs, \
                         self.assertRaisesRegex(ValueError, f"wrong {missed} expectation"):
                        combined.replay(["cargo"], data.parent, {}, [], "nist", data,
                                        "generate=1 verify=1 reject=1")
                    self.assertEqual(guard.call_count, runs.call_count)

    def test_wrong_expectations_preserve_inputs_and_layout(self):
        plain = {"reject": "open", "seal": "seal", "open": "reject"}
        extra = {"open-disjoint": "reject-disjoint", "seal-in-place": "seal-in-place",
                 "reject-disjoint": "open-disjoint"}
        for example, labels in (("nist", plain), ("gcmvs", plain | extra)):
            rows = [kind + "\t1234\t\t0a\n" for kind in labels]
            got = dict(combined.wrong_expectations([rows[0], *rows], example))
            self.assertEqual(got, {kind: new + "\t1234\t\t" + ("1a" if kind.startswith("seal") else "0a") + "\n"
                                   for kind, new in labels.items()})
            with self.assertRaisesRegex(ValueError, "missing differential controls"):
                list(combined.wrong_expectations(rows[:-1], example))

    def test_empty_graph_is_not_portable_evidence(self):
        with self.assertRaisesRegex(ValueError, "missing archive"):
            runner.check_graph({"resolve": {"root": None, "nodes": []}, "packages": []},
                               Path("/unused"), {}, "brynja")

    def test_frozen_inventory_requires_each_exact_file_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "example").write_bytes(b"public fixture")
            checksum = hashlib.sha256(b"public fixture").hexdigest()
            line = checksum + "  example\n"
            with patch.multiple(combined, ROOT=root, FIXTURE=root, INPUTS={"example"}):
                for inventory in ("", line * 2, line.replace("example", "extra"), "0" * 64 + line[64:]):
                    (root / "SHA256SUMS").write_text(inventory)
                    with self.subTest(inventory=inventory), self.assertRaises(ValueError):
                        combined.frozen()
                (root / "SHA256SUMS").write_text(line)
                combined.frozen()

    def test_combined_registry_binds_frozen_inputs_and_requires_full_replay(self):
        registry = tomllib.loads((runner.ROOT / "verification/checks.toml").read_text())
        check, = (c for c in registry["checks"] if
                  (c["component"], c["id"]) == ("gmac", "packaged-portable-acceptance"))
        self.assertEqual(check["command"], ["python3", "scripts/aes-gcm/check-portable-acceptance.py"])
        paths = {Path(p) for g in check["inputs"] for p in registry["groups"][g].get("paths", [])}
        for name in combined.INPUTS | {check["command"][1], "assurance/aead-portable-acceptance/SHA256SUMS"}:
            self.assertTrue(any(Path(name).is_relative_to(p) for p in paths), name)
        self.assertEqual(check["success"]["contains"], ["PORTABLE_AEAD_ARCHIVES_COMPLETE"])

    def test_fixture_change_fails_even_if_the_number_of_examples_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = root / "fixture"
            for directory in ("src", "tests"):
                shutil.copytree(runner.FIXTURE / directory, fixture / directory)
            data = fixture / "tests/nist-worked.txt"
            data.write_bytes(data.read_bytes().replace(b"3247184b", b"3247184a", 1))
            with patch.object(runner, "FIXTURE", fixture), self.assertRaisesRegex(ValueError, "NIST fixture"):
                runner.prepare(root, "brynja-crypto", {"brynja-crypto": "0.2.0"})

    def test_archive_registration_covers_every_packaged_crate_and_helper(self):
        registry = tomllib.loads((runner.ROOT / "verification/checks.toml").read_text())
        check, = (c for c in registry["checks"] if
                  (c["component"], c["id"]) == ("aes_gcm", "packaged-public-api"))
        self.assertEqual(check["command"], ["python3", "scripts/aes-gcm/check-packaged-api.py"])
        paths = {p for group in check["inputs"] for p in registry["groups"][group].get("paths", [])}
        required = {f"crates/{name}" for name in runner.pkg.MODERN}
        self.assertTrue(required | {check["command"][1], "scripts/ghash/check-packaged-api.py",
                        "scripts/hkdf/check-hkdf-public-api.py", "scripts/repository/facade_cargo_environment.py",
                        "assurance/aes-gcm-consumer/tests", "assurance/aes-gcm-consumer/src"} <= paths)
        self.assertEqual(check["success"]["contains"], ["AES_GCM_ARCHIVE_COMPLETE"])


if __name__ == "__main__":
    unittest.main()
