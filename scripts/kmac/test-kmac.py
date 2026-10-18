#!/usr/bin/env python3
"""Reject representative regressions across the reviewed KMAC boundary."""

from __future__ import annotations

import shutil
import subprocess
import re
import tempfile
from pathlib import Path

import kmac_policy


ROOT = Path(__file__).resolve().parents[2]


def codegen_lookup_regressions() -> None:
    """Exercise the real shell extractor and cSHAKE checks, without Cargo."""
    script = (ROOT / 'scripts/kmac/check-kmac-codegen.sh').read_text()
    prefix = script.split('for raw_toolchain in ', 1)[0]
    body = script.split('    for mir in "${sha3_mir[@]}"; do\n', 1)[1]
    body = body.split('\n    for artifact in ', 1)[0]
    command = prefix + '\nsha3_mir=("$1")\nfor mir in "${sha3_mir[@]}"; do\n' + body

    def function(method, identity, statements, extra=''):
        return (f'fn hardened::cshake::<impl at test.rs:1:1: 1:2>::{method}'
                f'(_1: &mut {identity}{extra}) -> () {{\n{statements}\n}}\n')

    source = ''
    for identity, rate in (('HardenedCshake128', 168), ('HardenedCshake256', 136)):
        # This valid prefix-colliding owner appeared first in actual release MIR.
        source += function('wipe_in_place', identity + 'Setup', '    Setup::wipe(move _1);')
        source += function('finalize_xof_erasing_source', identity,
                           f'    {identity}::enter_squeezing_in_place(copy _1);\n'
                           f'    {identity}::take_reader_erasing_source(copy _1);')
        source += function('enter_squeezing_in_place', identity,
                           f'    {identity}::finish(copy _1);\n    CshakeLifecycle::Squeezing;',
                           ', _2: Option<Fips202BitString>')
        source += function('wipe_in_place', identity,
                           f'    CshakeLifecycle::Vacated;\n    HardenedFips202Owner::<{rate}>::wipe(move _2);')
        source += function('take_reader_erasing_source', identity,
                           f'    _2 = &mut ((*_1).0: hardened::owner::HardenedFips202Owner<{rate}>);\n'
                           f'    HardenedFips202Owner::<{rate}>::wipe(move _2);')
    source += '// StateConsumed\n'
    with tempfile.TemporaryDirectory(prefix='brynja-kmac-codegen-test-') as directory:
        artifact = Path(directory) / 'fixture.mir'

        def check(text, success):
            artifact.write_text(text)
            result = subprocess.run(['bash', '-c', command, 'codegen-test', str(artifact)],
                                    capture_output=True, text=True, timeout=30)
            assert (result.returncode == 0) == success, result.stderr

        check(source, True)
        for identity, rate in (('HardenedCshake128', 168), ('HardenedCshake256', 136)):
            wipe = function('wipe_in_place', identity,
                            f'    CshakeLifecycle::Vacated;\n    HardenedFips202Owner::<{rate}>::wipe(move _2);')
            assert wipe in source
            check(source.replace(wipe, ''), False)
            check(source + wipe, False)
            check(source.replace(wipe, '    // ' + wipe.replace('\n', ' ') + '\n'), False)
            check(source.replace(wipe, wipe.rsplit('}', 1)[0]), False)
            check(source.replace(wipe, wipe.replace('CshakeLifecycle::Vacated;', '')), False)
            check(source.replace(wipe, wipe.replace('    CshakeLifecycle::Vacated;\n', '')
                                 .replace('\n}', '\n    CshakeLifecycle::Vacated;\n}')), False)
        for variable, method in (('fixed', 'finish_fixed'), ('xof', 'finish_xof'), ('cleanup', 'wipe')):
            pattern, = re.findall(rf"{variable}=\"\$\(extract_function '([^']+)'", script)
            extra = '' if method == 'wipe' else ', _2: bool'
            wanted = function(method, 'KmacCore<S, RATE, STRENGTH>', '    expected_owner;', extra)
            other = function(method, 'KmacCoreSetup<S, RATE, STRENGTH>', '    wrong_owner;', extra)
            extract = prefix + '\nextract_function "$2" "$1"\n'
            for text, success in ((other + wanted, True), (other, False), (wanted + wanted, False)):
                artifact.write_text(text)
                result = subprocess.run(['bash', '-c', extract, 'codegen-test', str(artifact), pattern],
                                        capture_output=True, text=True, timeout=30)
                assert (result.returncode == 0) == success, result.stderr
                if success:
                    assert result.stdout == wanted
    print('KMAC codegen accepts exact owners alongside Setup names and rejects 18 lookup/cleanup regressions')


def reject(label: str, path: Path, old: str, new: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"brynja-kmac-{label}-") as directory:
        root = Path(directory)
        for source in kmac_policy.FILES:
            target = root / source
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / source, target)
        reviewed = Path("scripts/kmac/kmac_reviewed_hashes.py")
        reviewed_target = root / reviewed
        reviewed_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / reviewed, reviewed_target)
        subject = root / path
        text = subject.read_text(encoding="utf-8")
        if old not in text:
            raise RuntimeError(f"broken KMAC fixture: {label}")
        subject.write_text(text.replace(old, new, 1), encoding="utf-8")
        try:
            kmac_policy.validate(root)
        except kmac_policy.KmacPolicyError:
            return
        raise RuntimeError(f"KMAC policy accepted regression: {label}")


def main() -> int:
    import test_kmac_retest
    test_kmac_retest.check()
    codegen_lookup_regressions()
    kmac_policy.validate(ROOT)
    streamed = Path("crates/brynja-mac-kmac/src/setup")
    reject("streamed-strength", streamed / "engine.rs", "key_bits < D::STRENGTH", "key_bits < 1")
    reject("streamed-completion", streamed / "engine.rs", "op.setup.emitted != op.setup.expected", "false")
    reject("streamed-cleanup", streamed / "engine.rs", "self.state.wipe_in_place();", "")
    reject("streamed-test-removal", streamed / "tests.rs", "fn streamed_setup_matches_all_four_contiguous_identities", "fn removed_streamed_coverage")
    reject("std", Path("crates/brynja-mac-kmac/src/lib.rs"), "#![no_std]", "extern crate std;")
    reject("unsafe", Path("crates/brynja-mac-kmac/src/output.rs"), "use brynja_core", "unsafe fn bypass() {}\nuse brynja_core")
    reject("domain-name", Path("crates/brynja-mac-kmac/src/backend.rs"), "b\"KMAC\"", "b\"RAW\"")
    reject("key-clear", Path("crates/brynja-mac-kmac/src/packer.rs"), "clear_owned_region(&mut self.pending)", "core::hint::black_box(&mut self.pending)")
    reject("key-length-clear", Path("crates/brynja-mac-kmac/src/packer.rs"), "clear_owned_region(&mut self.emitted)", "core::hint::black_box(&mut self.emitted)")
    reject("inline-source-option", Path("crates/brynja-mac-kmac/src/core_state.rs"), "state: S,", "state: Option<S>,")
    reject("in-place-transition", Path("crates/brynja-mac-kmac/src/core_state.rs"), "append_right_encode(&mut self.state", "append_right_encode(&mut temporary")
    reject("in-place-core-wipe", Path("crates/brynja-mac-kmac/src/core_state.rs"), "self.state.wipe_in_place();", "core::hint::black_box(&mut self.state);")
    reject("backend-source-erasure", Path("crates/brynja-mac-kmac/src/backend.rs"), "fn finalize_xof_erasing_source(&mut self)", "fn finalize_xof_erasing_source(self)")
    reject("backend-terminal-result", Path("crates/brynja-mac-kmac/src/backend.rs"), "Result<Self::Reader, HardenedSha3Error>", "Self::Reader")
    reject("terminal-error-mapping", Path("crates/brynja-mac-kmac/src/error.rs"), "HardenedSha3Error::StateConsumed => Self::StateConsumed", "HardenedSha3Error::StateConsumed => Self::SecretMemory")
    reject("terminal-error-propagation", Path("crates/brynja-mac-kmac/src/packer.rs"), ".finalize_xof_erasing_source().map_err(KmacError::from)", ".finalize_xof_erasing_source().map(|reader| reader)")
    reject("encoded-width-fail-closed", Path("crates/brynja-mac-kmac/src/packer.rs"), "self.bytes.get(..length).ok_or(KmacError::SecretMemory)", "Ok(self.bytes.get(..length).unwrap_or_default())")
    reject("borrowed-key-encoding", Path("crates/brynja-mac-kmac/src/packer.rs"), "fn left_encode(&mut self, value: u128)", "fn left_encode(mut self, value: u128)")
    reject("borrowed-bytepad", Path("crates/brynja-mac-kmac/src/packer.rs"), "fn finish_bytepad(&mut self, rate: usize)", "fn finish_bytepad(mut self, rate: usize)")
    reject("borrowed-framing", Path("crates/brynja-mac-kmac/src/packer.rs"), "storage: &'storage mut Framing", "storage: Framing")
    reject("borrowed-fragment", Path("crates/brynja-mac-kmac/src/packer.rs"), "byte: &u8, valid: u8", "byte: u8, valid: u8")
    reject("fragment-boundary", Path("crates/brynja-mac-kmac/src/packer.rs"), "brynja_core::xor_secret_byte_bits(pending, byte, position, take, used)", "Ok::<(), brynja_core::SecretBitRangeError>(())")
    reject("fragment-shape", Path("crates/brynja-mac-kmac/src/packer.rs"), "if valid > 8 || self.used() >= 8", "if valid > 9 || self.used() > 8")
    reject("conformance-feature", Path("crates/brynja-mac-kmac/src/lib.rs"), '#[cfg(feature = "conformance-testing")]\npub fn kmac128_conformance', "pub fn kmac128_conformance")
    reject("production-conformance-methods", Path("crates/brynja-mac-kmac/src/lib.rs"),
           '(production; $($method:item)*) => {};',
           '(production; $($method:item)*) => { $($method)* };')
    reject("conformance-namespace", Path("crates/brynja-mac-kmac/src/lib.rs"),
           'pub mod conformance {', 'mod conformance {')
    reject("conformance-compile-gate", Path("scripts/checks.sh"), "scripts/kmac/check-kmac-conformance-gate.sh", "true # removed conformance gate")
    reject("constant-time", Path("crates/brynja-mac-kmac/src/output.rs"), "ct_eq", "ordinary_eq")
    reject("borrowed-comparison", Path("crates/brynja-mac-kmac/src/output.rs"), "accumulate_secret_byte_difference", "ordinary_difference")
    reject("borrowed-decision", Path("crates/brynja-mac-kmac/src/output.rs"), "secret_difference_is_zero", "ordinary_zero_check")
    reject("official-vector", Path("crates/brynja-mac-kmac/tests/official_vectors.rs"), "E5780B0D3EA6F7D3", "F5780B0D3EA6F7D3")
    reject("differential", Path("scripts/checks.sh"), "python3 scripts/kmac/check-kmac-differential.py", "true")
    reject("production-oracle", kmac_policy.DIFFERENTIAL_FIXTURE,
           "profiles::production::dispatch(", "profiles::conformance::dispatch(")
    reject("enabled-conformance-gate", kmac_policy.CONFORMANCE_GATE,
           "--features enabled --message-format=json", "--message-format=json")
    reject("named-strength-policy", kmac_policy.CRATE / "src/policy.rs",
           "matches!(self, Self::Production)", "matches!(self, Self::Conformance)")
    reject("bare-strength-policy", kmac_policy.CRATE / "src/core_state.rs",
           "strength_policy: StrengthPolicy", "production: bool")
    reject("miri", Path("scripts/zeroization/check-zeroization-miri.sh"), "-p brynja-mac-kmac", "-p missing-kmac")
    reject(
        "sanitizer-targets",
        Path("scripts/zeroization/check-zeroization-sanitizer.sh"),
        "-p brynja-mac-kmac \\\n    --tests",
        "-p brynja-mac-kmac \\\n    --lib",
    )
    reject("dependency", Path("crates/brynja-mac-kmac/Cargo.toml"), "brynja-hash-sha3 = { workspace = true }", "foreign = \"1\"")
    scoped = Path("crates/brynja-mac-kmac/src/hardened_in_place")
    reject("scoped-guard", scoped / "fixed.rs", "let cleanup = Guard(&mut self.metadata);", "let cleanup = &mut self.metadata;")
    reject("scoped-domain", scoped / "fixed.rs", 'bytes(b"KMAC")?', 'bytes(b"RAW")?')
    reject("scoped-borrow", scoped / "fixed.rs", "impl for<'scope> FnOnce($state<'scope>) -> R", "impl FnOnce($state<'static>) -> R")
    reject("scoped-terminal", scoped / "core_state.rs", "self.core.state.0 = None;", "")
    reject("scoped-output", scoped / "core_state.rs", "let _ = clear_owned_region(output);", "")
    reject("scoped-verify", scoped / "core_state.rs", "secret_difference_is_zero(&cleanup.0.difference[0])", "secret_difference_is_zero(&0)")
    reject("scoped-xof-trailer", scoped / "core_state.rs", "self.finish(input, 0, 0, StrengthPolicy::Conformance)", "self.finish(input, 8, 0, StrengthPolicy::Conformance)")
    reject("scoped-reader-terminal", scoped / "reader.rs", "*self.reader = None;", "")
    reject("scoped-reader-metadata", scoped / "reader.rs", "self.metadata.wipe();", "")
    reject("scoped-reader-secret", scoped / "reader.rs", "clear_owned_region(output)", "core::hint::black_box(output)")
    reject("scoped-reader-public", scoped / "xof.rs", "_authority: KmacPublicDeclassification", "_authority: ()")
    reject("scoped-accelerated-scratch", scoped / "accelerated.rs", "clear_owned_region(self.0)", "core::hint::black_box(self.0)")
    reject("scoped-accelerated-guard", scoped / "accelerated/fixed.rs", "let cleanup = Guard(metadata);", "let cleanup = metadata;")
    reject("scoped-accelerated-domain", scoped / "accelerated/fixed.rs", 'bytes(b"KMAC")?', 'bytes(b"RAW")?')
    reject("scoped-accelerated-key", scoped / "accelerated/fixed.rs", "key.bit_len() < $strength", "false")
    reject("scoped-accelerated-feature", scoped.with_suffix('.rs'), '#[cfg(feature = "hardened-execution")]\npub mod accelerated;', 'pub mod accelerated;')
    for label, before, after in (
        ('state', 'self.core.finish_xof(input, strength_policy)?', 'self.core.finish_xof(input, false)?'),
        ('borrow', "&'scope mut [u8]", "[u8; 168]"),
        ('public', '_authority: KmacPublicDeclassification', '_authority: ()'),
        ('output', 'self.inner.public(output)', 'Ok(())'),
        ('final-bits', 'self.inner.final_secret(output, valid)', 'self.inner.final_secret(output, 8)'),
    ):
        reject('scoped-accelerated-xof-' + label, scoped / 'accelerated/xof.rs', before, after)
    print("KMAC policy rejects ownership, lifecycle, borrowed-comparison, feature, algorithm, test, and dependency regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
