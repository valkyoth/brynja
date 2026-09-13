#!/usr/bin/env python3
"""Adversarial source-review and emitted-artifact regression checks."""
import shutil
import tempfile
from pathlib import Path
import hardened_policy as policy
import hardened_codegen as codegen


def apple_inline_tests():
    target = 'aarch64-apple-darwin'
    symbol = '_RNbrynja_legacy_sha13cpu6secret9Authority8compress'
    instructions = ('sha1c', 'sha1p', 'sha1m', 'sha1h', 'sha1su0', 'sha1su1')
    assembly = '_' + symbol + ':\n ret\n_RNordinary:\n sha1c.4s q0,s0,v0\n'
    llvm = 'define void @' + symbol + '() {\n' + ''.join(
        ' call void @llvm.aarch64.crypto.' + name + '()\n' for name in instructions) + '}\n'
    assert 'sha1c' not in codegen.kernel_body(assembly, llvm, target)
    standalone = '_RNbrynja_legacy_sha1aarch64_sha1compress_secret:\n ret\n'
    assert codegen.kernel_body(standalone, '', target).strip() == 'ret'
    cases = [
        (assembly + assembly, llvm, target),
        (assembly, llvm + llvm, target),
        (assembly, '', target),
        (assembly.replace('3cpu6secret', '3cpu7session'), llvm, target),
        (assembly, llvm.replace('3cpu6secret', '3cpu7session'), target),
        (assembly, llvm, 'aarch64-unknown-linux-gnu'),
        (standalone + standalone + assembly, llvm, target),
        (assembly.replace('_' + symbol + ':', 'Lordinary:'), llvm, target),
    ]
    for instruction in instructions:
        missing = llvm.replace(' call void @llvm.aarch64.crypto.' + instruction + '()\n', '')
        # An intrinsic in a declaration or unrelated definition is insufficient.
        donated = missing + 'declare void @llvm.aarch64.crypto.' + instruction + '()\n'
        donated += 'define void @_RNordinary() {\n call void @llvm.aarch64.crypto.' + instruction + '()\n}\n'
        cases.append((assembly, donated, target))
    for asm, ir, triple in cases:
        try: codegen.kernel_body(asm, ir, triple)
        except ValueError: pass
        else: raise AssertionError('Apple inlined-kernel evidence regression survived')
    print(f'Apple hardened-kernel scoping: two valid layouts; {len(cases)} regressions rejected')


def main():
    apple_inline_tests()
    policy.validate()
    with tempfile.TemporaryDirectory(prefix='brynja-sha1-hardened-policy-') as temporary:
        root = Path(temporary)
        for relative in set(policy.inventory()) | {'scripts/checks.sh', 'scripts/tag_gate.sh', policy.REVIEW, '.github/workflows/ci.yml',
                'scripts/zeroization/check-zeroization-miri.sh', 'scripts/zeroization/check-zeroization-sanitizer.sh'}:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(policy.ROOT / relative, destination)
        policy.validate(root)
        cases = [
            (policy.LEAF+'src/hardened_execution/stream.rs', "impl<'a> Stream<'a> {", "impl<'a> Stream<'a> { pub fn check_additional_bits(&self, bits: u64) -> bool { crate::engine::admit_bits(self.owner.bits(), bits).is_ok() }"),
            (policy.LEAF+'src/hardened_execution/stream.rs', "impl<'a> Stream<'a> {", "impl<'a> Stream<'a> { pub fn check_additional_bytes(&self, bytes: usize) -> bool { crate::engine::admit_bytes(self.owner.bits(), bytes).is_ok() }"),
            (policy.LEAF+'src/cpu/secret.rs', 'PhantomData<*mut ()>', 'PhantomData<()>'),
            (policy.LEAF+'src/cpu/secret.rs', 'authority.compress(&mut owner)?;', ''),
            (policy.LEAF+'src/cpu/secret.rs', 'self.owner.wipe();', ''),
            (policy.LEAF+'src/cpu/secret.rs', 'clear_owned_region(&mut self.lanes)', 'clear_owned_region(&mut [])'),
            (policy.LEAF+'src/cpu/secret.rs', 'self.healthy.set(false);\n        if !(self.revalidate)', 'if !(self.revalidate)'),
            (policy.LEAF+'src/hardened_execution/mod.rs', 'self.revoked.set(true);', 'self.revoked.set(false);'),
            (policy.LEAF+'src/hardened_execution/stream.rs', 'self.state.owner.wipe();', ''),
            (policy.LEAF+'src/hardened_execution/stream.rs', 'impl HardenedSha1State for Stream', 'impl SomeOtherTrait for Stream'),
            (policy.LEAF+'src/hardened_execution/ownership.rs', 'need::<Executor>();', 'need::<()>();'),
            (policy.LEAF+'Cargo.toml', 'default = []', 'default = ["hardened-execution"]'),
            ('scripts/checks.sh', 'python3 scripts/sha1/check-sha1-hardened.py', ''),
            ('scripts/sha1/check-sha1-hardened-asan.py', "env['ASAN_OPTIONS'] = 'detect_leaks=1:halt_on_error=1:exitcode=1'", ''),
            ('scripts/sha1/check-sha1-hardened-asan.py', "env['LSAN_OPTIONS'] = 'exitcode=23'", "env['LSAN_OPTIONS'] = 'exitcode=0'"),
            ('.github/workflows/ci.yml', 'architecture: aarch64', 'architecture: unsupported'),
            ('.github/workflows/ci.yml', 'run: python3 scripts/sha1/check-sha1-hardened-ci.py', 'run: echo'),
            ('.github/workflows/ci.yml', 'run: python3 scripts/sha1/check-sha1-hardened-ci.py', '# run: python3 scripts/sha1/check-sha1-hardened-ci.py'),
            ('.github/workflows/ci.yml', '    name: Hardened SHA-1 native', '    continue-on-error: true\n    name: Hardened SHA-1 native'),
            ('scripts/sha1/check-sha1-hardened-ci.py', "BRYNJA_REQUIRE_HARDENED_SHA1='1'", "UNRELATED_FLAG='1'"),
            ('scripts/sha1/check-sha1-hardened-ci.py', "RUSTFLAGS='-C target-feature='+features", "RUSTFLAGS=''"),
            (policy.LEAF+'src/cpu/secret/tests.rs', 'std::env::var_os("BRYNJA_REQUIRE_HARDENED_SHA1").is_none()', 'true'),
            (policy.LEAF+'src/cpu/secret.rs', '**No runtime feature detection or migration protection is performed.**', 'Features are available.'),
            (policy.LEAF+'src/cpu/x86_sha1.rs', '#[target_feature(enable = "sha,sse2")]\npub(super) unsafe fn compress_secret(', 'pub(super) unsafe fn compress_secret('),
            (policy.LEAF+'src/cpu/aarch64_sha1.rs', '#[target_feature(enable = "neon,sha2")]\npub(super) unsafe fn compress_secret(', 'pub(super) unsafe fn compress_secret('),
        ]
        for relative, original, replacement in cases:
            path = root / relative
            before = path.read_text()
            if original not in before: raise AssertionError('stale policy mutation: '+original)
            try:
                path.write_text(before.replace(original, replacement))
                try: policy.validate(root, reviewed=False)
                except ValueError: pass
                else: raise AssertionError('hardened policy mutant survived: '+original)
            finally: path.write_text(before)
        path = root / policy.LEAF / 'src/hardened_execution/unreviewed.rs'
        path.write_text('// unexpected source')
        try: policy.validate(root, reviewed=False)
        except ValueError: pass
        else: raise AssertionError('new source escaped review')
        path.unlink()
        for relative in policy.inventory(root):
            path = root / relative
            before = path.read_bytes()
            try:
                path.write_bytes(before+b'\n// mutation\n')
                try: policy.validate(root)
                except (ValueError, SyntaxError): pass
                else: raise AssertionError('review binding accepted drift: '+relative)
            finally: path.write_bytes(before)
        print(f'Hardened SHA-1: {len(cases)+1} structural and {len(policy.inventory(root))} source-binding regressions rejected')
    # Mutation-test instruction scoping: ordinary-kernel instructions cannot
    # satisfy a missing hardened-kernel body.
    sample = '_RNbrynja_legacy_sha1x86_sha1compress_secret:\n ret\n_RNordinary:\n sha1msg1 xmm0,xmm1\n'
    body = codegen.assembly_function(sample, ('brynja_legacy_sha1', 'x86_sha1', 'compress_secret'))
    assert 'sha1msg1' not in body
    try: codegen.assembly_function(sample+sample, ('brynja_legacy_sha1', 'compress_secret'))
    except ValueError: pass
    else: raise AssertionError('duplicate kernel accepted')


if __name__ == '__main__': main()
