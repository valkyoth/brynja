"""Exact multibuffer Keccak assembly inspection; not side-channel qualification."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(command, env=None):
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            capture_output=True, timeout=300)
    if result.returncode:
        raise ValueError(f'{command}\n{result.stdout[-4000:]}\n{result.stderr[-4000:]}')
    return result.stdout


def inspect(assembly, target):
    if target.startswith('x86_64-'):
        architecture = 'x86'
        required = (r'vpxor\s+[^\n]*%?ymm\d+', r'vpandn\s+[^\n]*%?ymm\d+',
                    r'vpsllvq\s+[^\n]*%?ymm\d+', r'vpsrlvq\s+[^\n]*%?ymm\d+')
    elif target.startswith('aarch64-'):
        architecture = 'arm'
        # Apple's target baseline allows the compiler to fuse XOR/AND-NOT
        # into BCAX. The 1.90 compiler does so; generic Linux remains NEON.
        chi = '(?:bic|bcax)' if target == 'aarch64-apple-darwin' else 'bic'
        required = (r'eor(?:3)?(?:\s+v\d+\.16b|\.16b\s+v\d+)',
                    chi + r'(?:\s+v\d+\.16b|\.16b\s+v\d+)',
                    r'ushl(?:\s+v\d+\.2d|\.2d\s+v\d+)')
    else:
        raise ValueError('unsupported SIMD evidence target')
    # Exclude comments before matching: a quoted symbol or mnemonic is not code.
    assembly = re.sub(r'(?m)(?://|#)[^\n]*', '', assembly)
    pattern = (r'^[_A-Za-z][^\n:]*keccak_batch[^\n:]*' + architecture +
               r'[^\n:]*permute[^\n:]*:[ \t]*\n')
    starts = list(re.finditer(pattern, assembly, re.M))
    if len(starts) != 1:
        raise ValueError('missing/ambiguous independent Keccak permutation symbol')
    tail = assembly[starts[0].end():]
    if '.cfi_endproc' not in tail:
        raise ValueError('missing permutation function end')
    body = tail.split('.cfi_endproc', 1)[0]
    if re.search(r'(?m)^\s*\.(?:globl|global)\b', body):
        raise ValueError('permutation body crosses function boundary')
    if any(not re.search(r'(?m)^\s*' + token, body) for token in required):
        raise ValueError('independent SIMD operations absent from exact kernel')
    return body


def check(target, toolchain='1.98.1'):
    with tempfile.TemporaryDirectory(prefix='brynja-keccak-batch-codegen-') as temporary:
        env = dict(os.environ, CARGO_TARGET_DIR=temporary)
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
            env.pop(key, None)
        run(['cargo', '+' + toolchain, 'rustc', '--locked', '--offline', '--release',
             '-p', 'brynja-crypto-cpu', '--features', 'keccak-batch', '--target', target,
             '--', '--emit=asm'], env)
        paths = list((Path(temporary) / target / 'release/deps').glob('brynja_crypto_cpu-*.s'))
        if len(paths) != 1:
            raise ValueError('missing/ambiguous emitted assembly artifact')
        assembly = paths[0].read_text()
        inspect(assembly, target)
        tokens = (('vpxor',), ('vpandn',), ('vpsllvq',), ('vpsrlvq',)) if target.startswith('x86_64-') else (('eor',), ('bic', 'bcax'), ('ushl',))
        for group in tokens:
            mutant = assembly
            for token in group: mutant = mutant.replace(token, 'removed_instruction')
            try:
                inspect(mutant, target)
            except ValueError:
                pass
            else:
                raise ValueError('instruction-removal mutant survived: ' + repr(group))
    print(f'Keccak independent SIMD codegen: PASS; {toolchain}; {target}')
