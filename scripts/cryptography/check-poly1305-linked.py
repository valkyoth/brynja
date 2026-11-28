"""Replay and screen the normal verification path of two named x86-64 Linux ELFs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/aes-gcm'))
sys.path.insert(0, str(ROOT / 'scripts/repository'))
import facade_cargo_environment as environment
import paired_linked as elf

spec = importlib.util.spec_from_file_location('vectors', Path(__file__).with_name('test-poly1305-vectors.py'))
vectors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vectors)

VERIFY = 'brynja_mac_poly1305::Poly1305::verify'
WRAPPER = 'poly1305_consumer::verify_record'
BODIES = (VERIFY, elf.ACC, elf.BYTE, elf.PRED, elf.MASK, elf.CORE + '::clear_owned_region',
          elf.CORE + '_volatile::zeroize_region_volatile')
PINS = {
    '1.90.0': '284ce073054f7843d3ce2aa773812466d0a693842e4f17d644f7d61d4ccde8a5',
    '1.100.0': '35120eb0ca439702011dfc91f33f17aa3590217b5652ec383ad47a44059596de',
}


def instructions(image, name):
    addr = elf.unique(image, name)
    result = []
    for op, arg in image.bodies[addr]:
        if '(%rip)' in arg:
            # Resolve the actual ELF relocation. Do not trust the nearest-symbol comment.
            match = re.fullmatch(r'(\*?)[-+0-9a-fx]+\(%rip\)([^#]*?)\s*# 0x([a-f0-9]+)(?: .*)?', arg)
            if not match or (dest := image.slots.get(int(match[3], 16))) not in image.names:
                raise ValueError('unresolved RIP operand in ' + name)
            arg = match[1] + 'GOT:' + image.names[dest] + match[2]
        elif (op.startswith('j') or op == 'callq') and (m := elf.DIRECT.match(arg)):
            dest = int(m[1], 16)
            arg = image.names.get(dest, f'offset:{dest - addr}')
        result.append((op, arg))
        if name == VERIFY and op == 'retq':
            break  # exception landing pads are outside this normal-return observation
    while result and result[-1][0] == 'int3':
        result.pop()
    return result


def fingerprint(image):
    if not image.children(elf.unique(image, WRAPPER), VERIFY):
        raise ValueError('downstream wrapper does not call the inspected verifier')
    trace = [(name, instructions(image, name)) for name in BODIES]
    return hashlib.sha256(json.dumps(trace, separators=(',', ':')).encode()).hexdigest()


def main():
    for version, expected in PINS.items():
        with environment.private_directory(ROOT) as tmp:
            root = Path(tmp)
            env = {k: os.environ[k] for k in ('PATH', 'HOME', 'RUSTUP_HOME') if k in os.environ}
            env.update(CARGO_HOME=str(root / 'cargo-home'), CARGO_TARGET_DIR=str(root / 'target'),
                       CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0')
            environment.check(root, env)
            subprocess.run(['cargo', '+' + version, 'build', '--locked', '--offline', '--release',
                            '--target', 'x86_64-unknown-linux-gnu', '--manifest-path',
                            str(ROOT / 'assurance/poly1305/Cargo.toml')], env=env, cwd=root,
                           check=True, timeout=180)
            exe = root / 'target/x86_64-unknown-linux-gnu/release/poly1305-consumer'
            digest = elf.digest(exe)
            actual = fingerprint(elf.load(exe))
            if actual != expected:
                raise ValueError(f'{version}: linked verifier changed ({actual}); review before repinning')
            vectors.replay(version, [str(exe)])
            if elf.digest(exe) != digest:
                raise ValueError('executable changed during replay')
            print(f'{version}: reviewed normal-return verifier and helpers; ELF sha256 {digest}')
    print('Poly1305 linked verifier: both x86-64 endpoints passed')


if __name__ == '__main__':
    main()
