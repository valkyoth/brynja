"""Replay the unpublished two-block probe under AArch64 QEMU. Never benchmark QEMU."""
import hashlib
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/repository'))
import facade_cargo_environment as cargo

oracle = runpy.run_path(str(Path(__file__).with_name('test-poly1305-vectors.py')))
TARGET = 'aarch64-unknown-linux-musl'
NAME = r'neon_two_block::neon_probe::two_blocks(?:::h[0-9a-f]{16})?'


def corpus():
    rows = list(oracle['vectors']())
    for length in (*range(258), 511, 512, 513, 1500, 4096, 16384):
        for seed in range(8):
            label = f'neon:{seed}:{length}'
            if seed < 2:
                key = bytes([255 * seed]) * 32
                msg = b'\xff' * length
            else:
                key = hashlib.sha256(label.encode()).digest()
                msg = hashlib.shake_256(b'message:' + label.encode()).digest(length)
            rows.append((label, key, msg, oracle['reference'](key, msg)))
    return rows


def screen(listing):
    bodies = re.findall(r'^([0-9a-f]+) <(' + NAME + r')>:\n(.*?)(?=\n\n|\Z)',
                        listing, re.M | re.S)
    if len(bodies) != 1:
        raise ValueError('expected one two-block kernel')
    addr, name, body = bodies[0]
    if not re.search(r'\bbl\s+0x' + format(int(addr, 16), 'x') + ' <' + re.escape(name) + '>', listing):
        raise ValueError('missing linked call to two-block kernel')
    for op, count in [('umull', 5), ('umlal', 20)]:
        if len(re.findall(r'\b' + op + r'\s+v\d+\.2d, v\d+\.2s, v\d+\.2s', body)) != count:
            raise ValueError('missing vector product: ' + op)


def check(version, rows):
    with cargo.private_directory(ROOT) as tmp:
        root = Path(tmp)
        env = {k: os.environ[k] for k in ('PATH', 'HOME', 'RUSTUP_HOME') if k in os.environ}
        env.update(CARGO_HOME=str(root / 'cargo'), CARGO_TARGET_DIR=str(root / 'target'),
                   RUSTUP_AUTO_INSTALL='0', CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER='rust-lld')
        cargo.check(root, env)
        subprocess.run(['cargo', '+' + version, 'build', '--locked', '--offline', '--release',
                        '--manifest-path', str(ROOT / 'assurance/poly1305/Cargo.toml'), '--target',
                        TARGET, '--example', 'neon_two_block'], cwd=root, env=env, check=True, timeout=180)
        exe = root / 'target' / TARGET / 'release/examples/neon_two_block'
        digest = hashlib.sha256(exe.read_bytes()).hexdigest()
        listing = subprocess.check_output(['llvm-objdump', '-d', '--demangle', exe], text=True)
        screen(listing)
        try:
            screen(listing.replace('umlal', 'nop'))
        except ValueError as err:
            if str(err) != 'missing vector product: umlal':
                raise
        else:
            raise ValueError('instruction screen ignored the negative control')

        def replay(records):
            data = ''.join(f'{k.hex()}\t{m.hex()}\t{t.hex()}\n' for _, k, m, t in records)
            return subprocess.run(['qemu-aarch64', '-cpu', 'max', exe], input=data,
                                  text=True, capture_output=True, timeout=90)

        result = replay(rows)
        if (result.returncode, result.stdout, result.stderr) != (0, f'matched {len(rows)} public vectors\n', ''):
            raise ValueError('incomplete or failed QEMU replay: ' + result.stderr)
        label, k, m, t = rows[-1]
        bad = replay([(label, k, m, bytes([t[0] ^ 1]) + t[1:])])
        if bad.returncode == 0 or bad.stdout or 'vector mismatch' not in bad.stderr:
            raise ValueError('wrong-answer control did not reject the tag')
        if hashlib.sha256(exe.read_bytes()).hexdigest() != digest:
            raise ValueError('ELF changed during replay')
        print(f'Rust {version}: {len(rows)} AArch64 QEMU records, linked kernel and controls passed; ELF {digest}')


if __name__ == '__main__':
    records = corpus()
    for endpoint in ('1.90.0', '1.100.0'):
        check(endpoint, records)
