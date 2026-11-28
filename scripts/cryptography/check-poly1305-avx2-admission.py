"""Replay the unpublished required-native streaming experiment on stock Linux x86-64."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/repository'))
sys.path.insert(0, str(ROOT / 'scripts/aes-gcm'))
import facade_cargo_environment as cargo
import paired_linked as elf

PREFIX = 'four_block_probe::avx2::'
GOOD = 'required AVX2: KAT and long-update comparison passed\n'
CORPUS = ('AVX2 four-block probe: 12 RFC vectors and 2112 portable comparisons passed\n'
          'Streaming probe: 12 RFC vectors and 8448 partitioned portable comparisons passed\n')


def screen(image, version):
    group = elf.unique(image, PREFIX + 'group')
    groups = elf.unique(image, PREFIX + 'stream::groups')
    if group not in image.calls(groups):
        raise ValueError('long-update kernel does not call the four-block group')
    for name in ('admission::Required::probe', 'stream::candidate'):
        if groups not in image.calls(elf.unique(image, PREFIX + name)):
            raise ValueError(name + ' does not call the screened kernel')
    leaf, expected = group, 25
    if version == '1.90.0':
        leaf = elf.unique(image, PREFIX + 'group::_$u7b$$u7b$closure$u7d$$u7d$')
        if list(image.calls(group)).count(leaf) != 5:
            raise ValueError('missing outlined five-column path')
        expected = 5
    elif version != '1.100.0':
        raise ValueError('unknown compiler')
    if sum(op == 'vpmuludq' and '%ymm' in args for op, args in image.bodies[leaf]) != expected:
        raise ValueError('missing four-lane unsigned multiply')
    return leaf


def replay(cmd, env, cwd, expected):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=90, cwd=cwd, env=env)
    if (p.returncode, p.stdout, p.stderr) != expected:
        raise ValueError(f'unexpected replay: {p.returncode}, {p.stdout!r}, {p.stderr!r}')


def check(version):
    with cargo.private_directory(ROOT) as tmp:
        root = Path(tmp)
        env = {k: os.environ[k] for k in ('PATH', 'HOME', 'RUSTUP_HOME') if k in os.environ}
        env.update(CARGO_HOME=str(root / 'cargo'), CARGO_TARGET_DIR=str(root / 'target'),
                   CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0')
        cargo.check(root, env)
        target = 'x86_64-unknown-linux-gnu'
        subprocess.run(['cargo', '+' + version, 'build', '--locked', '--offline', '--release',
                        '--target', target, '--manifest-path', str(ROOT / 'assurance/poly1305/Cargo.toml'),
                        '--example', 'four_block_probe'], cwd=root, env=env, check=True, timeout=180)
        exe = root / 'target' / target / 'release/examples/four_block_probe'
        digest = elf.digest(exe)
        image = elf.load(exe)
        leaf = screen(image, version)
        # Negative control on the parsed listing only; the executed ELF is unchanged.
        image.bodies[leaf] = [(op, args) for op, args in image.bodies[leaf] if op != 'vpmuludq']
        try:
            screen(image, version)
        except ValueError as failure:
            if str(failure) != 'missing four-lane unsigned multiply':
                raise
        else:
            raise ValueError('screen accepted missing vector multiplication')
        replay([exe], env, root, (0, CORPUS, ''))
        cmd = [exe, '--check-admission']
        replay(cmd, env, root, (0, GOOD, ''))
        for cpu, result in [('max', (0, GOOD, '')),
                            ('max,-avx2', (2, '', 'required AVX2: unavailable\n'))]:
            replay(['qemu-x86_64', '-cpu', cpu, *cmd], env, root, result)
        if elf.digest(exe) != digest:
            raise ValueError('executable changed during replay')
        print(f'Rust {version}: native corpus, linked kernel and QEMU ISA controls passed; ELF {digest}')


if __name__ == '__main__':
    for endpoint in ('1.90.0', '1.100.0'):
        check(endpoint)
