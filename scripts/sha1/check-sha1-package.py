#!/usr/bin/env python3
"""Exercise the real SHA-1 consumer against packaged, not workspace, sources."""
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLOSURE = {'brynja-core': '0.9.0', 'brynja-hash-core': '0.1.0', 'brynja-legacy-sha1': '0.1.0'}


def main():
    with tempfile.TemporaryDirectory(prefix='brynja-sha1-package-') as temporary:
        root = Path(temporary)
        environment = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target'))
        command = ['cargo', 'package', '--locked', '--offline', '--allow-dirty', '--no-verify']
        for package in CLOSURE: command.extend(['-p', package])
        subprocess.run(command, cwd=ROOT, env=environment, check=True, timeout=180)
        for package, version in CLOSURE.items():
            prefix = f'{package}-{version}'
            archive = root / 'target/package' / (prefix + '.crate')
            total = 0
            with tarfile.open(archive) as handle:
                for member in handle:
                    path = Path(member.name)
                    total += member.size
                    if (path.is_absolute() or '..' in path.parts or not path.parts
                            or path.parts[0] != prefix or not member.isfile()
                            or total > 16 * 1024 * 1024):
                        raise ValueError('unexpected package archive entry')
                    destination = root / 'unpacked' / path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    stream = handle.extractfile(member)
                    if stream is None: raise ValueError('missing archive contents')
                    destination.write_bytes(stream.read())
        consumer = root / 'consumer'
        (consumer / 'src').mkdir(parents=True)
        manifest = '[package]\nname="sha1-packaged-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n'
        manifest += '[dependencies]\nbrynja-legacy-sha1 = { version="=0.1.0", default-features=false }\n[patch.crates-io]\n'
        for package, version in CLOSURE.items():
            manifest += f'{package} = {{ path="../unpacked/{package}-{version}" }}\n'
        (consumer / 'Cargo.toml').write_text(manifest)
        (consumer / 'src/lib.rs').write_bytes((ROOT / 'assurance/sha1-public-api/src/lib.rs').read_bytes())
        subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=consumer, env=environment, check=True, timeout=60)
        subprocess.run(['cargo', 'test', '--locked', '--offline'], cwd=consumer, env=environment, check=True, timeout=180)
    print('SHA-1 packaged closure and external consumer: PASS; no upload')


if __name__ == '__main__': main()
