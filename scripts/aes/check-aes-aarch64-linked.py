#!/usr/bin/env python3
"""Review retained native ARM artifacts offline; never rerun timing to populate evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tarfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('arm_linked_native', HERE / 'check-aes-aarch64-native.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
review = native.packaged.module('arm_linked_review', HERE / 'aes_aarch64_linked.py')
wrappers = native.packaged.module('arm_linked_wrappers', HERE / 'aes_aarch64_linked_wrappers.py')
public = native.packaged.module('arm_linked_public', HERE / 'aes_aarch64_linked_public.py')
cleanup = native.packaged.module('arm_linked_cleanup', HERE / 'aes_aarch64_linked_cleanup.py')
ROOT = native.linked.ROOT
RECORD = ROOT / 'assurance/aes-native-observations/v0.27.2/aws-aarch64.json'
ARTIFACTS = 'target/aes-aws-candidate-20261108/linked-artifacts.tar.gz'
SOURCE = 'target/aes-aws-candidate-source-20261108.tar.gz'
MARKER = 'AES ARM linked helper review: 16 retained executables; eleven AES helpers, six secret wrappers, copy and zeroizer each; six public boundaries and six constructors in eight KAT executables; six caller cleanup bodies in eight lifecycle executables with four bound unwind imports; 17756 rejected mutations; other entry points and unwind dispatch unreviewed'
require = review.require


def archive(path, expected):
    require(path.is_file() and not path.is_symlink() and all(not p.is_symlink() for p in path.parents), 'missing/symlinked archive')
    require(path.stat().st_size <= 64 * 1024**2, 'compressed archive size limit')
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == expected, 'archive digest mismatch')
    result, total = {}, 0
    with tarfile.open(path) as handle:
        for member in handle:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts and str(name) == member.name.rstrip('/'), 'invalid archive member path')
            if member.isdir():
                continue
            require(member.isfile() and member.name not in result, 'nonregular/duplicate archive member')
            total += member.size
            require(0 <= member.size <= 32 * 1024**2 and total <= 256 * 1024**2, 'archive size limit')
            result[member.name] = handle.extractfile(member).read()
    return result


def current_sources(files):
    paths = {'Cargo.toml', 'Cargo.lock', 'assurance/aes-public-api/src/lib.rs',
             'assurance/aes-public-api/src/wide.rs', 'assurance/aes-linked/linked.rs',
             'assurance/aes-linked/lifecycle.rs'}
    for name in native.packaged.archives.MODERN:
        crate = ROOT / 'crates' / name
        paths.update(str((crate / relative).relative_to(ROOT)) for relative in native.packaged.archives.package_files(crate))
    for relative in sorted(paths):
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink() and all(not p.is_symlink() for p in path.parents), 'missing/symlinked current source')
        require(relative in files and files[relative] == path.read_bytes(), 'retained source differs from current input: ' + relative)
    return len(paths)


def configuration_paths(entries, compiler):
    require(len(entries) == 24 and len({entry['artifact'] for entry in entries}) == 24, 'artifact population mismatch')
    paths = {entry['artifact'] for entry in entries}
    roots = {str(PurePosixPath(p).parent.parent) for p in paths}
    require(len(roots) == 1, 'mixed compiler artifact roots')
    root = roots.pop()
    require(root.startswith('target/aes-arm-native-' + compiler + '-') and len(PurePosixPath(root).parts) == 2, 'wrong compiler artifact root')
    expected = {f'{root}/{route}-{panic}/{binary}.{suffix}' for route in ('direct', 'facade')
                for panic in ('abort', 'unwind') for binary in ('linked', 'lifecycle') for suffix in ('elf', 'asm', 'nm')}
    require(paths == expected, 'missing/extra compiler configuration')
    return sorted(path[:-4] for path in paths if path.endswith('.elf'))


def check():
    record = json.loads(RECORD.read_text())
    require(record['schema'] == 1 and record['target'] == native.TARGET, 'unsupported retained record')
    def digest(rows, path):
        matches = [row['sha256'] for row in rows if row['path'] == path]
        require(len(matches) == 1, 'missing/duplicate archive record')
        return matches[0]
    source = archive(ROOT / SOURCE, digest(record['source_archives'], SOURCE))
    print('AES ARM retained source files matched:', current_sources(source), flush=True)
    files = archive(ROOT / ARTIFACTS, digest(record['observation_archives'], ARTIFACTS))
    require(len(record['native']) == 2 and {row['compiler'] for row in record['native']} == {'1.90.0', '1.99.1'}, 'compiler population mismatch')
    all_paths = {entry['artifact'] for row in record['native'] for entry in row['artifacts']}
    require(set(files) == all_paths, 'archive artifact population mismatch')
    rejected, count, public_count, cleanup_count = 0, 0, 0, 0
    for config in record['native']:
        compiler = config['compiler']
        require(config['exit_code'] == 0 and config['configurations'] == 4, 'native execution did not complete')
        paths = configuration_paths(config['artifacts'], compiler)
        for entry in config['artifacts']:
            require(hashlib.sha256(files[entry['artifact']]).hexdigest() == entry['sha256'], 'artifact hash mismatch')
        for path in paths:
            image, assembly = files[path + '.elf'], files[path + '.asm'].decode()
            native.elf_check(image)
            nm = files[path + '.nm'].decode()
            selected = review.select(native.linked.symbols(nm), nm, assembly)
            panic = PurePosixPath(path).parent.name.rsplit('-', 1)[1]
            reviews = []
            for role in review.ROLES:
                row = selected[role]
                lines, raw = review.decode(assembly, row)
                targets = {name: selected[name] for name in review.target_roles(role)}
                args = (lines, raw, row, image, targets, role, compiler)
                reviews.append(review.check(*args, panic=panic))
                rejected += review.mutations(*args, panic=panic)
            selected_wrappers = wrappers.select(nm, assembly, selected)
            all_targets = {**selected, **selected_wrappers}
            for role, row in selected_wrappers.items():
                lines, raw = review.decode(assembly, row)
                targets = {name: all_targets[name] for name in wrappers.EDGES[role]}
                args = (lines, raw, row, image, targets, role, compiler, panic)
                reviews.append(wrappers.check(*args))
                rejected += wrappers.mutations(*args)
            if PurePosixPath(path).name == 'linked':
                selected_public = public.select(nm, all_targets)
                all_targets.update(selected_public)
                for role, row in selected_public.items():
                    lines, raw = review.decode(assembly, row)
                    targets = {name: all_targets[name] for name in public.EDGES[role]}
                    args = (lines, raw, row, image, targets, role, compiler, panic)
                    reviews.append(public.check(*args))
                    rejected += public.mutations(*args)
                public_count += 1
            else:
                selected_cleanup = cleanup.select(nm, all_targets)
                targets = {'zeroize': selected['zeroize']}
                if panic == 'unwind':
                    targets['resume'] = cleanup.resume_target(assembly, image)
                    rejected += cleanup.resume_mutations(assembly, image)
                for role, row in selected_cleanup.items():
                    lines, raw = review.decode(assembly, row)
                    args = (lines, raw, row, image, targets, role, compiler, panic)
                    reviews.append(cleanup.check(*args))
                    rejected += cleanup.mutations(*args)
                cleanup_count += 1
            print(json.dumps({'artifact': path + '.elf', 'compiler': compiler, 'helpers': reviews}), flush=True)
            count += 1
    require(count == 16 and public_count == cleanup_count == 8 and rejected == 17756,
            'review/mutation population mismatch')
    print(MARKER, flush=True)


if __name__ == '__main__':
    check()
