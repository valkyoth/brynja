"""Read bounded Git/worktree inputs and classify semantic lockfile changes."""
from __future__ import annotations

import subprocess
import tomllib
import re
import ast
from pathlib import Path

LIMIT = 4 * 1024 * 1024
PACKAGES = {
    'brynja-core': 'core', 'brynja-sanitization': 'sanitization',
    'brynja-legacy-md5': 'md5', 'brynja-legacy-sha1': 'sha1',
    'brynja-hash-sha2': 'sha2', 'brynja-hash-sha3': 'sha3',
    'brynja-mac-kmac': 'kmac', 'brynja-hash-tuple': 'tuplehash',
    'brynja-hash-parallel': 'parallelhash',
    'brynja-legacy-hash-public-api-fixture': 'legacy',
}


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(['git', *args], cwd=root, timeout=30)


def snapshot(root: Path, base: str, path: str) -> tuple[bytes | None, bytes | None]:
    entry = git(root, 'ls-tree', '-z', base, '--', path)
    before = None
    if entry:
        if not entry.startswith(b'100644 blob ') and not entry.startswith(b'100755 blob '):
            raise ValueError('baseline input is not a regular file')
        if int(git(root, 'cat-file', '-s', f'{base}:{path}')) > LIMIT:
            raise ValueError('baseline input exceeds bound')
        before = git(root, 'show', f'{base}:{path}')
    file = root / path
    if file.is_symlink() or any(parent.is_symlink() for parent in file.parents if parent != root):
        raise ValueError('scope input is symlinked')
    if file.is_file() and file.stat().st_size > LIMIT:
        raise ValueError('worktree input exceeds bound')
    after = file.read_bytes() if file.is_file() else None
    if any(value is not None and len(value) > LIMIT for value in (before, after)):
        raise ValueError('scope input exceeds bound')
    return before, after


def document(data: bytes | None) -> dict:
    if data is None:
        raise ValueError('missing semantic input')
    return tomllib.loads(data.decode('utf-8'))


def lock_groups(before: bytes | None, after: bytes | None) -> set[str]:
    """Ignore only local versions, not registry versions/checksums or graph edges."""
    graphs = []
    for data in (before, after):
        parsed = document(data)
        if set(parsed) != {'version', 'package'} or parsed['version'] != 4:
            raise ValueError('unknown lock schema')
        graph = {}
        for raw in parsed['package']:
            package = dict(raw)
            name = package['name']
            if name in graph:
                raise ValueError('ambiguous multi-version lock package')
            dependencies = package.get('dependencies', [])
            if any(not isinstance(dep, str) or len(dep.split()) != 1 for dep in dependencies):
                raise ValueError('ambiguous dependency identifier')
            if 'source' not in package:
                # Local version numbers are not code identities. Source and
                # manifest changes are independently classified from Git.
                package.pop('version')
            graph[name] = package
        if any(dep not in graph for p in graph.values() for dep in p.get('dependencies', [])):
            raise ValueError('unresolved lock edge')
        graphs.append(graph)
    old, new = graphs
    changed = {name for name in old.keys() | new.keys() if old.get(name) != new.get(name)}
    # Traverse BOTH graphs so removing an edge cannot hide an affected consumer.
    affected = set(changed)
    while True:
        extra = {name for graph in graphs for name, p in graph.items()
                 if affected.intersection(p.get('dependencies', []))}
        if extra <= affected:
            break
        affected |= extra
    known = set(PACKAGES) | {'brynja-hash-core'}
    for name in changed:
        raw = new.get(name, old.get(name, {}))
        if 'source' not in raw and name not in known:
            raise ValueError('unknown changed local package')
        if 'source' in raw:
            reached = {name}
            while True:
                parents = {n for g in graphs for n, p in g.items()
                           if reached.intersection(p.get('dependencies', []))}
                if parents <= reached:
                    break
                reached |= parents
            if not reached.intersection(PACKAGES):
                raise ValueError('external change without classified consumer')
    return {group for name, group in PACKAGES.items() if name in affected}


def version_only(before: bytes | None, after: bytes | None) -> bool:
    left, right = document(before), document(after)
    def local_versions(value):
        if isinstance(value, dict):
            if isinstance(value.get('path'), str):
                value.pop('version', None)
            for child in value.values():
                local_versions(child)
        elif isinstance(value, list):
            for child in value:
                local_versions(child)
    for parsed in (left, right):
        parsed.get('package', {}).pop('version', None)
        local_versions(parsed)
    return left == right


def facade_pin_only(before: bytes | None, after: bytes | None, old: str, new: str) -> bool:
    if before is None or after is None:
        return False
    for version in (old, new):
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
            return False
    expected = before.replace(f'"{old}"'.encode(), f'"{new}"'.encode())
    expected = expected.replace(f'"={old}"'.encode(), f'"={new}"'.encode())
    return python_bindings_only(expected, after)


def python_bindings_only(before: bytes | None, after: bytes | None) -> bool:
    """Ignore digest values only in named top-level source inventory maps."""
    if before is None or after is None:
        return False
    def normalized(raw):
        tree = ast.parse(raw)
        for node in tree.body:
            target, value = None, None
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target, value = node.targets[0], node.value
            elif isinstance(node, ast.AnnAssign):
                target, value = node.target, node.value
            if (isinstance(target, ast.Name) and target.id in {'EXPECTED_SHA256', 'SOURCE_HASHES', 'TEST_HASHES', 'REVIEWED_HASHES'}
                    and isinstance(value, ast.Dict)):
                for item in value.values:
                    if isinstance(item, ast.Constant) and isinstance(item.value, str) and re.fullmatch(r'[a-f0-9]{64}', item.value):
                        item.value = 'SOURCE-DIGEST'
        return ast.dump(tree)
    return normalized(before) == normalized(after)


def verifier_only(before: bytes | None, after: bytes | None) -> bool:
    left, right = document(before), document(after)
    for parsed in (left, right):
        for tool in parsed.get('tools', []):
            if tool.get('id') in {'miri', 'rust-sanitizers'}:
                for key in ('version', 'revision', 'execution_toolchain'):
                    tool.pop(key, None)
    return left == right


def matrix_verifier_only(before: bytes | None, after: bytes | None) -> bool:
    left, right = document(before), document(after)
    for parsed in (left, right):
        parsed.get('dynamic', {}).pop('toolchain', None)
    return left == right


def hash_binding_only(before: bytes | None, after: bytes | None) -> bool:
    """Digest rebinding is metadata; changed source paths still select owners."""
    def scrub(value):
        if isinstance(value, dict):
            return {key: scrub(child) for key, child in value.items()}
        if isinstance(value, list):
            return [scrub(child) for child in value]
        if isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value):
            return 'SHA256-BINDING'
        return value
    return scrub(document(before)) == scrub(document(after))


def fixture_lock(data: bytes, workspace: bytes, manifest: bytes) -> None:
    parsed = document(data)
    if set(parsed) != {'version', 'package'} or parsed['version'] != 4:
        raise ValueError('unknown fixture lock schema')
    package = document(manifest)['package']
    if package.get('publish') is not False or not package['name'].endswith('-fixture'):
        raise ValueError('not an unpublished assurance fixture')
    packages = document(workspace)['package']
    names = [p['name'] for p in parsed['package']]
    if len(names) != len(set(names)) or names.count(package['name']) != 1:
        raise ValueError('duplicate or missing fixture package')
    for entry in parsed['package']:
        if entry['name'] == package['name']:
            if (set(entry) - {'name', 'version', 'dependencies'}
                    or entry['version'] != package['version']
                    or not set(entry.get('dependencies', [])) <= set(names) - {package['name']}):
                raise ValueError('invalid fixture identity or edge')
        elif entry not in packages:
            raise ValueError('fixture lock changes dependency closure')


def runner_groups(before: bytes | None, after: bytes | None) -> set[str]:
    """Only named group bodies may change without selecting the whole suite."""
    if before is None or after is None:
        raise ValueError('missing runner')
    parsed = []
    pattern = re.compile(r'^([a-z0-9_]+)\(\) \{\n.*?^\}\n', re.M | re.S)
    for raw in (before, after):
        text = raw.decode('utf-8')
        text = re.sub(r'nightly-\d{4}-\d{2}-\d{2}', 'nightly-PIN', text)
        functions = {m[1]: m[0] for m in pattern.finditer(text)}
        if len(functions) != len(list(pattern.finditer(text))):
            raise ValueError('duplicate shell function')
        parsed.append((pattern.sub('', text), functions))
    (old_shell, old), (new_shell, new) = parsed
    inventories = []
    for shell in (old_shell, new_shell):
        matches = re.findall(r'^all_groups=\(([a-z0-9_ ]+)\)$', shell, re.M)
        if len(matches) != 1:
            raise ValueError('missing group inventory')
        groups = matches[0].split()
        if len(groups) != len(set(groups)) or not set(groups) <= set(PACKAGES.values()):
            raise ValueError('unknown group inventory')
        inventories.append(set(groups))
    def shell_body(shell):
        shell = re.sub(r'^all_groups=.*$', 'all_groups=REGISTERED', shell, flags=re.M)
        return re.sub(r'\n(?:[ \t]*\n)+', '\n', shell).strip()
    if (not inventories[0] <= inventories[1] or not old.keys() <= new.keys()
            or shell_body(old_shell) != shell_body(new_shell)):
        raise ValueError('runner orchestration changed or coverage removed')
    groups = set()
    for name in new:
        if old.get(name) == new[name]:
            continue
        if not name.startswith(('quick_', 'full_')):
            raise ValueError('shared runner helper changed')
        group = name.split('_', 1)[1]
        if group not in PACKAGES.values():
            raise ValueError('unknown runner group')
        # A revised smoke case is executed by every focused run already.
        # Only full-campaign changes invalidate that group's full evidence.
        if name.startswith('full_'):
            groups.add(group)
    return groups
