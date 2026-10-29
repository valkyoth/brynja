"""Static, complete unittest groups for the two expensive hosted cleanup suites.

No archived Python is imported. Every discovered test is assigned exactly once;
unknown inheritance, aliases and duplicate method names fail closed.
"""
import ast
import shlex
from pathlib import PurePosixPath

import detached_manifest as records
import miri_coverage_identity as miri_identity

SUITES = {
    'scripts/hmac/test-hmac-hosted-cleanup.py': 'HostedTests',
    'scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py': 'Hosted',
}
GROUP_SIZE = 4


def groups(root, script):
    if script not in SUITES:
        raise ValueError('unregistered unittest suite')
    seen, active, modules = {}, set(), {}

    def visit(path, name):
        key = (path, name)
        if key in active or len(active) > 32:
            raise ValueError('unittest inheritance cycle')
        active.add(key)
        records.file_hash(root / path, 1024 * 1024)
        tree = ast.parse((root / path).read_bytes())
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name]
        if len(classes) != 1:
            raise ValueError('missing/duplicate unittest class')
        cls = classes[0]
        imports = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and not node.level and node.module:
                for item in node.names:
                    if item.asname or item.name == '*':
                        continue
                    imports[item.name] = node.module
        for base in cls.bases:
            if isinstance(base, ast.Attribute) and ast.unparse(base) == 'unittest.TestCase':
                continue
            if not isinstance(base, ast.Name) or base.id not in imports:
                raise ValueError('unknown unittest base')
            module = imports[base.id]
            if not module.isidentifier():
                raise ValueError('nonlocal unittest mixin')
            visit(str(PurePosixPath(path).parent / (module + '.py')), base.id)
        for node in cls.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_'):
                if node.name in seen or isinstance(node, ast.AsyncFunctionDef):
                    raise ValueError('duplicate/unsupported unittest method')
                seen[node.name] = path
                modules.setdefault(path, []).append(SUITES[script] + '.' + node.name)
        active.remove(key)

    visit(script, SUITES[script])
    if not seen or len(seen) > 1024:
        raise ValueError('empty/oversized unittest population')
    result = []
    for path in sorted(modules):
        names = sorted(modules[path])
        result.extend(names[i:i + GROUP_SIZE] for i in range(0, len(names), GROUP_SIZE))
    return result


def expand(entry, root):
    argv = entry['argv']
    if entry['phase'] != 'repository' or len(argv) != 2 or argv[0] != 'python3' or argv[1] not in SUITES:
        return [entry]
    return [{**entry, 'argv': argv + names, 'command': shlex.join(argv + names)}
            for names in groups(root, argv[1])]


def covers(old, new, old_root, new_root, *, miri=None):
    # Even byte-identical command lines may refer to different Miri cases after
    # catalog edits. Resolve before the ordinary exact-command shortcut.
    if miri_identity.is_task(old) or miri_identity.is_task(new):
        resolver = miri or miri_identity.Coverage(old_root, new_root)
        return resolver.covers(old, new)
    if old == new:
        return True
    # A successful old whole suite can cover its unchanged, enumerated subsets.
    # Never use an internal success line from a failed whole-suite command.
    if old['argv'][:2] != new['argv'][:2] or len(old['argv']) != 2:
        return False
    if old['argv'][1] not in SUITES or groups(old_root, old['argv'][1]) != groups(new_root, old['argv'][1]):
        return False
    return new in expand(old, new_root)
