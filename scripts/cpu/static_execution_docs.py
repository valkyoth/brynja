"""Bind current static reachability claims to the public surface and inventory."""
import ast
from pathlib import Path
import shutil
import tempfile
import tomllib

DOCS = ('docs/unsafe-policy.md', 'docs/threat-model.md', 'docs/security-controls.md')
MANIFEST = 'crates/brynja-crypto-cpu/Cargo.toml'
LIBRARY = 'crates/brynja-crypto-cpu/src/lib.rs'
INVENTORY = 'scripts/repository/unsafe_policy.py'
FILES = (*DOCS, MANIFEST, LIBRARY, INVENTORY)
CLAIMS = (
    'default-off `static-execution` feature exposes five ordinary raw kernels:',
    'x86 SHA-256, x86 AVX2 Keccak, Arm SHA-256, Arm SHA-512 and Arm SHA3 Keccak.',
    '`static_execution::Authority` requires the complete compiler feature bundle,',
    'the specialized executable platform contract and a direct kernel KAT',
    'Default hash constructors remain portable.',
)


def validate(root):
    texts = {name: (root / name).read_text(encoding='utf-8') for name in FILES}
    features = tomllib.loads(texts[MANIFEST]).get('features')
    if features != {'default': [], 'static-execution': [], 'runtime-execution': ['static-execution']}:
        raise ValueError('documented static feature no longer matches the manifest')
    if '#[cfg(feature = "static-execution")]\npub mod static_execution;' not in texts[LIBRARY]:
        raise ValueError('documented static module no longer matches its public gate')
    for name in DOCS:
        normalized = ' '.join(texts[name].split())
        for claim in CLAIMS:
            if claim not in normalized:
                raise ValueError(f'{name}: missing static reachability contract: {claim}')
        for stale in ('unreachable from ordinary execution', 'ordinary execution scalar/fail-closed',
                      'healthy KAT cannot authorize ordinary execution',
                      'reachable only through architecture-checked, thread-bound, direct-KAT-gated evidence sessions'):
            if stale in normalized:
                raise ValueError(f'{name}: stale ordinary reachability claim')
    inventory = [node.value for node in ast.parse(texts[INVENTORY]).body
                 if isinstance(node, ast.Assign) and any(
                     isinstance(target, ast.Name) and target.id == 'ALLOWED' for target in node.targets)]
    if len(inventory) != 1 or not isinstance(inventory[0], ast.Dict):
        raise ValueError('unsafe inventory is not an explicit dictionary')
    words = 'zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty'.split()
    count = len(inventory[0].keys)
    if count >= len(words):
        raise ValueError('extend the reviewed documentation count vocabulary')
    unsafe = ' '.join(texts[DOCS[0]].split())
    for claim in (f'Status: {words[count]} exact source-hash-bound exceptions',
                  f'Rust in only {words[count]} exact modules:'):
        if claim not in unsafe:
            raise ValueError('unsafe-policy displayed count differs from ALLOWED')
    if 'source-hash-bound module inventory' not in texts[DOCS[2]]:
        raise ValueError('security controls must link the authoritative module inventory')


def regressions(root):
    cases = [(name, claim, 'omitted') for name in DOCS for claim in CLAIMS]
    # Replace normalized text in disposable copies; source hashes are not used
    # here, so each test must fail for a semantic contract discrepancy.
    cases += [
        (DOCS[0], 'Status: seventeen exact', 'Status: nine exact'),
        (DOCS[0], 'Rust in only seventeen exact', 'Rust in only nine exact'),
        (DOCS[2], 'source-hash-bound module inventory', 'exactly nine modules'),
        (MANIFEST, 'default = []', 'default = ["static-execution"]'),
        (LIBRARY, 'pub mod static_execution;', 'mod static_execution;'),
        (INVENTORY, 'ALLOWED = {', 'ALLOWED = {"extra": (),'),
    ]
    for name in DOCS:
        cases.append((name, 'Default hash constructors remain portable.',
                      'Default hash constructors remain portable. Kernels are unreachable from ordinary execution.'))
    with tempfile.TemporaryDirectory(prefix='brynja-static-docs-') as directory:
        fixture = Path(directory)
        for name in FILES:
            destination = fixture / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, destination)
        validate(fixture)
        for name, before, after in cases:
            path = fixture / name
            original = path.read_text(encoding='utf-8')
            baseline = ' '.join(original.split()) if name in DOCS else original
            if before not in baseline:
                raise AssertionError(f'stale documentation mutant: {name}: {before}')
            path.write_text(baseline.replace(before, after, 1), encoding='utf-8')
            try:
                validate(fixture)
            except ValueError:
                pass
            else:
                raise AssertionError(f'documentation mutant accepted: {name}: {before}')
            finally:
                path.write_text(original, encoding='utf-8')
    print(f'Static reachability documentation rejects {len(cases)} semantic regressions')
