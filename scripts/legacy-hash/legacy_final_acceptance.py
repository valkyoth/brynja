"""Frozen consumer and explicitly non-authorizing final SHA-1/MD5 closure."""
import hashlib
import ast
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[2]
MAX_INPUT_BYTES = 4 * 1024 * 1024
FIXTURE = 'assurance/legacy-hash-final'
FROZEN = 'scripts/legacy-hash/frozen-v02420.toml'
SNAPSHOT = 'scripts/legacy-hash/native-source-snapshot.toml'
HASHES = 'scripts/legacy-hash/final-reviewed.toml'
CLAIMS = FIXTURE + '/claims.toml'
PACKAGES = ('brynja-core', 'brynja-hash-core', 'brynja-legacy-sha1',
            'brynja-legacy-md5', 'brynja-legacy-sha1-std', 'brynja-legacy-md5-std')
FROZEN_FILES = tuple('assurance/legacy-hash-public-api/' + name for name in (
    'Cargo.toml', 'Cargo.lock', 'src/lib.rs', 'src/main.rs', 'src/profiles.rs',
    'src/vectors.rs', 'fixtures/representative.txt', 'fixtures/archive-index.json'))
MD5_CAPTURES = {
    'amd-x86_64': 'e092daaba7b38affb472e1dd888d826a5f9e3ff815bf8800b25949ac48f787ca',
    'intel-x86_64': 'a3d365099bf401081f2e140ddeb48e98acbe777cdb2ed21edb420e7e768e3798',
    'aws-aarch64': '82204c471391acf0a264855a75d153b8e7774e42c1ce7bf86425a23d767c3ce3',
    'apple-m2-aarch64': 'e7e1db7b97aed25a13db94a9faba53222f9cea6dd91a9404a6a7039ed7311095',
}


def read(root, path):
    relative = Path(path)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('acceptance input must stay within the repository')
    file = root / path
    if root.is_symlink() or file.is_symlink() or not file.is_file() or file.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError('missing, symlinked or oversized acceptance input: ' + path)
    # Inspect repository-owned ancestors only. macOS may expose its trusted
    # temporary directory through /var -> /private/var above the chosen root.
    parent = file.parent
    while parent != root:
        if parent.is_symlink():
            raise ValueError('symlinked acceptance parent: ' + path)
        parent = parent.parent
    # Trusted, quiescent checkout required: these portable path checks do not
    # contain hostile concurrent filesystem mutation. Bound the actual read
    # too, so growth after stat cannot cause an unbounded allocation.
    with file.open('rb') as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('acceptance input grew beyond the read bound: ' + path)
    # Match read_text's universal newline normalization on all supported hosts.
    return raw.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n')


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def inventory(root=ROOT):
    files = set(FROZEN_FILES) | {FROZEN, SNAPSHOT, CLAIMS, 'docs/legacy-hash-final-acceptance.md',
        'scripts/checks.sh', 'scripts/ci/check-rust-version-matrix.sh',
        'scripts/assurance/check-bare-metal.sh', '.github/workflows/ci.yml',
        'scripts/zeroization/check-zeroization-miri.sh',
        'scripts/zeroization/check-zeroization-sanitizer.sh',
        'security/sha1-cpu-admissions.toml', 'security/md5-cpu-admissions.toml',
        'security/pentest/v0.24.21.md'}
    files.update(FIXTURE + '/' + name for name in ('Cargo.toml', 'Cargo.lock',
        'src/lib.rs', 'src/main.rs', 'src/batch.rs'))
    files.update('scripts/legacy-hash/' + name for name in (
        'legacy_final_acceptance.py', 'check-legacy-final-acceptance.py', 'test-legacy-final-acceptance.py',
        'final_batch_mutations.py'))
    for package in PACKAGES:
        base = root / 'crates' / package
        files.add(f'crates/{package}/Cargo.toml')
        files.update(p.relative_to(root).as_posix() for p in (base / 'src').rglob('*.rs'))
    return sorted(files)


def claims(root):
    document = tomllib.loads(read(root, CLAIMS))
    expected = {
        'schema': 1, 'milestone': '0.24.23', 'families': ['SHA-1', 'MD5'],
        'status': 'fully-implemented', 'portable': ['ordinary-byte', 'ordinary-bit',
            'hardened-byte', 'hardened-bit', 'streaming', 'one-shot'],
        'md5_batch': ['ordinary-public', 'hardened-public', 'hardened-secret'],
        'accelerated_admissions': [], 'independent_review': False, 'fips_validated': False,
        'collision_resistant': False, 'modern_default': False, 'hardened_simd': False,
        'sha1_native': 'historical-review-only; original private captures unavailable',
        'md5_native': 'archived-original-captures; unchanged implementation; not a new run',
        'riscv': 'no implemented legacy backend; unsupported, portable fallback only',
        'avx512': 'not implemented; no admission',
        'migration_safety': 'unproven', 'register_erasure': 'not guaranteed',
    }
    if document != expected:
        raise ValueError('final claims differ from the reviewed legacy-only disposition')


def validate_native(root):
    snapshot = read(root, SNAPSHOT)
    if sha(snapshot) != 'a4203f895840b395f23274c5f296394f9123d65e73be387ea73e59f3be4768e7':
        raise ValueError('historical source snapshot changed; reopen evidence review')
    for family, record in tomllib.loads(snapshot).items():
        expected = record['files']
        paths = set()
        for package in ('brynja-core', 'brynja-hash-core', f'brynja-legacy-{family}', f'brynja-legacy-{family}-std'):
            paths.add(f'crates/{package}/Cargo.toml')
            for folder in ('src', 'tests'):
                paths.update(p.relative_to(root).as_posix() for p in (root / 'crates' / package / folder).rglob('*.rs'))
        paths.update(p.relative_to(root).as_posix() for p in (root / f'assurance/{family}-cpu-public-api/src').rglob('*.rs'))
        paths.update(f'assurance/{family}-cpu-public-api/{name}' for name in ('Cargo.toml', 'Cargo.lock'))
        if paths != set(expected):
            raise ValueError('historical source closure inventory changed')
        for path, digest in expected.items():
            if sha(read(root, path)) != digest:
                raise ValueError('historical source closure changed; reopen evidence: ' + path)
    for lane, expected_hash in MD5_CAPTURES.items():
        path = f'assurance/md5-observations/v0.24.22/{lane}.json'
        text = read(root, path)
        if sha(text) != expected_hash:
            raise ValueError('original MD5 native capture changed: ' + lane)
        document = json.loads(text)
        if (document['commit'] != '95d1d6b56282621e742b425aa08988d9568d3e84'
            or document['lane'] != lane or document['admission'] != 'unadmitted'
            or document['independent_review'] is not False or document['fips_validated'] is not False):
            raise ValueError('native provenance/admission mismatch')
        for path, digest in document['source_sha256'].items():
            if path.endswith(('.rs', 'Cargo.toml', 'Cargo.lock')) and sha(read(root, path)) != digest:
                raise ValueError('native implementation changed; recapture or leave scope pending: ' + path)


def validate(root=ROOT, hashes=True):
    frozen_text = read(root, FROZEN)
    if sha(frozen_text) != '6ce171b2e4b888e6b33c7b655a4423dea6881463d1a7f93cb9fe7874274db4d9':
        raise ValueError('immutable v0.24.20 contract changed')
    frozen = tomllib.loads(frozen_text)
    if set(frozen) != {'baseline', 'files'} or frozen['baseline'] != 'v0.24.20' or set(frozen['files']) != set(FROZEN_FILES):
        raise ValueError('frozen v0.24.20 contract inventory changed')
    for path, digest in frozen['files'].items():
        if sha(read(root, path)) != digest:
            raise ValueError('frozen portable contract changed: ' + path)
    claims(root)
    validate_native(root)
    manifest = tomllib.loads(read(root, FIXTURE + '/Cargo.toml'))
    if manifest['package']['publish'] is not False or manifest['lints']['rust']['unsafe_code'] != 'forbid':
        raise ValueError('final fixture publication/unsafe boundary changed')
    if set(manifest['dependencies']) != {'brynja-core', 'brynja-legacy-hash-public-api-fixture',
        'brynja-legacy-sha1', 'brynja-legacy-md5', 'brynja-legacy-sha1-std', 'brynja-legacy-md5-std'}:
        raise ValueError('final fixture acquired an unexpected dependency')
    if 'source =' in read(root, FIXTURE + '/Cargo.lock'):
        raise ValueError('final fixture acquired an external dependency')
    batch = read(root, FIXTURE + '/src/batch.rs')
    if batch.count('output = wanted.map(|lane| lane.map(|byte| !byte));') != 3:
        raise ValueError('each batch profile must overwrite independently poisoned output')
    tests = ast.parse(read(root, 'scripts/legacy-hash/test-legacy-final-acceptance.py'))
    entry = [node for node in tests.body if isinstance(node, ast.FunctionDef) and node.name == 'main']
    required_call = ast.parse('final_batch_mutations.run_tests()').body[0]
    if len(entry) != 1 or not entry[0].body or ast.dump(entry[0].body[-1]) != ast.dump(required_call):
        raise ValueError('compiled batch mutations must execute at the end of the test entry point')
    for path, token in (
        ('scripts/checks.sh', 'python3 scripts/legacy-hash/check-legacy-final-acceptance.py'),
        ('scripts/checks.sh', 'python3 scripts/legacy-hash/test-legacy-final-acceptance.py'),
        ('scripts/legacy-hash/test-legacy-final-acceptance.py', 'final_batch_mutations.run_tests()'),
        ('scripts/ci/check-rust-version-matrix.sh', FIXTURE + '/Cargo.toml'),
        ('scripts/assurance/check-bare-metal.sh', FIXTURE + '/Cargo.toml'),
        ('.github/workflows/ci.yml', FIXTURE + '/Cargo.toml'),
        ('scripts/zeroization/check-zeroization-miri.sh', FIXTURE + '/Cargo.toml'),
        ('scripts/zeroization/check-zeroization-sanitizer.sh', FIXTURE + '/Cargo.toml'),
        (FIXTURE + '/src/lib.rs', 'brynja_legacy_hash_public_api_fixture::acceptance()'),
        (FIXTURE + '/src/lib.rs', 'comparisons != 160'),
        (FIXTURE + '/src/main.rs', 'RuntimeSha1Backend::required().is_ok()'),
        (FIXTURE + '/src/main.rs', 'RuntimeMd5Backend::required().is_ok()'),
        (FIXTURE + '/src/batch.rs', '!output_matches(secret.expose(), wanted.as_flattened())?'),
        (FIXTURE + '/src/batch.rs', 'Ok(actual.ct_eq(expected).expose_public())'),
        (FIXTURE + '/src/lib.rs', 'fn dynamic_neighbor_drop_unwind_clears_live_secret_output()'),
        (FIXTURE + '/src/lib.rs', 'fn dynamic_full_width_comparison_rejects_every_mismatch()'),
        (FIXTURE + '/src/batch.rs', 'output != [[0; 16]; 8]'),
    ):
        if token not in read(root, path):
            raise ValueError('mandatory final acceptance behavior missing: ' + token)
    actual = {p: sha(read(root, p)) for p in inventory(root)}
    for p in actual:
        if p.endswith(('.rs', '.py', '.sh')) and len(read(root, p).splitlines()) > 500:
            raise ValueError('final source exceeds 500 lines')
    if hashes and tomllib.loads(read(root, HASHES)) != {'files': actual}:
        raise ValueError('final acceptance review binding changed')


def render_hashes(root=ROOT):
    return '[files]\n' + ''.join(f'"{p}" = "{sha(read(root, p))}"\n' for p in inventory(root))
