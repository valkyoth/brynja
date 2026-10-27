"""Bind external tests only after building the pristine ParallelHash libraries."""
import json
import tomllib

TESTS = {
    'brynja-hash-parallel': {'api', 'official_vectors', 'execution', 'execution_stream',
                           'scoped_accelerated', 'scoped_scheduled'},
    'brynja-hash-parallel-std': {'executor', 'execution', 'scoped', 'scoped_execution'},
}


def test_paths(repository, package):
    directory = repository / 'crates' / package / 'tests'
    paths = {path.stem: path.resolve() for path in directory.glob('*.rs')}
    if set(paths) != TESTS[package]:
        raise ValueError('ParallelHash repository test-target inventory changed')
    if package == 'brynja-hash-parallel':
        paths['scoped'] = (repository / 'assurance/parallelhash-differential/tests/scoped.rs').resolve()
    if not all(path.is_file() for path in paths.values()):
        raise ValueError('ParallelHash repository test input missing')
    return paths


def prepare(roots, repository, check, environment):
    targets = {package: test_paths(repository, package) for package in TESTS}
    patches = '\n[workspace]\n[patch.crates-io]\n' + ''.join(
        f'{name}={{path={json.dumps(str(path))}}}\n' for name, path in roots.items())
    for package in TESTS:
        manifest = roots[package] / 'Cargo.toml'
        data = tomllib.loads(manifest.read_text())
        if data.get('test') or (roots[package] / 'tests').exists():
            raise ValueError('ParallelHash archive still includes standalone tests')
        manifest.write_text(manifest.read_text() + patches)
    # No fixture source, test target, or repository path is available to these
    # builds. Missing runtime inputs must fail before any testing adaptation.
    for package in TESTS:
        for profile in ([], ['--release']):
            check(['cargo', 'build', '--offline', '--all-features', '--lib', *profile],
                  roots[package], environment)
    for package, paths in targets.items():
        manifest = roots[package] / 'Cargo.toml'
        text = manifest.read_text()
        for name, path in sorted(paths.items()):
            text += f'\n[[test]]\nname={json.dumps(name)}\npath={json.dumps(str(path))}\n'
        manifest.write_text(text)
    # Unit tests, doctests and compiled source mutants still use the extracted
    # crate. Only external integration targets reference repository fixtures.
