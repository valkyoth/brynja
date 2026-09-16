#!/usr/bin/env python3
"""Fail-closed regression tests for package provenance and compiler negatives."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import hardened_batch_package_cases as cases

PATH = Path(__file__).with_name('check-hardened-batch-package.py')
SPEC = importlib.util.spec_from_file_location('hardened_package', PATH)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def rejects(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError('invalid package evidence accepted')


def diagnostic(code, level='error'):
    return json.dumps({'reason': 'compiler-message', 'message': {
        'level': level, 'code': {'code': code} if code else None}})


def result(status=1, output='', stderr=''):
    return subprocess.CompletedProcess(['cargo'], status, output, stderr)


def diagnostic_checks(module):
    module.require_success(result(0))
    rejects(lambda: module.require_success(result(1)))
    good = diagnostic('E0277')
    module.require_rejection(result(1, good), 'E0277')
    for bad in (
        result(0, good), result(1), result(1, 'not JSON'),
        result(1, diagnostic('E0433')), result(1, diagnostic(None)),
        result(1, diagnostic('E0277', 'warning')),
        result(1, good + '\n' + diagnostic('E0308')),
        result(1, '', 'error[E0277]: merely text, not a rustc diagnostic'),
        result(1, json.dumps({'reason': 'build-finished', 'message': 'error[E0277]'})),
    ):
        rejects(lambda bad=bad: module.require_rejection(bad, 'E0277'))


def graph_checks(module):
    with tempfile.TemporaryDirectory(prefix='brynja-package-graph-') as directory:
        root = Path(directory)
        name = 'brynja-hash-sha3'
        roots = {name: root / 'packed'}
        consumer = root / 'consumer'
        metadata = {'packages': [
            {'name': name, 'id': 'leaf', 'source': None,
             'manifest_path': str(roots[name] / 'Cargo.toml')},
            {'name': 'hardened-batch-external', 'id': 'consumer', 'source': None,
             'manifest_path': str(consumer / 'Cargo.toml')},
        ], 'resolve': {'nodes': [
            {'id': 'leaf', 'features': ['hardened-batch-execution']},
            {'id': 'consumer', 'features': []},
        ]}}
        module.validate_graph(metadata, roots, consumer)
        for kind in ('registry', 'workspace', 'ordinary', 'missing', 'extra'):
            changed = copy.deepcopy(metadata)
            if kind == 'registry':
                changed['packages'][0]['source'] = 'registry+https://example.invalid'
            elif kind == 'workspace':
                changed['packages'][0]['manifest_path'] = str(root / 'checkout/Cargo.toml')
            elif kind == 'ordinary':
                changed['resolve']['nodes'][0]['features'].append('batch-execution')
            elif kind == 'missing':
                changed['packages'].pop(0)
            else:
                changed['packages'].append({'name': 'unexpected'})
            rejects(lambda: module.validate_graph(changed, roots, consumer))
        metadata['resolve']['nodes'][0]['features'].append('batch-execution')
        module.validate_graph(metadata, roots, consumer, ordinary=True)


def controls():
    owners = cases.owners()
    boundaries = cases.boundaries()
    substitutions = list(cases.substitutions())
    assert len(owners) == len(set(owners)) == 26
    assert len(boundaries) == 129 and len(substitutions) == 16
    assert len({case[0] for case in boundaries + substitutions}) == 145
    with tempfile.TemporaryDirectory(prefix='brynja-package-controls-') as directory:
        root = Path(directory)
        source = root / 'lib.rs'
        for subject in boundaries + substitutions:
            label, positive, negative, code = subject
            seen = []

            def child(*_args):
                text = source.read_text()
                seen.append(text)
                if len(seen) == 1:
                    assert positive in text
                    return result(0)
                assert negative in text
                return result(1, diagnostic(code))

            with patch.object(checker, 'run', side_effect=child):
                assert checker.probes(source, ['cargo'], root, {}, [subject]) == 1
            assert len(seen) == 2, label
        with patch.object(checker, 'run', return_value=result(1, diagnostic('E0433'))) as child:
            rejects(lambda: checker.probes(source, ['cargo'], root, {}, [boundaries[0]]))
            assert child.call_count == 1  # A broken control must stop before the negative.


def mutation_controls():
    # A compiled mutation must execute exactly one failing runtime test, and the
    # extracted source must be restored even if compilation or test selection fails.
    with tempfile.TemporaryDirectory(prefix='brynja-package-mutations-') as directory:
        root = Path(directory)
        source = root / 'workspace.rs'
        original = 'before\n'
        subject = ('brynja-hash-sha3', 'workspace.rs', 'before', 'after', 'test', 1)
        args = SimpleNamespace(target='x86_64-unknown-linux-gnu', simd=False)
        for outcome in ('runtime', 'survived', 'compile', 'missing_baseline'):
            source.write_text(original)
            calls = []

            def child(*_args):
                text = source.read_text()
                calls.append(text)
                if outcome == 'missing_baseline':
                    return result(0, 'test result: ok. 0 passed;')
                if text == original:
                    return result(0, 'test result: ok. 1 passed;')
                assert text == 'after\n'
                if outcome == 'runtime':
                    return result(1, 'test result: FAILED. 0 passed; 1 failed;')
                if outcome == 'survived':
                    return result(0, 'test result: ok. 1 passed;')
                return result(1, '', 'error[E0308]: compilation failed')

            with patch.object(checker.cases, 'compiled_mutants', return_value=[subject]), \
                    patch.object(checker, 'run', side_effect=child), \
                    contextlib.redirect_stdout(io.StringIO()):
                call = lambda: checker.compiled_regressions({'brynja-hash-sha3': root}, ['cargo'], {}, args)
                if outcome == 'runtime':
                    call()
                    assert calls == [original, 'after\n', original]
                else:
                    rejects(call)
            assert source.read_text() == original


def main():
    diagnostic_checks(checker)
    graph_checks(checker)
    controls()
    mutation_controls()
    source = PATH.read_text()
    changes = (
        ('not result.returncode or not errors or set(errors) != {code}', 'not errors or set(errors) != {code}'),
        ('set(errors) != {code}', 'code not in errors'),
        ("package['source'] is not None or", 'False or'),
        ("Path(package['manifest_path']).resolve() != (directory / 'Cargo.toml').resolve()", 'False'),
        ("if not ordinary and set(node['features']) & set(ORDINARY.get(name, [])):", 'if False:'),
    )
    for before, after in changes:
        assert source.count(before) == 1
        mutant = type('Mutant', (), {})
        namespace = {'__file__': str(PATH), '__name__': 'mutant'}
        exec(compile(source.replace(before, after), str(PATH), 'exec'), namespace)
        for name in ('require_success', 'require_rejection', 'validate_graph'):
            setattr(mutant, name, staticmethod(namespace[name]))
        try:
            diagnostic_checks(mutant)
            graph_checks(mutant)
        except AssertionError:
            continue
        raise AssertionError('package-checker mutant survived: ' + before)
    print('Hardened package checker: diagnostics, graph provenance, 145 paired controls and five enforcement mutants PASS')


if __name__ == '__main__':
    main()
