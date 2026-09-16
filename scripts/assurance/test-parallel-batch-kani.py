#!/usr/bin/env python3
"""Check exact real-source mutation anchors and isolated harness assembly."""
import importlib.util
from pathlib import Path
import subprocess

PATH = Path(__file__).with_name('check-parallel-batch-kani.py')
SPEC = importlib.util.spec_from_file_location('parallel_kani', PATH)
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


def rejects(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError('invalid source mutation accepted')


def exercise(change):
    assert change('prefix exact suffix', 'exact', 'changed') == 'prefix changed suffix'
    assert change('prefix exact suffix', 'exact', '') == 'prefix  suffix'
    for original, before, after in (
        ('body', '', 'new'), ('body', 'absent', 'new'),
        ('body body', 'body', 'new'), ('body', 'body', 'body'),
    ):
        rejects(lambda: change(original, before, after))


def interruptions(check):
    result = lambda extra: subprocess.CompletedProcess([], 1,
        'assertion failure\nVERIFICATION:- FAILED\n' + extra, '')
    check(result(''))
    for message in ('Timed out', 'TIMEOUT', 'CBMC failed with status 15',
                    'out of memory', 'killed by signal 9'):
        rejects(lambda: check(result(message)))


def main():
    exercise(driver.changed_source)
    interruptions(driver.counterexample)
    base = driver.ROOT / 'crates/brynja-hash-parallel/src'
    for key, name, before, after in driver.MUTANTS:
        assert key in driver.HARNESSES and name in driver.SOURCES
        original = (base / name).read_text()
        changed = driver.changed_source(original, before, after)
        assert changed != original
    assert len(set(driver.HARNESSES.values())) == len(driver.HARNESSES)
    for name, harness in driver.HARNESSES.items():
        function = harness.rsplit('::', 1)[1]
        assert sum(source.count('fn ' + function + '(') for source in driver.SOURCES.values()) == 1, name
    source = PATH.read_text()
    before = 'not before or before == after or original.count(before) != 1'
    for after in ('original.count(before) != 1', 'False', 'not before or before == after',
                  'not before or before == after or original.count(before) == 0'):
        assert source.count(before) == 1
        namespace = {'__file__': str(PATH), '__name__': 'mutant'}
        exec(compile(source.replace(before, after), str(PATH), 'exec'), namespace)
        try:
            exercise(namespace['changed_source'])
        except AssertionError:
            continue
        raise AssertionError('weakened mutation anchor check survived')
    assert source.count('if re.search(') == 1
    namespace = {'__file__': str(PATH), '__name__': 'mutant'}
    exec(compile(source.replace('if re.search(', 'if False and re.search('), str(PATH), 'exec'), namespace)
    try:
        interruptions(namespace['counterexample'])
    except AssertionError:
        pass
    else:
        raise AssertionError('disabled interruption rejection survived')
    print(f'ParallelHash Kani harness assembly: {len(driver.HARNESSES)} exact harnesses, '
          f'{len(driver.MUTANTS)} live source anchors, four weakened anchor checks '
          'and five interrupted-verifier outcomes rejected; interruption guard mutation rejected')


if __name__ == '__main__':
    main()
