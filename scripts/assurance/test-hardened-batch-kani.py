#!/usr/bin/env python3
"""Kani failure/empty-selection must never count as successful qualification."""
import importlib.util
from pathlib import Path
import subprocess

PATH = Path(__file__).with_name('check-hardened-batch-kani.py')
SPEC = importlib.util.spec_from_file_location('batch_kani', PATH)
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


def rejects(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError('invalid verifier outcome accepted')


def exercise(success, counterexample):
    result = lambda status, output: subprocess.CompletedProcess(['cargo', 'kani'], status, output, '')
    success(result(0, 'VERIFICATION:- SUCCESSFUL'))
    counterexample(result(1, 'assertion failure\nVERIFICATION:- FAILED'))
    for status, output in (
        (1, 'VERIFICATION:- SUCCESSFUL'), (0, ''), (1, 'compiler error'),
        (0, 'Complete - 0 successfully verified harnesses'),
        (1, 'assertion failure\nVERIFICATION:- FAILED'),
    ):
        rejects(lambda: success(result(status, output)))
    for status, output in (
        (0, 'assertion failure\nVERIFICATION:- FAILED'),
        (1, 'compiler error: assertion'), (1, 'VERIFICATION:- FAILED'),
        (0, 'VERIFICATION:- SUCCESSFUL'), (1, ''),
        (1, 'VERIFICATION:- FAILED\nFailed Checks: unwinding assertion loop 0'),
        (1, 'assertion failure\nVERIFICATION:- FAILED\n[Kani] info: Verification output shows one or more unwinding failures.'),
    ):
        rejects(lambda: counterexample(result(status, output)))


def main():
    banner = 'Kani Rust Verifier 0.68.0 (cargo plugin)\nCBMC 6.11.0'
    result = lambda status, output: subprocess.CompletedProcess([], status, output, '')
    check.require_version(result(0, banner + '\n'), '0.68.0')
    for status, output in ((1, banner), (0, ''), (0, 'cargo-kani 0.67.0'),
                           (0, banner.replace('0.68.0', '0.67.0')),
                           (0, banner.replace('6.11.0', '0.0.0')),
                           (0, banner.splitlines()[0]), (0, banner + '\nunexpected')):
        rejects(lambda: check.require_version(result(status, output), '0.68.0'))
    exercise(check.require_success, check.require_counterexample)
    source = PATH.read_text()
    for before, after in (
        ("result.returncode or 'VERIFICATION:- SUCCESSFUL' not in result.stdout",
         "'VERIFICATION:- SUCCESSFUL' not in result.stdout"),
        ("result.returncode or 'VERIFICATION:- SUCCESSFUL' not in result.stdout", 'result.returncode'),
        ("not result.returncode or 'VERIFICATION:- FAILED' not in result.stdout or 'assertion' not in result.stdout",
         "'VERIFICATION:- FAILED' not in result.stdout or 'assertion' not in result.stdout"),
        (" or 'assertion' not in result.stdout", ''),
        ("'unwinding failures' in result.stdout", 'False'),
        ("'Failed Checks: unwinding assertion' in result.stdout", 'False'),
    ):
        assert source.count(before) == 1
        namespace = {'__file__': str(PATH), '__name__': 'mutant'}
        exec(compile(source.replace(before, after), str(PATH), 'exec'), namespace)
        try:
            exercise(namespace['require_success'], namespace['require_counterexample'])
        except AssertionError:
            continue
        raise AssertionError('Kani outcome-check mutant survived')
    print('Hardened Kani outcome checks: twelve invalid outcomes and six weakened verifiers rejected')


if __name__ == '__main__':
    main()
