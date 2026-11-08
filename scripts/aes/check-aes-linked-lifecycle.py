#!/usr/bin/env python3
"""Archive-only final-linked public AES owner lifecycle; no internal fault hooks."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('aes_lifecycle_linked', HERE / 'check-aes-linked.py')
linked = importlib.util.module_from_spec(spec)
spec.loader.exec_module(linked)
packaged, require = linked.packaged, linked.require
cleanup = packaged.module('aes_linked_cleanup', HERE / 'aes_linked_cleanup.py')
FIXTURE = linked.ROOT / 'assurance/aes-linked/lifecycle.rs'
OWNERS = [f'Aes{bits}{kind}' for bits in (128, 192, 256) for kind in ('Key', 'ExpandedKey')]


def prepare(directory):
    require(FIXTURE.is_file() and not FIXTURE.is_symlink()
            and not any(p.is_symlink() for p in FIXTURE.parents), 'missing or symlinked lifecycle fixture')
    linked.prepare(directory)
    shutil.copyfile(FIXTURE, directory / 'src/bin/lifecycle.rs')


def output_lines(panic):
    require(panic in ('abort', 'unwind'), 'unsupported lifecycle panic profile')
    count = 8 if panic == 'unwind' else 0
    return [f'AES_LINKED_LIFECYCLE: {owner}; 12 normal cases; {count} caller unwinds' for owner in OWNERS] + [
        'AES_LINKED_LIFECYCLE: complete; 72 normal cases; ' +
        ('48 caller unwinds' if panic == 'unwind' else '0 caller unwinds; abort cleanup not claimed')]


def output_check(output, panic):
    require(output.splitlines() == output_lines(panic), 'missing/duplicate/incorrect lifecycle markers')


def negative_result(result, reason):
    require(result.returncode == 101 and not result.stdout and reason in result.stderr,
            'lifecycle panic negative control did not fail as expected')


def marker(compiler, route, panic):
    count = 48 if panic == 'unwind' else 0
    rejected = 75 if panic == 'unwind' else 63
    return f'AES linked lifecycle: PASS; {compiler}; {route}; {panic}; 72 normal cases; {count} caller unwinds; six cleanup boundaries reviewed; {rejected} rejected mutations'


def inspect(binary, directory, env, nm, objdump, compiler, panic):
    def output(command):
        result = packaged.archives.run(command, directory, env)
        require(not result.stderr, 'lifecycle inspection tool diagnostic')
        return result.stdout
    table = output([str(nm), '--print-size', '--defined-only', str(binary)])
    rows = cleanup.candidates(table)
    zeroize = linked.clearing_symbol(table)
    lines, raw = linked.disassemble(binary, directory, env, objdump, zeroize)
    reviews = [linked.helpers.check(lines, raw, zeroize[0], zeroize[1], 'zeroize', compiler)]
    rejected = linked.helpers.mutations(lines, raw, zeroize[0], zeroize[1], 'zeroize', compiler)
    require(rejected == 3, 'lifecycle zeroizer controls changed')
    image = binary.read_bytes()
    targets = {'zeroize': zeroize}
    if panic == 'unwind':
        targets['resume'] = cleanup.resume_target(
            output([str(objdump), '--disassemble', '--section=.plt', str(binary)]),
            output([str(objdump), '--dynamic-reloc', str(binary)]), image)
    for role, row in rows.items():
        lines, raw, sizes = linked.disassemble(binary, directory, env, objdump, row, True)
        args = (lines, raw, sizes, row[0], row[1], image, targets, role, compiler, panic)
        reviews.append(cleanup.check(*args))
        count = cleanup.mutations(*args)
        require(count == (12 if panic == 'unwind' else 10), 'lifecycle cleanup controls changed')
        rejected += count
    print(json.dumps({'cleanup_symbols': rows, 'cleanup_targets': targets,
                      'machine_reviews': reviews, 'rejected_mutations': rejected}), flush=True)


def check(compiler):
    require(compiler in packaged.consumer.TOOLCHAINS, 'unsupported lifecycle compiler')
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'requires native Linux x86_64')
    for name in linked.REJECT:
        require(name not in os.environ, 'remove ambient ' + name)
    tools = []
    for name in ('llvm-nm', 'llvm-objdump'):
        path = shutil.which(name)
        require(path is not None, 'missing ' + name)
        tools.append(Path(path).resolve(strict=True))
    tool_hashes = [linked.file_digest(path) for path in tools]
    with packaged.archives.cargo_environment.private_directory(linked.ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        for path, digest in zip(tools, tool_hashes):
            print(json.dumps({'tool': str(path), 'sha256': digest,
                              'version': packaged.archives.run([str(path), '--version'], linked.ROOT, env).stdout}), flush=True)
        print(packaged.archives.run(['rustc', '+' + compiler, '-vV'], linked.ROOT, env).stdout, flush=True)
        versions = packaged.package_sources(root, env)
        directory = root / 'consumers/aes'
        packaged.prepare(directory, versions)
        prepare(directory)
        packaged.archives.run(['cargo', '+' + compiler, 'generate-lockfile', '--offline'], directory, env)
        for route in packaged.consumer.ROUTES:
            for panic in ('abort', 'unwind'):
                binary, build_env = linked.build(root, directory, versions, compiler, route, panic, env, 'lifecycle')
                before = linked.file_digest(binary)
                inspect(binary, directory, build_env, *tools, compiler, panic)
                result = packaged.archives.run([str(binary)], directory, build_env)
                require(not result.stderr, 'lifecycle executable diagnostic')
                output_check(result.stdout, panic)
                if panic == 'unwind':
                    for mode, reason in (('unexpected-panic', 'unexpected panic payload'),
                                         ('no-panic', 'caller unwind did not occur')):
                        # Both controls unwind to the process boundary, never abort;
                        # a signal/timeout/other failure is not an accepted control.
                        packaged.archives.cargo_environment.check(directory, build_env)
                        negative_result(subprocess.run([str(binary), mode], cwd=directory, env=build_env,
                                                       text=True, capture_output=True, timeout=30), reason)
                require(linked.file_digest(binary) == before
                        and [linked.file_digest(path) for path in tools] == tool_hashes,
                        'lifecycle executable/tool changed')
                print(json.dumps({'compiler': compiler, 'route': route, 'panic': panic,
                                  'target': linked.TARGET, 'profile': linked.PROFILE,
                                  'binary_sha256': before}), flush=True)
                print(result.stdout, end='', flush=True)
                print(marker(compiler, route, panic), flush=True)
    print(f'AES linked lifecycle completed: {compiler}; four binaries; 288 normal cases; 96 caller unwinds; 4 panic controls; 276 machine mutations rejected', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=packaged.consumer.TOOLCHAINS, required=True)
    check(parser.parse_args().toolchain)
