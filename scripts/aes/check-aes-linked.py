#!/usr/bin/env python3
"""Packaged final-linked portable AES acceptance; bounded machine review."""
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('aes_linked_packages', HERE / 'check-aes-packaged.py')
packaged = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaged)
ROOT = packaged.ROOT
TARGET = 'x86_64-unknown-linux-gnu'
FIXTURE = ROOT / 'assurance/aes-linked/linked.rs'
require = packaged.require
flow = packaged.module('aes_linked_flow', HERE / 'check-aes-dataflow.py')
helpers = packaged.module('aes_linked_helpers', HERE / 'aes_linked_helpers.py')
mix = packaged.module('aes_linked_mix', HERE / 'aes_linked_mix.py')
substitute = packaged.module('aes_linked_substitute', HERE / 'aes_linked_substitute.py')
rounds = packaged.module('aes_linked_rounds', HERE / 'aes_linked_rounds.py')
wrappers = packaged.module('aes_linked_wrappers', HERE / 'aes_linked_wrappers.py')
public = packaged.module('aes_linked_public', HERE / 'aes_linked_public.py')
POLICY = HERE / 'linked-inverse-review.json'
PROFILE = 'opt3-fat-lto-cgu1-overflow'
REJECT = (*packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH')
KAT_LINES = [f'AES_LINKED_KAT: {bits} six operations; secret outputs and key storage cleared'
             for bits in (128, 192, 256)] + ['AES_LINKED_KAT: complete; 18 operations']


def reviewed(lines, raw, compiler, policy):
    require(set(policy) == {'schema', 'target', 'profile', 'routes', 'panics', 'review', 'compilers'}
            and policy['schema'] == 1 and policy['target'] == TARGET and policy['profile'] == PROFILE
            and policy['routes'] == ['direct', 'facade'] and policy['panics'] == ['abort', 'unwind']
            and policy['review'] == 'docs/assurance/aes-linked-review.md'
            and set(policy['compilers']) == {'1.90.0', '1.99.1'}, 'linked review scope changed')
    for row in policy['compilers'].values():
        require(set(row) == {'inverse_sha256', 'inverse_bytes_sha256', 'instructions', 'symbol_bytes'}
                and all(isinstance(row[k], str) and re.fullmatch('[0-9a-f]{64}', row[k])
                        for k in ('inverse_sha256', 'inverse_bytes_sha256'))
                and all(type(row[k]) is int and row[k] > 100 for k in ('instructions', 'symbol_bytes')),
                'invalid linked inverse policy')
    require(compiler in policy['compilers'], 'unreviewed linked compiler')
    digest, count = inverse_review(lines)
    actual = {'inverse_sha256': digest, 'instructions': count, 'symbol_bytes': len(raw),
              'inverse_bytes_sha256': hashlib.sha256(raw).hexdigest()}
    require(actual == policy['compilers'][compiler], 'reviewed inverse changed; explicit re-review required')
    return actual


def mutations(lines, raw, compiler, policy):
    for instruction in ('jne 0', 'callq 0', 'movb (%rax), %al', 'movb (%rsp,%rax), %al',
                        'shlb %cl, %al', 'movq %rax, %rsp', 'retq', '.byte 0', 'xorb %al, %cl'):
        changed = [*lines[:-1], instruction, lines[-1]]
        try:
            reviewed(changed, raw, compiler, policy)
        except ValueError as error:
            if instruction == 'xorb %al, %cl':
                require('reviewed inverse changed' in str(error), 'arithmetic mutation rejected for unrelated reason')
        else:
            raise ValueError('linked inverse mutation accepted: ' + instruction)
    try:
        reviewed(lines, bytes([raw[0] ^ 1]) + raw[1:], compiler, policy)
    except ValueError as error:
        require('reviewed inverse changed' in str(error), 'encoding mutation rejected for unrelated reason')
    else:
        raise ValueError('linked inverse encoding mutation accepted')
    return 10


def symbols(output):
    rows = []
    for line in output.splitlines():
        if '13brynja_crypto3aes8portable' not in line:
            continue
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] (\S+)', line)
        require(match is not None, 'unrecognized portable symbol row')
        address, size, name = match.groups()
        rows.append((name, int(address, 16), int(size, 16)))
    require(len(rows) == 11 and len({name for name, _, _ in rows}) == 11,
            'final-linked portable helper population changed')
    require(all(size > 0 for _, _, size in rows), 'empty final-linked helper')
    ordered = sorted(rows, key=lambda row: row[1])
    require(all(a + n <= b for (_, a, n), (_, b, _) in zip(ordered, ordered[1:])),
            'overlapping final-linked helpers')
    for role in ('10substitute', '3mix', '5field7inverse', '6expand', '7add_key', '9transform'):
        require(sum(bool(re.fullmatch(r'(?:_ZN13brynja_crypto3aes8portable' + role
                                     + r'17h[0-9a-f]{16}E|_RNv(?:Nt){2,3}C\w+_13brynja_crypto3aes8portable'
                                     + role + ')', name)) for name, _, _ in rows) == 1,
                'missing/ambiguous final-linked helper: ' + role)
    for role, count in (('6expand', 2), ('7add_key', 1), ('9transform', 2)):
        v0 = (r'_RNvNtNtNtC\w+_13brynja_crypto3aes8portable4wide7add_key' if role == '7add_key' else
              r'_RINvNtNtNtC\w+_13brynja_crypto3aes8portable4wide' + role
              + r'(?:Kj18_Kjd0_Kjc_|Kj20_Kjf0_Kje_)EB8_')
        require(sum(bool(re.fullmatch(r'(?:_ZN13brynja_crypto3aes8portable4wide' + role
                                     + r'17h[0-9a-f]{16}E|' + v0 + ')', name)) for name, _, _ in rows) == count,
                'missing/ambiguous final-linked wide helper: ' + role)
    return rows


def decode(output, symbol, start, size, with_sizes=False):
    """Require continuous instruction bytes inside the ELF symbol extent.

    Do not strip padding or truncate at the first return. Bytes beyond the
    symbol are excluded by objdump's explicit start/stop bounds, not guessed.
    """
    require(output.count('file format elf64-x86-64') == 1, 'wrong executable architecture')
    header = re.findall(r'^([0-9a-f]+) <([^>]+)>:$', output, re.M)
    require(header == [(f'{start:016x}', symbol)], 'missing/ambiguous disassembly symbol')
    body = output.split(f'{start:016x} <{symbol}>:\n', 1)[1]
    cursor, lines, raw, sizes = start, [], bytearray(), []
    for line in body.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'\s*([0-9a-f]+): ((?:[0-9a-f]{2} )*[0-9a-f]{2}) *\t(.+)', line)
        require(match is not None, 'unrecognized disassembly row')
        address, encoding, instruction = match.groups()
        data = bytes.fromhex(encoding)
        require(int(address, 16) == cursor and 1 <= len(data) <= 15,
                'noncontiguous or invalid instruction bytes')
        cursor += len(data)
        require(cursor <= start + size, 'instruction crosses symbol extent')
        raw.extend(data)
        sizes.append(len(data))
        lines.append(' '.join(instruction.split()))
    require(cursor == start + size and lines, 'incomplete disassembly extent')
    return (lines, bytes(raw), sizes) if with_sizes else (lines, bytes(raw))


def inverse_review(lines):
    # Reuse the conservative grammar, then bind the exact decoded instruction
    # stream separately. No metadata or labels are allowed in decoded rows.
    require(all(not line.startswith('.') and '#' not in line for line in lines),
            'unexpected decoded inverse metadata')
    asm = 'inverse:\n' + '\n'.join(lines) + '\n.size inverse, .-inverse\n'
    count = flow.check_inverse_assembly(asm, 'inverse')
    digest = hashlib.sha256(('\n'.join(lines) + '\n').encode()).hexdigest()
    return digest, count


def clearing_symbol(table):
    candidates = [line for line in table.splitlines() if 'zeroize_region_volatile' in line]
    require(len(candidates) == 1, 'missing/ambiguous linked clearing symbol')
    match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) [tT] '
                        r'((?:_ZN11brynja_core22secret_memory_volatile23zeroize_region_volatile17h[0-9a-f]{16}E'
                        r'|_RNvNtC\w+_11brynja_core22secret_memory_volatile23zeroize_region_volatile))', candidates[0])
    require(match is not None and int(match[2], 16) > 0, 'unrecognized linked clearing symbol')
    return match[3], int(match[1], 16), int(match[2], 16)


def disassemble(binary, directory, env, objdump, row, with_sizes=False):
    symbol, start, size = row
    result = packaged.archives.run([str(objdump), '--disassemble-symbols=' + symbol,
                                    f'--start-address={start}', f'--stop-address={start + size}',
                                    '--no-print-imm-hex', str(binary)], directory, env)
    require(not result.stderr, 'disassembly tool diagnostic')
    return decode(result.stdout, symbol, start, size, with_sizes)


def inspect(binary, directory, env, nm, objdump, compiler, panic):
    result = packaged.archives.run([str(nm), '--print-size', '--defined-only', str(binary)], directory, env)
    require(not result.stderr, 'symbol tool diagnostic')
    table = result.stdout
    rows = symbols(table)
    selected = {'zeroize': clearing_symbol(table)}
    for role, wide in (('add_key', False), ('wide_add_key', True)):
        matches = [row for row in rows if '7add_key' in row[0] and ('4wide' in row[0]) == wide]
        require(len(matches) == 1, 'missing/ambiguous linked round-key helper')
        selected[role] = matches[0]
    helper_reviews, rejected = [], 0
    for role in helpers.ROLES:
        row = selected[role]
        lines, raw = disassemble(binary, directory, env, objdump, row)
        helper_reviews.append(helpers.check(lines, raw, row[0], row[1], role, compiler))
        rejected += helpers.mutations(lines, raw, row[0], row[1], role, compiler)
    require(rejected == 9, 'linked helper mutation population changed')
    row = next(row for row in rows if '3mix' in row[0])
    selected['mix'] = row
    mix_lines, mix_raw, sizes = disassemble(binary, directory, env, objdump, row, True)
    executable = binary.read_bytes()
    helper_reviews.append(mix.check(mix_lines, mix_raw, sizes, row[0], row[1], executable, compiler))
    require(mix.mutations(mix_lines, mix_raw, sizes, row[0], row[1], executable, compiler) == 7,
            'linked mix mutation population changed')
    inverse = next(row for row in rows if '5field7inverse' in row[0])
    selected['inverse'] = inverse
    row = next(row for row in rows if '10substitute' in row[0])
    selected['substitute'] = row
    sub_lines, sub_raw, sizes = disassemble(binary, directory, env, objdump, row, True)
    helper_reviews.append(substitute.check(sub_lines, sub_raw, sizes, row[0], row[1], executable, inverse, compiler))
    require(substitute.mutations(sub_lines, sub_raw, sizes, row[0], row[1], executable, inverse, compiler) == 6,
            'linked substitution mutation population changed')
    round_roles = []
    for row in rows:
        if not any(part in row[0] for part in ('6expand', '9transform')):
            continue
        body, code, sizes = disassemble(binary, directory, env, objdump, row, True)
        role = rounds.role_for(body, row[0])
        round_roles.append(role)
        selected[role] = row
        names = ('inverse', 'zeroize') if role.startswith('expand') else (
            'substitute', 'mix', 'zeroize', 'add_key' if role == 'transform128' else 'wide_add_key')
        targets = {name: selected[name] for name in names}
        args = (body, code, sizes, row[0], row[1], executable, targets, role, compiler)
        helper_reviews.append(rounds.check(*args))
        require(rounds.mutations(*args) == 8, 'linked round mutation population changed')
    rounds.population(round_roles)
    wrapper_rows, secret_rows = wrappers.candidates(table)
    selected.update(wrapper_rows)
    for row in secret_rows:
        body, _, _ = disassemble(binary, directory, env, objdump, row, True)
        role = wrappers.secret_role(body, row[0], selected)
        require(role not in wrapper_rows, 'duplicate wide secret wrapper')
        wrapper_rows[role] = row
        selected[role] = row
    require(set(wrapper_rows) == set(wrappers.EDGES), 'missing wrapper review')
    for role, edges in wrappers.EDGES.items():
        row = wrapper_rows[role]
        body, code, sizes = disassemble(binary, directory, env, objdump, row, True)
        args = (body, code, sizes, row[0], row[1], executable,
                {edge: selected[edge] for edge in edges}, role, compiler, panic)
        helper_reviews.append(wrappers.check(*args))
        require(wrappers.mutations(*args) == 8, 'linked wrapper mutation population changed')
    public_rows = public.candidates(table)
    selected.update(public_rows)
    for role, edges in public.EDGES.items():
        row = public_rows[role]
        body, code, sizes = disassemble(binary, directory, env, objdump, row, True)
        args = (body, code, sizes, row[0], row[1], executable,
                {edge: selected[edge] for edge in edges}, role, compiler, panic)
        helper_reviews.append(public.check(*args))
        require(public.mutations(*args) == 10, 'linked public mutation population changed')
    lines, raw = disassemble(binary, directory, env, objdump, inverse)
    print(json.dumps({'linked_helpers': [{'symbol': name, 'address': addr, 'size': length}
                                        for name, addr, length in rows],
                      'additional_machine_reviews': helper_reviews}), flush=True)
    return lines, raw


def prepare(directory):
    require(FIXTURE.is_file() and not FIXTURE.is_symlink()
            and not any(p.is_symlink() for p in FIXTURE.parents), 'missing or symlinked linked fixture')
    destination = directory / 'src/bin/linked.rs'
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURE, destination)
    manifest = directory / 'Cargo.toml'
    text = manifest.read_text()
    old = '[profile.release]\noverflow-checks=true\n'
    require(text.count(old) == 1, 'packaged release profile changed')
    manifest.write_text(text.replace(old, old + 'opt-level=3\nlto="fat"\ncodegen-units=1\nstrip=false\n'))


def build(root, directory, versions, compiler, route, panic, env, binary_name='linked'):
    require(compiler in packaged.consumer.TOOLCHAINS and route in packaged.consumer.ROUTES
            and panic in ('abort', 'unwind'), 'unsupported linked configuration')
    require(binary_name in ('linked', 'lifecycle'), 'unsupported linked binary')
    env = {**env, 'CARGO_PROFILE_RELEASE_PANIC': panic,
           'CARGO_TARGET_DIR': str(root / f'linked-{compiler}-{route}-{panic}')}
    cargo = ['cargo', '+' + compiler]
    selection = ['--locked', '--offline', '--no-default-features', '--features', route]
    metadata = packaged.archives.run(cargo + ['metadata', '--format-version=1', *selection,
                                             '--filter-platform', TARGET], directory, env)
    packaged.graph(json.loads(metadata.stdout), route, directory, root / 'unpacked', versions)
    packaged.archives.run(cargo + ['build', *selection, '--release', '--bin', binary_name, '--target', TARGET], directory, env)
    return Path(env['CARGO_TARGET_DIR']) / TARGET / 'release' / binary_name, env


def file_digest(path):
    require(path.is_file(), 'missing linked tool or executable')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def output_check(output):
    require(output.splitlines() == KAT_LINES, 'missing/duplicate/incorrect linked execution markers')


def marker(compiler, route, panic):
    return f'AES linked: PASS; {compiler}; {route}; {panic}; 18 operations; 11 portable helpers; six secret wrappers, six public boundaries, six constructors and two core routines reviewed; 256 rejected mutations'


def check(compiler):
    require(compiler in packaged.consumer.TOOLCHAINS, 'unsupported linked compiler')
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'requires native Linux x86_64')
    for name in REJECT:
        require(name not in os.environ, 'remove ambient ' + name)
    tools = []
    for name in ('llvm-nm', 'llvm-objdump'):
        path = shutil.which(name)
        require(path is not None, 'missing ' + name)
        tools.append(Path(path).resolve(strict=True))
    before = [file_digest(p) for p in tools]
    policy = json.loads(POLICY.read_text())
    with packaged.archives.cargo_environment.private_directory(ROOT) as temporary:
        root = Path(temporary)
        env = packaged.archives.isolated_env(root)
        for path, digest in zip(tools, before):
            print(json.dumps({'tool': str(path), 'sha256': digest,
                              'version': packaged.archives.run([str(path), '--version'], ROOT, env).stdout}), flush=True)
        print(packaged.archives.run(['rustc', '+' + compiler, '-vV'], ROOT, env).stdout, flush=True)
        versions = packaged.package_sources(root, env)
        directory = root / 'consumers/aes'
        packaged.prepare(directory, versions)
        prepare(directory)
        packaged.archives.run(['cargo', '+' + compiler, 'generate-lockfile', '--offline'], directory, env)
        for route in packaged.consumer.ROUTES:
            for panic in ('abort', 'unwind'):
                binary, build_env = build(root, directory, versions, compiler, route, panic, env)
                binary_hash = file_digest(binary)
                lines, raw = inspect(binary, directory, build_env, *tools, compiler, panic)
                actual = reviewed(lines, raw, compiler, policy)
                require(mutations(lines, raw, compiler, policy) == 10, 'mutation population changed')
                result = packaged.archives.run([str(binary)], directory, build_env)
                require(not result.stderr, 'linked executable diagnostic')
                output_check(result.stdout)
                require(file_digest(binary) == binary_hash and [file_digest(p) for p in tools] == before,
                        'linked executable/tool changed during review')
                print(json.dumps({'compiler': compiler, 'route': route, 'panic': panic,
                                  'target': TARGET, 'profile': PROFILE, 'binary_sha256': binary_hash, **actual}), flush=True)
                print(result.stdout, end='', flush=True)
                print(marker(compiler, route, panic), flush=True)
    print(f'AES linked completed: {compiler}; four packaged final executables; eleven portable helpers, six secret wrappers, six public boundaries, six constructors and two core routines reviewed', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', choices=packaged.consumer.TOOLCHAINS, required=True)
    check(parser.parse_args().toolchain)
