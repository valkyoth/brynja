#!/usr/bin/env python3
"""Retained accelerated output staging/cleanup requests, not callee erasure proof."""
import argparse
import json
from pathlib import Path
import re

import check_kmac_verify_comparisons as comparison
import check_secret_output_write as writing

require = comparison.require
SSA = writing.SSA
LABEL = r'(?:"[^"\n]+"|[-.$\w]+)'
UNKNOWN = 'unknown'


def graph(function):
    result, label = {}, None
    for raw in function.splitlines()[1:-1]:
        line = raw.strip()
        if not line or line.startswith(';'):
            continue
        found = re.fullmatch('(' + LABEL + r'):(?:\s*;.*)?', line)
        if found:
            label = found[1]
            require(label not in result, 'unique accelerated block')
            result[label] = []
        else:
            require(label is not None, 'instruction has block')
            result[label].append(re.sub(r'(?:, ![\w.]+ !\d+)+$', '', line))
    return result


def unique(definitions, *tokens):
    matches = [name for name in definitions if all(token in name for token in tokens)]
    require(len(matches) == 1, 'unique accelerated callee: ' + repr(tokens))
    return matches[0]


def invocation(line):
    symbol = re.search(comparison.SYMBOL, line)
    require(symbol is not None, 'named cleanup call')
    args = comparison.arguments(line, symbol.end())
    return symbol[1], args


def value(token, env):
    if token in ('null', 'false'):
        return 0
    if token == 'true':
        return 1
    if re.fullmatch(r'-?\d+', token):
        return int(token)
    require(token in env, 'known cleanup value: ' + token)
    return env[token]


def edges(line):
    found = re.fullmatch('to label %(' + LABEL + ') unwind label %(' + LABEL + ')', line)
    require(found is not None, 'explicit normal/unwind successors')
    return found.groups()


def walk(blocks, start, predecessor, env, names, guard, required, expected_exit):
    """Closed grammar for selected post-error paths; excludes double-panic aborts."""
    pending = [(start, predecessor, dict(env), {}, frozenset(), ())]
    terminals = 0
    while pending:
        label, previous, state, memory, events, history = pending.pop()
        require(label in blocks and label not in history, 'finite cleanup path')
        history += (label,)
        body = blocks[label]
        for index, line in enumerate(body):
            found = re.fullmatch('(' + SSA + r') = phi (?:i\d+|\{ ptr, i32 \}) (.+)', line)
            if found:
                pairs = re.findall(r'\[ ([^,]+), %(' + LABEL + r') \]', found[2])
                require(len({p for _, p in pairs}) == len(pairs), 'distinct phi predecessors')
                selected = [item for item, pred in pairs if pred == previous]
                require(len(selected) == 1, 'cleanup phi has predecessor')
                state[found[1]] = value(selected[0], state)
                continue
            found = re.fullmatch('(' + SSA + r') = getelementptr inbounds nuw i8, ptr (' + SSA + r'), i64 (' + SSA + r'|-?\d+)', line)
            if found:
                root = value(found[2], state)
                offset = value(found[3], state)
                require(isinstance(root, tuple) and isinstance(offset, int), 'known cleanup address')
                state[found[1]] = (root[0], root[1] + offset)
                continue
            found = re.fullmatch('(' + SSA + r') = load i64, ptr (' + SSA + '), align 8', line)
            if found:
                address = value(found[2], state)
                require(address == ('init', 0), 'only initialization-presence load on error path')
                state[found[1]] = 1
                continue
            found = re.fullmatch(r'store i(8|64) (' + SSA + r'|-?\d+), ptr (' + SSA + r'), align (?:1|8)', line)
            if found:
                address = value(found[3], state)
                require(address in {('result', 0), ('result', 8), ('storage', 859), ('storage', 616)}, 'bounded error/terminal metadata write')
                memory[address] = (int(found[1]), value(found[2], state))
                continue
            found = re.fullmatch('(' + SSA + r') = icmp (eq|ne) (?:i8|i64|ptr) (' + SSA + r'), (-?\d+|null)', line)
            if found:
                left, right = value(found[3], state), value(found[4], state)
                require(left != UNKNOWN, 'known cleanup predicate')
                state[found[1]] = int((left == right) if found[2] == 'eq' else (left != right))
                continue
            found = re.fullmatch('(' + SSA + r') = trunc nuw i8 (' + SSA + ') to i1', line)
            if found:
                state[found[1]] = value(found[2], state) & 1
                continue
            found = re.fullmatch('(' + SSA + r') = landingpad \{ ptr, i32 \}', line)
            if found:
                state[found[1]] = UNKNOWN
                continue
            if line == 'cleanup':
                continue
            if ' call ' in ' ' + line or ' invoke ' in ' ' + line:
                name, args = invocation(line)
                if name.startswith('llvm.lifetime.') or name == 'llvm.assume':
                    continue
                if name == names['clear']:
                    require(len(args) == 2, 'clear arity')
                    pointer = value(comparison.pointer(args[0]), state)
                    width = value(re.search(r'(-?\d+|' + SSA + ')$', args[1])[0], state)
                    require((pointer, width) in {(('storage', 864), 168), (('storage', 1056), 2)}, 'full original staging/domain clear request')
                    events |= {('clear', pointer[1], width)}
                elif name == names['wipe']:
                    require(len(args) == 1 and value(comparison.pointer(args[0]), state) == ('storage', 624), 'original engine memory wipe')
                    events |= {('wipe', 624, 234)}
                elif name == names['drop']:
                    require(len(args) == 1 and value(comparison.pointer(args[0]), state) == ('init', 8), 'original initialization drop')
                    events |= {('drop',)}
                elif name == names['guard']:
                    require(len(args) == 2 and value(comparison.pointer(args[0]), state) == ('storage', 0)
                            and args[1] == 'i8 0', 'incomplete original operation guard')
                    # The actual guard definition is checked separately, not trusted by name alone.
                    require(guard, 'validated operation guard')
                    events |= {('wipe', 624, 234), ('clear', 864, 168), ('clear', 1056, 2)}
                else:
                    raise ValueError('unreviewed cleanup call: ' + name)
                if 'invoke ' in line:
                    require(index + 1 == len(body) - 1, 'invoke terminates cleanup block')
                    normal, unwind = edges(body[index + 1])
                    pending.append((normal, label, dict(state), dict(memory), events, history))
                    # A second failure during destruction aborts, outside recoverable-unwind claims.
                    abort = blocks.get(unwind, [])
                    if any('16panic_in_cleanup' in item for item in abort):
                        require(abort[-1] == 'unreachable', 'double panic is nonreturning')
                    else:
                        pending.append((unwind, label, dict(state), dict(memory), events, history))
                    break
                continue
            branch = re.fullmatch('br label %(' + LABEL + ')', line)
            conditional = re.fullmatch('br i1 (' + SSA + '), label %(' + LABEL + '), label %(' + LABEL + ')', line)
            if branch or conditional:
                require(index == len(body) - 1, 'branch terminates block')
                target = branch[1] if branch else conditional[2 if value(conditional[1], state) else 3]
                pending.append((target, label, dict(state), dict(memory), events, history))
                break
            if line == 'ret void' or line.startswith('resume { ptr, i32 } '):
                require(index == len(body) - 1 and required <= events, 'cleanup requests precede return/resume')
                if expected_exit == 'error' and line == 'ret void':
                    require(memory.get(('result', 0)) == (64, 2), 'error remains an error')
                if expected_exit == 'unwind':
                    require(line.startswith('resume '), 'unwind cannot become ordinary return')
                terminals += 1
                break
            raise ValueError('unreviewed cleanup instruction: ' + line)
        else:
            raise ValueError('cleanup block has no terminator')
    require(terminals > 0, 'nonvacuous cleanup exits')
    return terminals


def inspect(sha3, core, compiler):
    require(compiler in ('1.90.0', '1.98.1'), 'reviewed accelerated compiler')
    definitions = comparison.definitions(sha3)
    names = {key: unique(definitions, *tokens) for key, tokens in {
        'producer': ('accelerated', '8Borrowed6secret'),
        'wipe': ('accelerated', '6Memory4wipe'),
        'read': ('accelerated', '6Engine4read'),
    }.items()}
    core_defs = comparison.definitions(core)
    names['write'] = unique(core_defs, 'Initialization5write')
    names['clear'] = unique(core_defs, '18clear_owned_region')
    names['drop'] = unique(core_defs, 'SecretRegionInitialization', '4drop')
    guard_names = [name for name in definitions if 'Operation' in name and 'xof' in name
                   and ('drop_in_place' in name or 'drop_glue' in name)]
    require(len(guard_names) == 1, 'unique actual operation drop')
    names['guard'] = guard_names[0]
    all_clear = {('wipe', 624, 234), ('clear', 864, 168), ('clear', 1056, 2)}
    for flag in (0, 1):
        walk(graph(definitions[names['guard']]), 'start', None,
             {'%_1.0.val': ('storage', 0), '%_1.8.val': flag}, names, False,
             all_clear if flag == 0 else {('clear', 864, 168)}, 'guard')
    blocks = graph(definitions[names['producer']])
    calls = {}
    for label, body in blocks.items():
        for i, line in enumerate(body):
            if 'invoke ' not in line:
                continue
            name, args = invocation(line)
            for kind in ('write', 'read'):
                if name == names[kind]:
                    require(kind not in calls and i == len(body) - 2, 'unique read/write invocation')
                    calls[kind] = (label, line, args, edges(body[i + 1]))
    require(set(calls) == {'write', 'read'}, 'read and write present')
    read, write = calls['read'], calls['write']
    stage = comparison.pointer(read[2][1])
    count_match = re.search(SSA + '$', read[2][2])
    require(count_match is not None, 'read uses bounded count SSA')
    count = count_match[0]
    init = comparison.pointer(write[2][0])
    require(comparison.pointer(read[2][0]) == '%self.0.val'
            and comparison.pointer(write[2][1]) == stage and write[2][2] == read[2][2], 'read/write same original stage and count')
    function = definitions[names['producer']]
    require(re.search(re.escape(stage) + r' = getelementptr inbounds nuw i8, ptr %self.0.val, i64 864\n', function), 'stage belongs to storage')
    require(re.search(re.escape(init) + r' = getelementptr inbounds nuw i8, ptr %_10, i64 8\n', function), 'initialization descriptor address')
    minimum = next((line for line in blocks[read[0]] if '@llvm.umin.i64(' in line), '')
    require(re.fullmatch(re.escape(count) + r' = call noundef i64 @llvm.umin.i64\(i64 ' + SSA + r', i64 168\)', minimum), 'bounded producer chunk')
    env = {'%self.0.val': ('storage', 0), '%_0': ('result', 0), '%_10': ('init', 0),
           init: ('init', 8), stage: ('storage', 864)}
    terminals = 0
    for kind, (label, line, args, (normal, unwind)) in calls.items():
        returned = re.search('(' + SSA + r') = invoke', line)[1]
        # Both compilers lower these Result discriminants differently.
        success = (4 if kind == 'write' else 12) if compiler == '1.90.0' else -1
        branch = blocks[normal]
        require(len(branch) == 2, 'closed result branch')
        test = writing.match('(' + SSA + ') = icmp eq i8 ' + re.escape(returned) + ', ' + str(success), branch[0])[1]
        destinations = writing.match('br i1 ' + re.escape(test) + ', label %(' + LABEL + '), label %(' + LABEL + ')', branch[1])
        failed_env = dict(env, **{returned: 2})
        terminals += walk(blocks, normal, label, failed_env, names, True, all_clear | {('drop',)}, 'error')
        terminals += walk(blocks, unwind, label, failed_env, names, True, all_clear | {('drop',)}, 'unwind')
        if kind == 'write':
            cleared = blocks[destinations[1]]
            require(len(cleared) == 2, 'success immediately requests clear')
            callee, clear_args = invocation(cleared[0])
            require(callee == names['clear'] and len(clear_args) == 2
                    and comparison.pointer(clear_args[0]) == stage and clear_args[1] == 'i64 noundef 168', 'full success staging clear')
            _, clear_unwind = edges(cleared[1])
            require(clear_unwind == unwind, 'clear unwind uses same cleanup')
    return terminals


def cases(record):
    document = json.loads(record.read_text())
    comparison.validate_record(document, record.parent)
    for row in document['records']:
        if row['profile'] != 'release' or row['mode'] != 'accelerated':
            continue
        def artifact(package):
            return next((record.parent / path).read_text() for path in row['artifacts']
                        if Path(path).name.startswith(package + '-') and path.endswith('.ll'))
        yield artifact('brynja_hash_sha3'), artifact('brynja_core'), row['compiler'].splitlines()[0].split()[1]


def main(record):
    before = comparison.capture.sources()
    outcomes = [inspect(*case) for case in cases(record)]
    require(len(outcomes) == 4 and before == comparison.capture.sources(), 'complete unchanged accelerated matrix')
    print(f'Accelerated staging: four optimized producers and guards PASS; {sum(outcomes)} selected error/unwind exits')
    print('Read/write failures retain cleanup requests; unwind passes incomplete guard; successful write clears full staging')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Not callee erasure, all producer paths, debug, spills, abort or native-platform qualification; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
