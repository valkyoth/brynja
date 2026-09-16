"""Strict MIR field and LLVM/assembly call checks for batch transport/stream cleanup."""
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cryptography'))
import batch_cleanup_flow as cleanup
import mir_cleanup_flow as flow

require = cleanup.require
WORKSPACE = 'execution::batch::Workspace'
STREAM = "stream::batch::Stream<'_, '_, '_>"
CANCEL = "stream::batch::Stream::<'_, '_, '_>::cancel("
HASH = 'brynja_hash_sha3::hardened_batch::Workspace'
ROOT = "execution::collector::Collector<'_, '_, '_>"
PREFIX = 'crates/brynja-hash-parallel/src/execution/'


def mir(row, panic):
    def get(file, method, owner):
        return flow.exact_function(row['mir'], (PREFIX + file + ':', '::' + method + '(', '_1: &mut ' + owner))
    selected = []
    def linear(file, method, owner, events, borrowed=()):
        body = get(file, method, owner)
        cleanup.linear_fields(body, [(f, cleanup.compact(k), c) for f, k, c in events], panic, owner, borrowed)
        selected.append(body)
    linear('batch.rs', 'clear', WORKSPACE, [('0', HASH, HASH + '::clear('),
           ('1', '[u8]', 'clear_owned_region('), ('2', '[u8]', 'clear_owned_region(')])
    linear('batch.rs', 'drop', WORKSPACE, [('self', WORKSPACE, WORKSPACE + '::clear(')])
    linear('batch/transfer.rs', 'drop', "TransferredLeaves<'_, '_, '_>",
           [('4', '[u8]', 'clear_owned_region(')], ('4',))
    linear('stream/batch.rs', 'cancel', STREAM, [('0', ROOT, "Collector::<'_, '_, '_>::cancel("),
           ('3', WORKSPACE, WORKSPACE + '::clear('), ('2', '[u8]', 'clear_owned_region('),
           ('4', '[u8]', 'clear_owned_region('), ('5', '[u8]', 'clear_owned_region(')], ('2',))
    linear('stream/batch.rs', 'drop', STREAM, [('self', STREAM, CANCEL)])
    linear('stream/batch/output.rs', 'drop', "stream::batch::output::StreamReader<'_, '_, '_, '_>",
           [('0', 'execution::' + STREAM, CANCEL)], ('0',))
    guard = get('stream/batch.rs', 'drop', "stream::batch::Operation<'_, '_, '_, '_>")
    blocks = flow.basic_blocks(guard)
    require(set(blocks) == {'bb0', 'bb1', 'bb2'}, 'exact conditional guard blocks')
    clean = lambda key: cleanup.compact(re.sub(r'Storage(?:Live|Dead)\(_\d+\);', '', blocks[key]))
    require(re.fullmatch(r'(?P<c>_\d+)=copy\(\(\*_1\)\.1:bool\);switchInt\(move(?P=c)\)->\[0:bb1,otherwise:bb2\];}', clean('bb0')),
            'incomplete guard must take cancellation edge')
    pattern = (r'(?P<s>_\d+)=(?:no_retag)?copy\(\(\*_1\)\.0:&mut' +
               re.escape(cleanup.compact('execution::' + STREAM)) + r'\);_\d+=' +
               re.escape(cleanup.compact(CANCEL)) + r'move(?P=s)\)->\[return:bb2,unwind' +
               ('continue' if panic == 'unwind' else 'unreachable') + r'\];}')
    require(re.fullmatch(pattern, clean('bb1')) and clean('bb2') == 'return;}}', 'guard clears exact stream before exit')
    return selected + [guard]


def llvm_calls(body, loads):
    aliases, calls, terminal = {'%self': ('owner', 0)}, [], False
    for raw in body.splitlines()[1:]:
        line = raw.split(';', 1)[0].strip().split(', !', 1)[0]
        if not line or line in ('start:', '}'):
            continue
        require(not terminal, 'no instructions after cleanup return')
        if line == 'ret void':
            terminal = True
            continue
        gep = re.fullmatch(r'(%[\w.]+) = getelementptr (?:inbounds(?: nuw)? )?i8, ptr (%[\w.]+), i64 (\d+)', line)
        if gep:
            base = aliases.get(gep[2])
            require(base and base[0] == 'owner' and gep[1] not in aliases, 'exact owner address')
            aliases[gep[1]] = ('owner', base[1] + int(gep[3]))
            continue
        load = re.fullmatch(r'(%[\w.]+) = load (ptr|i64), ptr (%[\w.]+), align \d+', line)
        if load:
            address = aliases.get(load[3])
            require(address and address[0] == 'owner' and (load[2], address[1]) in loads,
                    'exact borrowed-region field load')
            require(load[1] not in aliases, 'unique loaded value')
            aliases[load[1]] = loads[load[2], address[1]]
            continue
        call = re.fullmatch(r'(?:%[\w.]+ = )?(?:tail )?call (?:noundef i8|void) @([^\s(]+)\('
                            r'ptr (?:(?:noalias|nofree|noundef|nonnull|align \d+|dereferenceable\(\d+\)) )*'
                            r'(%[\w.]+)(?:, i64 (?:noundef )?(%[\w.]+|\d+))?\)(?: #\d+)?', line)
        require(call and call[2] in aliases, 'only reviewed whole-region cleanup calls: ' + line)
        symbol = call[1]
        if '11brynja_core13secret_memory18clear_owned_region' in symbol:
            require(call[3], 'clear length must be present')
            width = int(call[3]) if call[3].isdigit() else aliases.get(call[3])
            require(width is not None, 'known clear length')
            calls.append(('clear', aliases[call[2]], width))
        else:
            require(not call[3], 'no unknown nested arguments')
            if '16brynja_hash_sha314hardened_batch9workspace' in symbol and '9Workspace5clear' in symbol:
                kind = 'hash'
            else:
                require('20brynja_hash_parallel9execution9collector' in symbol and '9Collector6cancel' in symbol,
                        'exact nested root cancellation')
                kind = 'root'
            calls.append((kind, aliases[call[2]]))
    require(terminal, 'cleanup must return')
    return calls


def emitted(row):
    specifications = (
        (('9execution5batch', '9Workspace5clear'), {},
         [('hash', ('owner', 512)), ('clear', ('owner', 0), 256), ('clear', ('owner', 256), 256)]),
        (('9execution6stream5batch', '6Stream6cancel'),
         {('ptr', 1152): ('loan', 2), ('i64', 1160): ('length', 2)},
         [('root', ('owner', 0)), ('hash', ('owner', 1744)),
          ('clear', ('owner', 1232), 256), ('clear', ('owner', 1488), 256),
          ('clear', ('loan', 2), ('length', 2)), ('clear', ('owner', 1168), 16), ('clear', ('owner', 1184), 16)]),
        (('8transfer', '17TransferredLeaves', '4drop'), {('ptr', 32): ('loan', 4)},
         [('clear', ('loan', 4), 256)]),
    )
    bodies = []
    for tokens, loads, expected in specifications:
        if tokens[0] == '8transfer':
            legacy = 'brynja_hash_parallel..execution..batch..transfer..TransferredLeaves$u20$as$u20$core..ops..drop..Drop$GT$4drop'
            if legacy in row['ll']:
                require(not re.search(r'^define[^\n]*17TransferredLeaves[^\n]*4drop', row['ll'], re.M),
                        'no ambiguous legacy/v0 transfer destructor')
                tokens = (legacy,)
        llvm = cleanup.llvm_function(row['ll'], tokens)
        require(llvm_calls(llvm, loads) == expected, 'exact LLVM cleanup regions and order')
        assembly = cleanup.assembly_function(row['s'], tokens)
        calls = cleanup.assembly_calls(assembly)
        require(len(calls) == len(expected), 'exact assembly cleanup call count')
        for symbol, event in zip(calls, expected):
            if event[0] == 'clear':
                require('18clear_owned_region' in symbol, 'assembly clear')
            elif event[0] == 'hash':
                require('14hardened_batch9workspace' in symbol and '9Workspace5clear' in symbol, 'assembly hardened hash owner')
            else:
                require('9collector' in symbol and '9Collector6cancel' in symbol, 'assembly root cancellation')
        bodies.append((llvm, assembly))
    return bodies


def check(row, panic):
    mir(row, panic)
    emitted(row)


def reject(row, panic):
    try:
        check(row, panic)
    except (ValueError, flow.MirCleanupFlowError):
        return
    raise AssertionError('ParallelHash cleanup mutation survived')


def mutations(row, panic):
    selected = mir(row, panic)
    bodies = emitted(row)
    cases = []
    for index, before, after in (
        (0, '((*_1).0:', '((*_1).1:'),
        (0, 'clear_owned_region(', 'omitted_clear('),
        (1, 'Workspace::clear(', 'Workspace::omitted('),
        (2, '((*_1).4:', '((*_1).3:'),
        (2, 'clear_owned_region(', 'omitted_clear('),
        (3, '((*_1).2:', '((*_1).1:'),
        (3, '((*_1).4:', '((*_1).5:'),
        (3, 'Collector::', 'OrdinaryRoot::'),
        (4, '::cancel(', '::omitted('),
        (5, '((*_1).0:', '((*_1).1:'),
        (6, '0: bb1, otherwise: bb2', '1: bb1, otherwise: bb2'),
        (6, '((*_1).0:', '((*_1).1:'),
    ):
        source = selected[index]
        cases.append(('mir', source, source.replace(before, after)))
    for llvm, assembly in bodies:
        cases += [('ll', llvm, llvm.replace('18clear_owned_region', '18ordinary_region')),
                  ('ll', llvm, llvm.replace('i64 noundef 256)', 'i64 noundef 255)').replace('i64 256)', 'i64 255)')),
                  ('ll', llvm, llvm.replace('ret void', 'store i8 1, ptr %self\n  ret void')),
                  ('s', assembly, assembly.replace('18clear_owned_region', '18ordinary_region'))]
        for match in re.finditer(r'getelementptr inbounds(?: nuw)? i8, ptr %self, i64 (\d+)', llvm):
            cases.append(('ll', llvm, llvm[:match.start(1)] + str(int(match[1]) + 1) + llvm[match.end(1):]))
    for extension, original, changed in cases:
        require(original != changed, 'live ParallelHash cleanup mutation')
        reject(dict(row, **{extension: row[extension].replace(original, changed)}), panic)
    return len(cases)
