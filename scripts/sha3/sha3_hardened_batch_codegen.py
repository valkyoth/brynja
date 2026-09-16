"""Inspect complete emitted SHA-3 batch workspace coverage and frame provenance.

The MIR frame inspector binds named fields; the LLVM inspector checks the fully
unrolled workspace, exact nested clearing owners and nonoverlapping coverage of
all 5260 bytes. Unknown layout/control-flow shapes fail closed. The nested owner
implementations and their non-panicking contracts are separate obligations.
"""
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cryptography'))
import batch_cleanup_flow as cleanup
import mir_cleanup_flow as flow

require = cleanup.require
IDENTITY = ('14hardened_batch', '9workspace', '9Workspace4wipe')
WIDTHS = [800, 800, 32, 32, 4, 4, 4] + [72, 51, 32, 1] * 4
SCALAR = 'HardenedFips202Owner'
CPU = '21keccak_hardened_batch'


def llvm_coverage(body):
    header = body.splitlines()[0]
    require(re.search(r'dereferenceable\(5260\) %self\)', header), 'exact workspace extent')
    aliases, spans, kinds, returned = {'%self': 0}, [], [], False
    for raw in body.splitlines()[1:]:
        line = raw.strip()
        if not line or line.startswith(';') or line in ('start:', '}'):
            continue
        require(not returned, 'no instructions after return')
        gep = re.fullmatch(r'(%[\w.]+) = getelementptr inbounds(?: nuw)? i8, ptr (%[\w.]+), i64 (\d+)', line)
        if gep:
            require(gep[1] not in aliases and gep[2] in aliases, 'unique derived workspace address')
            aliases[gep[1]] = aliases[gep[2]] + int(gep[3])
            continue
        if line == 'ret void':
            returned = True
            continue
        call = re.fullmatch(r'(?:%[\w.]+ = )?(?:tail )?call (?:noundef i8|void) @([^\s(]+)\((.*)\)(?: #\d+)?', line)
        require(call is not None, 'unreviewed workspace LLVM instruction: ' + line)
        symbol, args = call.groups()
        argument = re.fullmatch(r'ptr (?:(?:noalias|nofree|noundef|nonnull|align [1-9][0-9]*) )*'
                                r'(?:dereferenceable\((\d+)\) )?(%[\w.]+)(?:, i64 (?:noundef )?(\d+))?', args)
        require(argument and argument[2] in aliases, 'whole workspace-derived call argument: ' + args)
        if '18clear_owned_region' in symbol:
            require('11brynja_core13secret_memory18clear_owned_region' in symbol and argument[3], 'exact clearing callee')
            width, kind = int(argument[3]), 'bytes'
        elif scalar(symbol):
            require('16brynja_hash_sha38hardened5owner' in symbol and not argument[3]
                    and argument[1] == '1040', 'exact nested scalar owner')
            width, kind = 1040, 'scalar'
        else:
            require('17brynja_crypto_cpu' + CPU in symbol and '9Workspace5clear' in symbol
                    and not argument[3] and argument[1] == '1920', 'distinct nested CPU owner: ' + line)
            width, kind = 1920, 'cpu'
        start = aliases[argument[2]]
        spans.append((start, start + width))
        kinds.append((kind, width))
    require(returned and kinds == [('bytes', width) for width in WIDTHS] + [('scalar', 1040), ('cpu', 1920)],
            'seven byte regions, all four frames and two nested owners')
    end = 0
    for start, stop in sorted(spans):
        require(start == end and stop > start, 'complete disjoint workspace coverage')
        end = stop
    require(end == 5260, 'no uncovered workspace suffix')


def check(row, panic):
    source = 'crates/brynja-hash-sha3/src/hardened_batch/'
    frame = flow.exact_function(row['mir'], (source + 'framing.rs:', '::wipe(', '_1: &mut Frame)'))
    cleanup.linear_fields(frame, [(str(i), '[u8]', 'clear_owned_region(') for i in range(4)], panic, 'Frame')
    drop = flow.exact_function(row['mir'], (source + 'framing.rs:', '::drop(', '_1: &mut Frame)'))
    cleanup.linear_fields(drop, [('self', 'Frame', 'Frame::wipe(')], panic, 'Frame')
    owner = 'hardened_batch::workspace::Workspace'
    workspace_drop = flow.exact_function(row['mir'], (source + 'workspace.rs:', '::drop(', '_1: &mut ' + owner))
    cleanup.linear_fields(workspace_drop, [('self', owner, owner + '::wipe(')], panic, owner)
    guard = flow.exact_function(row['mir'], (source + 'mod.rs:', '::drop(', '_1: &mut Operation<'))
    cleanup.entry_cleanup(guard, owner + '::wipe(', owner, panic)
    llvm = cleanup.llvm_function(row['ll'], IDENTITY)
    llvm_coverage(llvm)
    asm = cleanup.assembly_function(row['s'], IDENTITY)
    calls = cleanup.assembly_calls(asm)
    require(len(calls) == 25 and all('18clear_owned_region' in call for call in calls[:23])
            and scalar(calls[23])
            and CPU in calls[24] and '9Workspace5clear' in calls[24], 'ordered assembly clearing calls')
    return frame, drop, workspace_drop, guard, llvm, asm


def scalar(symbol):
    # Rust 1.90 uses legacy mangling for this const-generic type; 1.98 uses v0.
    return bool(re.search(r'(?:20HardenedFips202Owner|29HardenedFips202Owner\$LT\$_\$GT\$)', symbol)
                and '4wipe' in symbol)


def reject(row, panic):
    try:
        check(row, panic)
    except (ValueError, flow.MirCleanupFlowError):
        return
    raise AssertionError('SHA-3 batch cleanup mutation survived')


def mutations(row, panic):
    frame, drop, workspace_drop, guard, llvm, asm = check(row, panic)
    cases = []
    for field in range(4):
        cases.append(('mir', frame, frame.replace(f'((*_1).{field}:', f'((*_1).{(field + 1) % 4}:')))
    cases += [
        ('mir', frame, frame.replace('clear_owned_region(', 'omitted_clear(')),
        ('mir', drop, drop.replace('Frame::wipe(', 'Frame::omitted(')),
        ('mir', workspace_drop, workspace_drop.replace('Workspace::wipe(', 'Workspace::omitted(')),
        ('mir', guard, guard.replace('((*_1).1:', '((*_1).0:')),
        ('ll', llvm, llvm.replace('ret void', 'store i8 1, ptr %self\n  ret void')),
        ('ll', llvm, llvm.replace('ret void', 'br label %bypass\nbypass:\n  ret void')),
        ('ll', llvm, llvm.replace('18clear_owned_region', '18ordinary_region')),
        ('ll', llvm, llvm.replace(CPU, '12keccak_batch')),
        ('ll', llvm, llvm.replace(SCALAR, '18OrdinaryFipsOwner')),
        ('s', asm, asm.replace('18clear_owned_region', '18ordinary_region')),
        ('s', asm, asm.replace(CPU, '12keccak_batch')),
    ]
    # Every individual unrolled region must remain both present and correctly sized.
    for match in re.finditer(r'^.*\bcall\b.*18clear_owned_region.*$', llvm, re.M):
        line = match[0]
        wrong_width = re.sub(r'i64 (?:noundef )?(\d+)\)', lambda m: 'i64 noundef ' + str(int(m[1]) - 1) + ')', line)
        cases.append(('ll', llvm, llvm[:match.start()] + wrong_width + llvm[match.end():]))
    for match in re.finditer(r'getelementptr inbounds(?: nuw)? i8, ptr %self, i64 (\d+)', llvm):
        # Shift a real region address; width/call-count-only checks would miss this.
        cases.append(('ll', llvm, llvm[:match.start(1)] + str(int(match[1]) + 1) + llvm[match.end(1):]))
    for extension, original, changed in cases:
        require(original != changed, 'live SHA-3 compiler mutation')
        reject(dict(row, **{extension: row[extension].replace(original, changed)}), panic)
    return len(cases)
