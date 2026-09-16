"""Inspect distinct SHA-2 batch workspace cleanup without ordinary-owner aliases."""
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cryptography'))
import batch_cleanup_flow as cleanup
import mir_cleanup_flow as flow

require = cleanup.require


def workspace(row, family, panic):
    wide = family == 'sha512'
    module = 'hardened_batch512' if wide else 'hardened_batch'
    owner = module + '::workspace::Workspace'
    source = f'crates/brynja-hash-sha2/src/{module}/'
    wipe = owner + '::wipe('
    scalar = 'hardened::owner::HardenedSha2Owner'
    cpu = f'brynja_crypto_cpu::{family}_hardened_batch::Workspace'
    expected = [(str(i), '[u8]', 'clear_owned_region(') for i in range(7)]
    expected += [('7', scalar, 'HardenedSha2Owner::wipe('), ('8', cpu, cpu + '::clear(')]
    selected = flow.exact_function(row['mir'], (source + 'workspace.rs:', '::wipe(', '_1: &mut ' + owner))
    cleanup.linear_fields(selected, expected, panic, owner)
    destructor = flow.exact_function(row['mir'], (source + 'workspace.rs:', '::drop(', '_1: &mut ' + owner))
    cleanup.linear_fields(destructor, [('self', owner, wipe)], panic, owner)
    guard = flow.exact_function(row['mir'], (source + 'mod.rs:', '::drop(', '&mut ' + module + '::Operation<'))
    cleanup.entry_cleanup(guard, wipe, owner, panic)

    # Mangled identifier includes its length so narrow cannot match wide.
    identity = (f'{len(module)}{module}', '9workspace', '9Workspace4wipe')
    body = cleanup.llvm_function(row['ll'], identity)
    code = '\n'.join(line for line in body.splitlines() if not line.lstrip().startswith(';'))
    require(not re.search(r'\b(?:br|switch|invoke|unreachable)\b', code), 'straight emitted workspace clear')
    calls = [line for line in code.splitlines() if re.search(r'\bcall\b', line)]
    clears = [line for line in calls if '18clear_owned_region' in line]
    widths = [256, 256, 512, 256, 32 if wide else 64, 4 if wide else 8, 1]
    observed = []
    for line in clears:
        match = re.search(r'i64 (?:noundef )?(\d+)\)', line)
        require(match is not None, 'constant full-region LLVM width')
        observed.append(int(match[1]))
    require(observed == widths and len(calls) == 9, 'exact seven byte regions and two nested owners')
    require(sum('17HardenedSha2Owner4wipe' in line for line in calls) == 1, 'nested scalar clear')
    require(sum(f'{family}_hardened_batch' in line and '9Workspace5clear' in line for line in calls) == 1,
            'distinct nested hardened CPU clear')

    asm = cleanup.assembly_function(row['s'], identity)
    # Require actual direct calls/tail calls, not names in comments or debug data.
    calls = cleanup.assembly_calls(asm)
    require(len(calls) == 9, 'only the nine reviewed assembly cleanup calls')
    require(sum('18clear_owned_region' in line for line in calls) == 7, 'seven assembly clearing calls')
    require(sum('17HardenedSha2Owner4wipe' in line for line in calls) == 1, 'scalar assembly clear')
    require(sum(f'{family}_hardened_batch' in line and '9Workspace5clear' in line for line in calls) == 1,
            'distinct CPU assembly clear')
    return selected, destructor, guard, body, asm


def check(row, panic):
    for family in ('sha256', 'sha512'):
        workspace(row, family, panic)


def mutations(row, panic):
    count = 0
    for family in ('sha256', 'sha512'):
        wipe, drop, guard, llvm, asm = workspace(row, family, panic)
        for field in range(7):
            needle = f'((*_1).{field}:'
            replacement = f'((*_1).{(field + 1) % 7}:'
            changed = wipe.replace(needle, replacement)
            require(changed != wipe, 'field mutation anchor')
            mutant = dict(row, mir=row['mir'].replace(wipe, changed))
            reject(mutant, panic)
            count += 1
        for extension, original, changed in (
            ('mir', wipe, wipe.replace('clear_owned_region(', 'omitted_clear(')),
            ('mir', wipe, wipe.replace('HardenedSha2Owner::wipe(', 'ordinary_owner::wipe(')),
            ('mir', wipe, wipe.replace(f'{family}_hardened_batch::Workspace::clear(', f'{family}_batch::Workspace::clear(')),
            ('mir', wipe, wipe.replace('as_flattened_mut(', 'partial_slice(')),
            ('mir', drop, drop.replace('Workspace::wipe(', 'Workspace::omitted(')),
            ('mir', guard, guard.replace('((*_1).1:', '((*_1).0:')),
            ('mir', guard, guard.replace('Workspace::wipe(', 'Workspace::omitted(')),
            ('ll', llvm, llvm.replace('i64 noundef 256)', 'i64 noundef 128)').replace('i64 256)', 'i64 128)')),
            ('ll', llvm, llvm.replace('18clear_owned_region', '18omitted_region')),
            ('ll', llvm, llvm.replace('17HardenedSha2Owner4wipe', '17OrdinarySha2Owner4wipe')),
            ('s', asm, asm.replace('18clear_owned_region', '18omitted_region')),
            ('s', asm, asm.replace(f'{family}_hardened_batch', f'{family}_ordinary_batch')),
        ):
            require(original != changed, 'live artifact mutation')
            reject(dict(row, **{extension: row[extension].replace(original, changed)}), panic)
            count += 1
    return count


def reject(row, panic):
    try:
        check(row, panic)
    except (ValueError, flow.MirCleanupFlowError):
        return
    raise AssertionError('compiler cleanup mutation survived')
