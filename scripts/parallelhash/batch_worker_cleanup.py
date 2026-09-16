"""Recognize the exact worker Storage clear loop, not arbitrary loop programs.

For a valid Vec of 256-byte slots, the matched loop clears [base, base+256*n)
by induction: initial pointer=base, one full clear, increment=256, stop=end.
This relies on Vec's allocation/length invariant and non-unwinding external clear.
It does not prove worker joining, allocation reuse, machine lowering or caller
unwind dominance. Rust layouts are compiler-specific, not a stable ABI claim.
"""
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cryptography'))
import batch_cleanup_flow as cleanup
import batch_output_flow as output
import mir_cleanup_flow as flow

VALUE = r'%[\w.]+'
OWNER = 'execution::batch::worker::Storage'


def code(body):
    return '\n'.join(line for raw in body.splitlines()[1:]
                     if (line := raw.split(';', 1)[0].strip().split(', !', 1)[0]))


def loop_check(body):
    header = re.search(r'\(ptr (?P<base>' + VALUE + r'), i64 (?P<len>' + VALUE + r')\)', body.splitlines()[0])
    cleanup.require(header is not None, 'exact promoted Vec pointer/length parameters')
    base, length = map(re.escape, (header['base'], header['len']))
    # Optional nonnull assume is a compiler-expressed Vec invariant, never an
    # arbitrary predicate that could hide a loop or length case from inspection.
    prefix = (r'start:\n(?:' + r'(?P<nonnull>' + VALUE + r') = icmp ne ptr ' + base + r', null\n'
              r'tail call void @llvm.assume\(i1 (?P=nonnull)\)\n)?')
    pattern = (prefix +
        r'(?:(?P<bytes>' + VALUE + r') = shl nuw nsw i64 ' + length + r', 8\n)?' +
        r'(?P<end>' + VALUE + r') = getelementptr inbounds(?: nuw)? ' +
        r'(?(bytes)i8, ptr ' + base + r', i64 (?P=bytes)|\[4 x \[64 x i8\]\], ptr ' + base + r', i64 ' + length + r')\n' +
        r'(?P<empty>' + VALUE + r') = icmp eq i64 ' + length + r', 0\n' +
        r'br i1 (?P=empty), label %(?P<done>[\w.]+), label %(?P<loop>[\w.]+)\n' +
        r'(?P=loop):\n' +
        r'(?P<cursor>' + VALUE + r') = phi ptr \[ (?P<next>' + VALUE + r'), %(?P=loop) \], \[ ' + base + r', %start \]\n' +
        r'(?P=next) = getelementptr inbounds(?: nuw)? i8, ptr (?P=cursor), i64 256\n' +
        r'(?P<call>[^\n]+)\n' +
        r'(?P<last>' + VALUE + r') = icmp eq ptr (?P=next), (?P=end)\n' +
        r'br i1 (?P=last), label %(?P=done), label %(?P=loop)\n' +
        r'(?P=done):\nret void\n}')
    match = re.fullmatch(pattern, code(body))
    cleanup.require(match is not None, 'exact complete worker-storage affine loop')
    cleanup.require(output.instruction(match['call']) == ('clear', match['cursor'], '256'),
                    'worker iteration clears current full slot before advancing')


def check(row, panic):
    destructor = flow.exact_function(row['mir'],
        ('crates/brynja-hash-parallel-std/src/execution/batch/worker.rs:', '::drop(', '_1: &mut ' + OWNER))
    cleanup.linear_fields(destructor, [('self', OWNER, OWNER + '::clear(')], panic, OWNER)
    body = cleanup.llvm_function(row['ll'], ('9execution5batch6worker', '7Storage5clear'))
    loop_check(body)
    return destructor, body


def mutations(row, panic):
    destructor, body = check(row, panic)
    cases = [('mir', destructor, destructor.replace('Storage::clear(', 'Storage::omitted('))]
    for before, after in ((', 8\n', ', 7\n'), ('i64 256', 'i64 255'),
                          ('i64 noundef 256', 'i64 noundef 255'),
                          ('18clear_owned_region', '18ordinary_region'),
                          ('ret void', 'store i8 1, ptr null\nret void'),
                          ('shl nuw nsw', 'shl'), ('icmp eq ptr', 'icmp ne ptr'),
                          ('[4 x [64 x i8]]', '[3 x [64 x i8]]')):
        if before in body:
            cases.append(('ll', body, body.replace(before, after)))
    for extension, original, changed in cases:
        try:
            check(dict(row, **{extension: row[extension].replace(original, changed)}), panic)
        except (ValueError, flow.MirCleanupFlowError):
            continue
        raise AssertionError('worker cleanup regression survived')
    return len(cases)
