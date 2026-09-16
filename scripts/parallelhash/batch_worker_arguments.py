"""Closed checks for the standalone Storage destructor's promoted arguments.

The reviewed compiler layouts store Vec base at self+8 and live length at
self+16. Check their unchanged transfer to the exact qualified clear function,
in LLVM and machine code. This is not a stable Rust ABI claim, an inlined-call
proof, or proof that arbitrary callers constructed a valid Vec.
"""
import re

import batch_worker_cleanup as worker
from batch_cleanup_flow import require, llvm_function, assembly_function
from batch_worker_assembly import function_code

IDENTITIES = (
    ('execution..batch..worker..Storage', 'Drop$GT$4drop'),
    ('9execution5batch6worker', '7Storage', '4Drop4drop'),
)


def functions(row):
    matches = []
    for tokens in IDENTITIES:
        if any(line.startswith('define ') and all(token in line for token in tokens)
               for line in row['ll'].splitlines()):
            matches.append(tokens)
    require(len(matches) == 1, 'unique worker destructor mangling domain')
    clear = llvm_function(row['ll'], ('9execution5batch6worker', '7Storage5clear'))
    symbol = re.search(r'@([A-Za-z0-9_]+)\(', clear.splitlines()[0])
    require(symbol is not None, 'exact defined worker clear symbol')
    return (llvm_function(row['ll'], matches[0]),
            assembly_function(row['s'], matches[0]), symbol[1])


def llvm_check(body, symbol):
    header = body.splitlines()[0]
    argument = re.fullmatch(r'define void @(?:"[^"\n]+"|[\w]+)\(ptr '
                            r'(?:(?:noalias|nocapture|nofree|noundef|readonly|align 8|captures\(none\)) )+'
                            r'dereferenceable\(24\) (' + worker.VALUE + r')\)'
                            r'(?: unnamed_addr)?(?: #\d+)? \{', header)
    require(argument is not None, 'single valid 24-byte Storage input')
    owner = re.escape(argument[1])
    pattern = (
        r'start:\n(?P<bp>' + worker.VALUE + r') = getelementptr inbounds(?: nuw)? i8, ptr ' + owner + r', i64 8\n'
        r'(?P<base>' + worker.VALUE + r') = load ptr, ptr (?P=bp), align 8\n'
        r'(?P<lp>' + worker.VALUE + r') = getelementptr inbounds(?: nuw)? i8, ptr ' + owner + r', i64 16\n'
        r'(?P<len>' + worker.VALUE + r') = load i64, ptr (?P=lp), align 8\n'
        r'tail call fastcc void @' + re.escape(symbol) +
        r'\(ptr nonnull (?P=base), i64 (?P=len)\)(?: #\d+)?\nret void\n}')
    require(re.fullmatch(pattern, worker.code(body)) is not None,
            'unchanged original Vec base and live length to qualified clear')


def assembly_check(body, symbol):
    code, labels = function_code(body)
    require(not labels, 'straight-line worker argument handoff')
    x86 = [('movq', ['8(%rdi)', '%rax']), ('movq', ['16(%rdi)', '%rsi']),
           ('movq', ['%rax', '%rdi']), ('jmp', [symbol])]
    arm = [('ldp', ['x8', 'x1', '[x0, #8]']), ('mov', ['x0', 'x8']), ('b', [symbol])]
    apple = arm[:-1] + [('b', ['_' + symbol])]
    require(code in (x86, arm, apple), 'exact ABI-preserving full Vec argument transfer')


def check(row):
    llvm, assembly, symbol = functions(row)
    llvm_check(llvm, symbol)
    assembly_check(assembly, symbol)
    return llvm, assembly, symbol


def mutations(row):
    llvm, assembly, symbol = check(row)
    count = 0
    for original, checker, edits in (
        (llvm, llvm_check, (('i64 8\n', 'i64 0\n'), ('i64 16\n', 'i64 8\n'),
                           ('load ptr', 'load i64'), ('load i64', 'load i32'),
                           ('ptr nonnull %self.val,', 'ptr nonnull %self,'),
                           ('i64 %self.val1)', 'i64 1)'),
                           ('ret void', 'store i8 1, ptr %self\nret void'),
                           (symbol, symbol + '_wrong'))),
        (assembly, assembly_check, (('8(%rdi)', '0(%rdi)'), ('16(%rdi)', '8(%rdi)'),
                                   ('%rax, %rdi', '%rsi, %rdi'), ('movq', 'movl'),
                                   ('[x0, #8]', '[x0, #0]'), ('x8, x1', 'x8, x2'),
                                   ('x0, x8', 'x0, x1'), ('ldp', 'ldr'),
                                   (symbol, symbol + '_wrong'))),
    ):
        for before, after in edits:
            if before not in original:
                continue
            changed = original.replace(before, after)
            try:
                checker(changed, symbol)
            except ValueError:
                count += 1
                continue
            raise AssertionError('worker argument mutation survived: ' + before)
    require(count == 13, 'non-vacuous LLVM/assembly argument mutations')
    return count
