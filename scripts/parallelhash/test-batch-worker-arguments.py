#!/usr/bin/env python3
"""Reject shifted, substituted, truncated and omitted Storage arguments."""
import batch_worker_arguments as check

SYMBOL = '_ZN24brynja_hash_parallel_std9execution5batch6worker7Storage5clear17h1234E'
LLVM = '''define void @destructor(ptr noalias readonly align 8 dereferenceable(24) %self) {
start:
%0 = getelementptr inbounds nuw i8, ptr %self, i64 8
%self.val = load ptr, ptr %0, align 8
%1 = getelementptr inbounds nuw i8, ptr %self, i64 16
%self.val1 = load i64, ptr %1, align 8
tail call fastcc void @CLEAR(ptr nonnull %self.val, i64 %self.val1)
ret void
}'''.replace('CLEAR', SYMBOL)
X86 = 'movq 8(%rdi), %rax\nmovq 16(%rdi), %rsi\nmovq %rax, %rdi\njmp ' + SYMBOL
ARM = 'ldp x8, x1, [x0, #8]\nmov x0, x8\nb ' + SYMBOL


def rejects(inspector, body):
    try:
        inspector(body, SYMBOL)
    except ValueError:
        return
    raise AssertionError('worker argument regression survived: ' + body)


def main():
    count = 0
    check.llvm_check(LLVM, SYMBOL)
    check.llvm_check(LLVM.replace('%self', '%renamed'), SYMBOL)
    for before, after in (
        ('i64 8\n', 'i64 0\n'), ('i64 16\n', 'i64 8\n'),
        ('ptr %0,', 'ptr %1,'), ('ptr %1,', 'ptr %0,'),
        ('i64 %self.val1)', 'i64 0)'), ('i64 %self.val1)', 'i64 1)'),
        ('ptr nonnull %self.val', 'ptr nonnull %self'),
        ('ptr nonnull %self.val', 'ptr null'), ('load i64', 'load i32'),
        ('@' + SYMBOL, '@wrong'), ('%self) {', '%self, ptr %foreign) {'),
        ('@destructor(ptr ', '@destructor(ptr %foreign, ptr '),
        ('ret void', 'store i64 0, ptr %1\nret void'),
        ('ret void', 'br label %start'),
    ):
        rejects(check.llvm_check, LLVM.replace(before, after))
        count += 1
    for template in (X86, ARM, ARM.replace('b _', 'b __')):
        body = '.cfi_startproc\n' + template + '\n.cfi_endproc'
        check.assembly_check(body, SYMBOL)
        abort = template + '\n.globl _Next\n.p2align 2'
        check.assembly_check(abort, SYMBOL)
        for line in template.splitlines():
            for replacement in ('', 'unknown_op', line + '\nret'):
                rejects(check.assembly_check, body.replace(line, replacement))
                count += 1
        for before, after in (('8(%rdi)', '0(%rdi)'), ('16(%rdi)', '8(%rdi)'),
                              ('%rax, %rdi', '%rsi, %rdi'), ('movq', 'movl'),
                              ('[x0, #8]', '[x0, #16]'), ('x8, x1', 'x8, x2'),
                              ('x0, x8', 'x0, x1'), ('ldp', 'ldr'),
                              (SYMBOL, SYMBOL + '_wrong')):
            if before in body:
                rejects(check.assembly_check, body.replace(before, after))
                count += 1
        rejects(check.assembly_check, abort + '\n.byte 0')
        count += 1
    print(f'Worker destructor arguments reject {count} provenance/ABI/boundary regressions')


if __name__ == '__main__':
    main()
