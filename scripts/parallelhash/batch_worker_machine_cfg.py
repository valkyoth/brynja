"""Closed instruction/label extraction for coordinator normal control flow.

The non-control allowlist asserts only instruction class, not data semantics.
CFI/LSDA/linker hints are recognized metadata but are NOT interpreted as unwind
edges. No indirect jumps, opaque directives, inline assembly or tail calls are
accepted. Ordinary returning callees must obey their ABI and symbol identity.
"""
import re

import batch_worker_inline as inline
from batch_cleanup_flow import require

X86_DATA = set('''adcq addb addl addq andl andq cmovaeq cmovbq cmovel cmovneq
cmpb cmpl cmpq decq incq leal leaq movabsq movaps movb movdqa movdqu movl movq
movups movw movzbl movzwl mulq negb negq notq orb orl orq pcmpeqb pmovmskb
popq pushq pxor sbbq seta setb sete setne seto sets shll shlq shrl shrq subq
testb testq xorl xorps xorq'''.split())
ARM_DATA = set('''adc adcs add adds adrp and bfi casa ccmp cinc cmn cmp csel
cset dmb ldadd ldaddl ldar ldarb ldapr ldaprb ldapur ldp ldr ldrb ldrh ldur
ldurh lsl lsr madd mov movi movi.2d movk mul orr sbc sbcs stlr stlur stp str
strb strh stur sturb sturh sub subs tst ubfiz umulh'''.split())
X86_BRANCH = set('ja jae jb jbe je jle jne jo'.split())
ARM_BRANCH = set('b.eq b.hi b.hs b.lo b.ls b.ne'.split())
LABEL = r'\.?L(?:BB[\w]+|tmp\d+|loh\d+|func_(?:begin|end)\d+)'
SYMBOL = r'[A-Za-z_][\w.$]*'
CFI = r'\.cfi_(?:def_cfa_offset|def_cfa|offset|personality|lsda|restore)\s+[^;\n]+'


def parse(body, arm):
    code, labels, raw_lines = [], {}, []
    begun = ended = False
    for source_line, raw in enumerate(body.splitlines()):
        require(not re.fullmatch(r'(?:#|//)\s*(?:NO_)?APP', raw.strip()), 'no inline assembly region')
        line = raw.split('//', 1)[0].strip()
        if not arm:
            line = line.split('#', 1)[0].strip()
        if not line:
            continue
        if line == '.cfi_startproc':
            require(not begun, 'one machine function entry')
            begun = True
            continue
        if line == '.cfi_endproc':
            require(begun and code, 'bounded machine function extent')
            ended = True
            break  # Exception tables/next-symbol headers are separate obligations.
        label = re.fullmatch('(' + LABEL + '):', line)
        if label:
            require(label[1] not in labels, 'unique coordinator machine label')
            labels[label[1]] = len(code)
            continue
        require(begun, 'no machine instruction before function entry')
        if re.fullmatch(CFI, line) or line in ('.cfi_remember_state', '.cfi_restore_state'):
            continue
        if re.fullmatch(r'\.p2align\s+\d+(?:, 0x[0-9a-f]+)?', line) or re.fullmatch(
                r'\.size\s+' + SYMBOL + r',\s*\.Lfunc_end\d+-' + SYMBOL, line):
            continue
        if re.fullmatch(r'\.loh (?:AdrpAdd|AdrpLdrGotLdr|AdrpLdrGotStr)\s+Lloh\d+(?:, Lloh\d+){1,2}', line):
            continue
        require(';' not in line, 'one machine instruction per line')
        parts = line.split(None, 1)
        args = re.split(r',\s*(?![^\[\]()]*[\])])', parts[1]) if len(parts) == 2 else []
        op = parts[0]
        if op == 'lock':
            require(not arm and re.fullmatch(r'lock\s+(?:incq|decq|xaddq|cmpxchgq)\s+[^;]+', line),
                    'reviewed non-control x86 lock operation')
        elif op in (ARM_DATA if arm else X86_DATA):
            require(args, 'nonempty data instruction')
        elif op in (ARM_BRANCH if arm else X86_BRANCH) or op == ('b' if arm else 'jmp'):
            require(len(args) == 1 and re.fullmatch(LABEL, args[0]), 'local direct machine branch')
        elif arm and op in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            require(len(args) == (2 if op in ('cbz', 'cbnz') else 3) and
                    re.fullmatch(r'[xw]\d+', args[0]) and re.fullmatch(LABEL, args[-1]) and
                    (len(args) == 2 or re.fullmatch(r'#\d+', args[1])), 'reviewed Arm tested branch')
        elif op in (('bl', 'blr') if arm else ('callq',)):
            require(len(args) == 1, 'single call target')
            if arm:
                require(re.fullmatch(r'x\d+' if op == 'blr' else SYMBOL, args[0]), 'reviewed Arm call')
            else:
                require(re.fullmatch(SYMBOL + r'(?:@PLT)?|\*' + SYMBOL + r'@GOTPCREL\(%rip\)|'
                                     r'\*%(?:r\w+)|\*(?:\d+)?\(%r\w+\)', args[0]), 'reviewed x86 call')
        elif op == ('ret' if arm else 'retq'):
            require(not args, 'ABI ordinary return')
        elif op == ('brk' if arm else 'ud2'):
            require(args == ['#0x1'] if arm else not args, 'reviewed terminal trap')
        else:
            raise ValueError('unreviewed coordinator machine instruction: ' + line)
        code.append((op, args))
        raw_lines.append((source_line, raw.strip()))
    require(ended, 'machine function end is present')
    for op, args in code:
        if op in (ARM_BRANCH | {'b', 'cbz', 'cbnz', 'tbz', 'tbnz'} if arm else X86_BRANCH | {'jmp'}):
            require(args[-1] in labels and labels[args[-1]] < len(code), 'existing executable machine successor')
    return code, labels, raw_lines


def call_symbol(op, args, arm, apple):
    if op not in (('bl',) if arm else ('callq',)):
        return None
    target = args[0]
    if not arm:
        if target.startswith('*'):
            if not target.endswith('@GOTPCREL(%rip)'):
                return None
            target = target[1:].removesuffix('@GOTPCREL(%rip)')
        target = target.removesuffix('@PLT')
    return target.removeprefix('_') if apple else target
