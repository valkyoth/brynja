"""Small integer/memory interpreter for the saved public lane-index regions.

Not an x86 emulator or a general memory-safety proof. Uninitialized reads,
unassigned writes/calls, unsupported instructions and excess steps fail closed.
Only public identities, counters and public IVs enter this interpreter.
"""
import re
import windows_enclave_kmac_shapes as s

REGS = {}
for full, short, low in (('rax','eax','al'), ('rbx','ebx','bl'), ('rcx','ecx','cl'),
                         ('rdx','edx','dl'), ('rsi','esi','sil'), ('rdi','edi','dil'),
                         ('rbp','ebp','bpl'), ('rsp','esp','spl')):
    for name, size in ((full,8),(short,4),(low,1)): REGS['%'+name] = (full,size)
for index in range(8,16):
    for suffix, size in (('',8),('d',4),('b',1)): REGS[f'%r{index}{suffix}'] = (f'r{index}',size)


def address(operand, registers):
    m = re.fullmatch(r'(-?\d*)\((%\w+)?(?:,(%\w+)(?:,([1248]))?)?\)', operand)
    s.require(m is not None, 'assigned index address expression')
    result = int(m[1] or 0)
    for name, scale in ((m[2],1),(m[3],int(m[4] or 1))):
        if name:
            s.require(name in REGS and REGS[name][1] == 8, '64-bit index address register')
            key = REGS[name][0]
            s.require(key in registers, 'initialized index address register')
            result += registers[key] * scale
    s.require(0 <= result < 1 << 64, 'nonwrapping reviewed index address')
    return result


def compile_region(lines, entry, exit_label):
    labels = {line[:-1]: i for i,line in enumerate(lines) if line.endswith(':')}
    s.require(len(labels) == sum(line.endswith(':') for line in lines), 'unique index labels')
    s.require(entry in labels and exit_label in labels, 'index entry and exit labels')
    allowed = {'movq','movl','movb','movzbl','leaq','xorl','cmpq','cmpl','cmpw',
               'testq','testl','incq','addq','shlq','shrq','andl','jmp','je','jne','ja','jbe','callq','vzeroupper'}
    code = []
    for line in lines:
        if line.endswith(':'):
            code.append(('label',[])); continue
        op, _, rest = line.partition(' ')
        s.require(op in allowed, 'supported public index instruction: '+op)
        operands = rest.split(', ') if rest else []
        s.require(len(operands) == (0 if op=='vzeroupper' else 1 if op in ('incq','jmp','je','jne','ja','jbe','callq') else 2),
                  'index instruction operand count')
        if op in ('jmp','je','jne','ja','jbe'):
            s.require(operands[0] in labels, 'index control flow stays in assigned region')
        code.append((op,operands))
    return code, labels, entry, exit_label


def run(program, registers, memory, writable, wipe, max_steps=4096):
    code, labels, entry, exit_label = program
    registers = dict(registers); memory = dict(memory); writes=[]; cf=zf=None
    def read(operand, size):
        if operand.startswith('$'): return int(operand[1:]) & ((1 << (size*8))-1)
        if operand.startswith('%'):
            s.require(operand in REGS and REGS[operand][1] == size, 'index register read width')
            key,_ = REGS[operand]; s.require(key in registers, 'initialized index register read')
            return registers[key] & ((1 << (size*8))-1)
        at=address(operand,registers)
        s.require(all(at+i in memory for i in range(size)), 'initialized index memory read')
        return int.from_bytes(bytes(memory[at+i] for i in range(size)), 'little')
    def write(operand,size,value):
        value &= (1 << (size*8))-1
        if operand.startswith('%'):
            s.require(operand in REGS and REGS[operand][1] == size, 'index register write width')
            key,_=REGS[operand]
            if size == 1:
                s.require(key in registers, 'partial write needs initialized upper register')
                value |= registers[key] & ~255
            registers[key]=value
        else:
            at=address(operand,registers)
            s.require(all(at+i in writable for i in range(size)), 'index write in assigned storage')
            for i,b in enumerate(value.to_bytes(size,'little')): memory[at+i]=b
            writes.append((at,size,value))
    pc=labels[entry]
    for step in range(max_steps):
        if pc == labels[exit_label]:
            return dict(registers=registers,memory=memory,writes=writes,steps=step)
        s.require(0 <= pc < len(code), 'no escaped index path')
        op,args=code[pc]; pc+=1
        if op=='label': continue
        if op=='vzeroupper': continue  # No vector value participates in public index computation.
        if op in ('jmp','je','jne','ja','jbe'):
            s.require(op=='jmp' or cf is not None and zf is not None, 'initialized branch flags')
            take=op=='jmp' or {'je':zf,'jne':not zf,'ja':not cf and not zf,'jbe':cf or zf}.get(op,False)
            if take: pc=labels[args[0]]
            continue
        if op=='callq':
            target,base,spans=wipe
            s.require(args==[target] and registers.get('rcx')==base, 'sole reviewed workspace wipe call')
            for offset,size in spans:
                for at in range(base+offset,base+offset+size):
                    s.require(at in writable, 'workspace wipe remains in assigned storage')
                    memory[at]=0
            for name in ('rax','rcx','rdx','r8','r9','r10','r11'): registers.pop(name,None)
            cf=zf=None
            continue
        size=8 if op.endswith('q') else 2 if op.endswith('w') else 1 if op=='movb' else 4
        if op=='leaq': write(args[1],8,address(args[0],registers)); continue
        if op=='movzbl': write(args[1],4,read(args[0],1)); continue
        if op.startswith('mov'): write(args[1],size,read(args[0],size)); continue
        if op in ('cmpq','cmpl','cmpw','testq','testl'):
            a,b=read(args[0],size),read(args[1],size)
            cf,zf=(b<a,b==a) if op.startswith('cmp') else (False,(a&b)==0)
            continue
        if op=='xorl':
            value=0 if args[0]==args[1] else read(args[0],4)^read(args[1],4)
            write(args[1],4,value);cf,zf=False,value==0;continue
        if op=='andl':
            value=read(args[0],4)&read(args[1],4)
            write(args[1],4,value);cf,zf=False,value==0;continue
        destination=args[0] if op=='incq' else args[1]
        before=read(destination,8)
        if op in ('shlq','shrq'):
            shift=read(args[0],8);s.require(0<shift<64,'assigned nonzero index shift')
            value=before<<shift if op=='shlq' else before>>shift
            cf=bool((before>>(64-shift if op=='shlq' else shift-1))&1)
        else:
            value=before+(1 if op=='incq' else read(args[0],8))
            if op!='incq':cf=value>=(1<<64)
        write(destination,8,value);zf=(value&((1<<64)-1))==0
    raise ValueError('bounded index instruction budget exhausted')
