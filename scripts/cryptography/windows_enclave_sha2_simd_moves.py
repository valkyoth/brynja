"""Small symbolic byte-copy checker for selected emitted aggregate moves only.

No arithmetic, branches, calls, indexed addressing or arbitrary x86 semantics
are accepted. Unseeded bytes retain distinct unknown origins, never zero values.
"""
import re
import windows_enclave_kmac_shapes as s


def register(name):
    vector=re.fullmatch(r'%(xmm|ymm)(\d+)',name)
    if vector and int(vector[2])<16: return 'v'+vector[2],16 if vector[1]=='xmm' else 32
    for family in ('a','b','c','d'):
        aliases={f'%r{family}x':8,f'%e{family}x':4,f'%{family}x':2,f'%{family}l':1}
        if name in aliases: return family,aliases[name]
    for family in ('si','di','bp','sp'):
        aliases={f'%r{family}':8,f'%e{family}':4,f'%{family}':2,f'%{family}l':1}
        if name in aliases: return family,aliases[name]
    match=re.fullmatch(r'%r(8|9|1[0-5])([dwb]?)',name)
    if match:return 'r'+match[1],{'':8,'d':4,'w':2,'b':1}[match[2]]
    raise ValueError('unsupported move register '+name)


def memory(operand):
    match=re.fullmatch(r'(-?\d*)\(%(rbx|rbp|rsi)\)',operand)
    s.require(match is not None,'direct assigned move-memory base only: '+operand)
    return match[2],int(match[1] or '0')


def evaluate(code,seed):
    mem=dict(seed);regs={}
    bases={register('%'+base)[0] for base in re.findall(r'\(%(rbx|rbp|rsi)\)', '\n'.join(code))}
    def read(operand,size):
        if operand.startswith('%'):
            name,width=register(operand);s.require(width==size,'move source register width')
            return regs.get(name,[('register',name,i) for i in range(32 if name.startswith('v') else 8)])[:size]
        base,offset=memory(operand)
        return [mem.get((base,offset+i),('memory',base,offset+i)) for i in range(size)]
    def write(operand,values):
        if operand.startswith('%'):
            name,width=register(operand);s.require(len(values)==width,'move destination register width')
            s.require(name not in bases,'copy trace cannot modify its address bases')
            old=regs.get(name,[('register',name,i) for i in range(32 if name.startswith('v') else 8)])
            # VEX xmm writes clear upper ymm; 32-bit GPR writes clear high half.
            regs[name]=(values+[0]*(len(old)-width) if name.startswith('v') or width==4 else values+old[width:])
        else:
            base,offset=memory(operand)
            for i,value in enumerate(values): mem[(base,offset+i)]=value
    for line in code:
        op,operands=line.split(' ',1)
        s.require(op in ('movb','movw','movl','movq','movzbl','movzwl','vmovaps','vmovups','vmovdqa','vmovdqu'),
                  'copy trace admits moves only')
        parts=operands.split(', ');s.require(len(parts)==2,'two move operands')
        source,dest=parts
        s.require(source.startswith('%') or dest.startswith('%'),'memory-to-memory move is invalid')
        if op.startswith('vmov'):
            vector=source if source.startswith('%') else dest
            name,size=register(vector);s.require(name.startswith('v'),'vector move requires vector register')
            values=read(source,size)
        else:
            size={'movb':1,'movw':2,'movl':4,'movq':8,'movzbl':1,'movzwl':2}[op]
            values=read(source,size)
            if op in ('movzbl','movzwl'): values += [0]*(4-size)
        write(dest,values)
    return mem


def trace(body,first,last,source,destination,size):
    lines=s.lines(body)
    s.require(lines.count(first)==lines.count(last)==1,'unique aggregate move boundaries')
    a,b=lines.index(first),lines.index(last);s.require(a<=b,'ordered aggregate moves')
    seed={(source[0],source[1]+i):('source',i) for i in range(size)}
    result=evaluate(lines[a:b+1],seed)
    actual=[result.get((destination[0],destination[1]+i)) for i in range(size)]
    s.require(actual==[('source',i) for i in range(size)],'complete ordered descriptor-byte preservation')
    return dict(first=first,last=last,source=list(source),destination=list(destination),bytes=size,
                moves=b-a+1,unseeded_bytes_never_assumed_initialized=True)
