"""Bounded absorption replay; helper calls have explicit checked byte effects.

Not a general emulator. Only assigned memory/calls/jumps are permitted; the
reviewed region and helper bodies must separately match the emitted image.
"""
import windows_enclave_sha2_index_machine as index
import windows_enclave_sha3_simd_absorb_shape as shape
s=shape.s
STACK,WORK,INPUT,TABLE,RATES,CONTROL=range(0x10000,0x70000,0x10000)
ERRORS=('.B207','.B208','.B210','.B211','.B213')


def run(code,n,memory,writable,tag,lane,poison=0xa5,fail_call=None,max_steps=40000):
    regs={name:poison*0x0101010101010101 for name,_ in index.REGS.values()}
    regs.update(rbp=STACK,rsp=STACK-128,rbx=WORK,r14=INPUT,r9=lane,r8=112*lane,rax=tag,
                rdx=WORK+3624+156*lane,r12=CONTROL)
    memory=dict(memory);before=dict(memory);cf=zf=None;calls=[];writes=[];call_sites=[]
    targets={TABLE+0x100+16*v:f'.B{v}' for v in shape.TARGETS}
    def address(operand):
        if operand=='.LJTI30_1(%rip)':return TABLE
        if operand=='switch.table.'+n['executor']+'.104(%rip)':return RATES
        return index.address(operand,regs)
    def read(operand,size):
        mask=(1<<(8*size))-1
        if operand.startswith('$'):return int(operand[1:])&mask
        if operand.startswith('%'):
            s.require(operand in index.REGS and index.REGS[operand][1]==size,'absorb read register width')
            return regs[index.REGS[operand][0]]&mask
        at=address(operand);s.require(all(at+i in memory for i in range(size)),'initialized absorb read')
        return int.from_bytes(bytes(memory[at+i] for i in range(size)),'little')
    def put(at,size,value):
        s.require(all(at+i in writable for i in range(size)),'assigned absorb write')
        memory.update(enumerate(value.to_bytes(size,'little'),at));writes.append((at,size))
    def write(operand,size,value):
        mask=(1<<(8*size))-1;value&=mask
        if operand.startswith('%'):
            s.require(operand in index.REGS and index.REGS[operand][1]==size,'absorb write register width')
            key,_=index.REGS[operand];regs[key]=value|(regs[key]&~mask) if size<4 else value
        else:put(address(operand),size,value)
    def condition(op):
        s.require(cf is not None and zf is not None,'initialized absorb flags')
        return {'e':zf,'ne':not zf,'b':cf,'ae':not cf,'a':not cf and not zf}[op]
    labels={l[:-1]:i for i,l in enumerate(code) if l.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in code),'unique absorb labels')
    pc=0;failure=None
    for steps in range(max_steps):
        if failure or pc==labels['.B91']:
            return dict(memory=memory,before=before,calls=calls,writes=writes,registers=regs,
                        failure=failure,steps=steps,call_sites=call_sites)
        s.require(0<=pc<len(code),'bounded absorb control')
        line=code[pc];pc+=1
        if line.endswith(':') or line=='vzeroupper':continue
        op,_,rest=line.partition(' ');a=rest.split(', ')
        if op in ('jmp','je','jne','jb','jae','ja'):
            if op=='jmp' or condition(op[1:]):
                if a[0] in ERRORS:failure=a[0];continue
                s.require(a[0] in labels,'assigned absorb branch');pc=labels[a[0]]
            continue
        if op=='jmpq':
            s.require(a==['*%rax'] and regs['rax'] in targets,'bounded framing part dispatch')
            pc=labels[targets[regs['rax']]];continue
        if op=='callq':
            s.require(a==[n['xor']],'only reviewed XOR helper')
            dst,src,right,count=(regs[k] for k in ('rcx','rdx','r8','r9'))
            right&=255;count&=255;left=read('32(%rsp)',1)
            s.require(WORK+1920+200*lane<=dst<WORK+2120+200*lane,'XOR stays in selected state')
            s.require(src in memory and (src not in writable or src==STACK+176),
                      'readonly XOR source or public pad byte')
            s.require(dst!=src and 0<=count<=8 and 0<=left<=15,'XOR private ABI and disjoint bytes')
            bad=not(1<=count<=8 and right<=8-count and left<=8-count)
            calls.append((dst,src,right,count,left,bad));call_sites.append(pc-1);bad|=len(calls)==fail_call
            if not bad:put(dst,1,memory[dst]^(((memory[src]>>right)&((1<<count)-1))<<left))
            for key in ('rax','rcx','rdx','r8','r9','r10','r11'):regs[key]=poison*0x0101010101010101
            regs['rax']=(regs['rax']&~255)|int(bad);cf=zf=None;continue
        if op in ('movzbl','movslq'):
            value=read(a[0],1 if op=='movzbl' else 4)
            if op=='movslq' and value&(1<<31):value-=1<<32
            write(a[1],4 if op=='movzbl' else 8,value);continue
        size={'q':8,'l':4,'b':1}.get(op[-1],0)
        if op in ('movq','movl','movb'):write(a[1],size,read(a[0],size));continue
        if op in ('leaq','leal'):write(a[1],size,address(a[0]));continue
        if op=='setne':write(a[0],1,int(condition('ne')));continue
        if op in ('cmovaeq','cmoveq','cmovbq','cmovnel'):
            if condition(op[4:-1]):write(a[1],size,read(a[0],size))
            continue
        if op=='imulq':write(a[2],8,read(a[0],8)*read(a[1],8));cf=zf=None;continue
        if op.startswith(('cmp','test')) and size:
            x,y=read(a[0],size),read(a[1],size)
            cf,zf=(y<x,y==x) if op.startswith('cmp') else (False,(x&y)==0);continue
        s.require(op in ('decq','incq','addq','addl','subq','subl','shrq','shll','shlb','xorl','orq','andl'),
                  'assigned absorb instruction: '+op)
        dst=a[-1];y=read(dst,size);mask=(1<<(8*size))-1
        x=1 if op in ('incq','decq') else read(a[0],1 if a[0]=='%cl' else size)
        if op.startswith('sh'):
            shift=x&(63 if size==8 else 31)
            if not shift:continue
            s.require(shift<=size*8,'defined reviewed shift carry')
            value=y>>shift if op=='shrq' else y<<shift
            cf=bool(y>>(shift-1 if op=='shrq' else size*8-shift)&1)
        elif op=='xorl':value=y^x;cf=False
        elif op=='orq':value=y|x;cf=False
        elif op=='andl':value=y&x;cf=False
        elif op.startswith('sub') or op=='decq':
            value=y-x
            if op!='decq':cf=y<x
        else:
            value=y+x
            if op!='incq':cf=value>mask
        write(dst,size,value);zf=value&mask==0
    raise ValueError('bounded absorption instruction budget exhausted')
