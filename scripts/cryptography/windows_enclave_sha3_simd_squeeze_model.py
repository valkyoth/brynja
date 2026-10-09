"""Bounded saved-lane replay with synthetic bytes and checked helper effects.

This checks copying/masking/counters, not Keccak permutation correctness or
the lifetimes of pointers reaching this region from every predecessor.
"""
import windows_enclave_sha2_index_machine as index
import windows_enclave_sha3_simd_squeeze_shape as shape
s=shape.s
STACK,WORK,INPUT,STAGING,TABLE,CONTROL=range(0x10000,0x70000,0x10000)
RATES=(144,136,104,72,168,136,168,136)
MASK=(1<<64)-1


def run(code,n,tag,bits,written,start,lane,poison=0xa5,copy_failure=False,max_steps=256):
    s.require(0<=tag<8 and 0<=bits<=MASK and 0<=written<=MASK and 0<=start<=MASK and
              0<=lane<4,'bounded squeeze model inputs')
    regs={name:poison*0x0101010101010101 for name,_ in index.REGS.values()}
    regs.update(rbp=STACK,rbx=WORK,r14=INPUT,r15=STAGING,r8=112*lane,r9=lane,rax=tag,
                rdx=WORK+3624+156*lane,r12=CONTROL)
    memory={};writable=set();events=[];cf=zf=None
    def seed(at,size,value):memory.update(enumerate(value.to_bytes(size,'little'),at))
    for at,size in ((WORK,5260),(STAGING,1024)):
        for i in range(size):memory[at+i]=(i*73+(i//200)*29+poison)&255
    writable.update(range(STAGING,STAGING+1024))
    writable.update(range(WORK+3552,WORK+3584));writable.update(range(WORK+5248,WORK+5252))
    for offset in (816,832,864,896,952):writable.update(range(STACK+offset,STACK+offset+8))
    for offset,value in ((1104,WORK),(960,WORK+1920),(888,WORK+5248),(968,INPUT),(1120,CONTROL)):
        seed(STACK+offset,8,value)
    seed(INPUT+112*lane+96,8,bits);seed(WORK+3552+8*lane,8,written)
    seed(WORK+3520+8*lane,8,start)
    for i,rate in enumerate(RATES):seed(TABLE+8*i,8,rate)
    before=dict(memory)
    def address(operand):
        if operand=='switch.table.'+n['executor']+'(%rip)':return TABLE
        return index.address(operand,regs)
    def read(operand,size):
        mask=(1<<(8*size))-1
        if operand.startswith('$'):return int(operand[1:])&mask
        if operand.startswith('%'):
            s.require(operand in index.REGS and index.REGS[operand][1]==size,'squeeze register read width')
            return regs[index.REGS[operand][0]]&mask
        at=address(operand);s.require(all(at+i in memory for i in range(size)),'initialized squeeze read')
        return int.from_bytes(bytes(memory[at+i] for i in range(size)),'little')
    def write(operand,size,value):
        mask=(1<<(8*size))-1;value&=mask
        if operand.startswith('%'):
            s.require(operand in index.REGS and index.REGS[operand][1]==size,'squeeze register write width')
            key,_=index.REGS[operand];regs[key]=value|(regs[key]&~mask) if size<4 else value
        else:
            at=address(operand);s.require(all(at+i in writable for i in range(size)),'assigned squeeze write')
            seed(at,size,value)
    def condition(which):
        s.require(cf is not None and zf is not None,'initialized squeeze flags')
        return {'e':zf,'ne':not zf,'b':cf,'ae':not cf}[which]
    labels={l[:-1]:i for i,l in enumerate(code) if l.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in code),'unique squeeze labels')
    pc=labels['.B122'];failed=False
    for steps in range(max_steps):
        if failed or pc==labels['.B91']:
            return dict(failed=failed,memory=memory,before=before,events=events,registers=regs,steps=steps)
        s.require(0<=pc<len(code),'bounded squeeze control')
        line=code[pc];pc+=1
        if line.endswith(':') or line=='vzeroupper':continue
        op,_,rest=line.partition(' ');a=rest.split(', ')
        if op in ('jmp','je','jne','jb'):
            if op=='jmp' or condition(op[1:]):
                if a[0]=='.B207':failed=True;continue
                s.require(a[0] in labels,'assigned squeeze branch');pc=labels[a[0]]
            continue
        if op=='callq':
            if a==[n['copy']]:
                dest,length,source,other=(regs[k] for k in ('rcx','rdx','r8','r9'))
                s.require(0<length<=200 and length==other,'matching bounded copy lengths')
                s.require(source==WORK+1920+200*lane,'correct lane state source')
                s.require(STAGING<=dest and dest+length<=STAGING+1024,'copy stays in staging')
                s.require(source+length<=dest or dest+length<=source,'nonoverlap copy')
                events.append(('copy',dest,length,source))
                if not copy_failure:
                    for i in range(length):memory[dest+i]=memory[source+i]
            elif a==[n['mask']]:
                dest,mask=regs['rcx'],regs['rdx']&255
                s.require(STAGING<=dest<STAGING+1024 and mask in (1,3,7,15,31,63,127),
                          'bounded partial-byte mask preconditions')
                memory[dest]&=mask;events.append(('mask',dest,mask))
            else:raise ValueError('unassigned squeeze helper')
            for key in ('rax','rcx','rdx','r8','r9','r10','r11'):regs[key]=poison*0x0101010101010101
            if a==[n['copy']]:regs['rax']=(regs['rax']&~255)|(0 if copy_failure else 255)
            cf=zf=None;continue
        if op in ('setne','setb','setae'):write(a[0],1,int(condition(op[3:])));continue
        size={'q':8,'l':4,'b':1}.get(op[-1],0)
        if op in ('leaq','leal'):write(a[1],size,address(a[0]));continue
        if op in ('movq','movl','movb','movabsq'):write(a[1],size,read(a[0],size));continue
        if op=='cmovbq':
            if condition('b'):write(a[1],8,read(a[0],8))
            continue
        if op=='imulq':write(a[2],8,read(a[0],8)*read(a[1],8));cf=zf=None;continue
        if op.startswith(('cmp','test')) and size:
            x,y=read(a[0],size),read(a[1],size)
            cf,zf=(y<x,y==x) if op.startswith('cmp') else (False,(x&y)==0)
            continue
        s.require(op in ('shrq','xorl','andq','orb','addq','addb','subq','sbbq','decq'),
                  'assigned squeeze instruction: '+op)
        dst=a[-1];y=read(dst,size);x=1 if op=='decq' else read(a[0],1 if a[0]=='%cl' else size)
        mask=(1<<(size*8))-1
        if op=='shrq':
            shift=x&63
            if not shift:continue
            value=y>>shift;cf=bool(y>>(shift-1)&1)
        elif op=='xorl':value=y^x;cf=False
        elif op=='andq':value=y&x;cf=False
        elif op=='orb':value=y|x;cf=False
        elif op in ('subq','sbbq','decq'):
            borrow=int(cf) if op=='sbbq' else 0;value=y-x-borrow
            if op!='decq':cf=y<x+borrow
        else:value=y+x;cf=value>mask
        write(dst,size,value);zf=value&mask==0
    raise ValueError('bounded squeeze instruction budget exhausted')


def check(code,n,tag,bits,written,start,lane,poison=0xa5,copy_failure=False):
    actual=run(code,n,tag,bits,written,start,lane,poison,copy_failure)
    total=(bits+7)//8;take=min(max(total-written,0),RATES[tag]);end=start+written+take
    invalid=written>total or take>0 and end>1024
    failed=invalid or take>0 and copy_failure
    s.require(actual['failed']==failed,'independent squeeze failure decision')
    want=dict(actual['before']);events=[]
    if not invalid and take:
        dest=STAGING+start+written;source=WORK+1920+200*lane
        events.append(('copy',dest,take,source))
        if not copy_failure:
            for i in range(take):want[dest+i]=want[source+i]
            value=written+take;want.update(enumerate(value.to_bytes(8,'little'),WORK+3552+8*lane))
            if value==total and bits%8:
                mask=(1<<(bits%8))-1;want[dest+take-1]&=mask;events.append(('mask',dest+take-1,mask))
    if not failed:want[WORK+5248+lane]=int(written+take<total)
    for at in [*range(WORK,WORK+5260),*range(STAGING,STAGING+1024)]:
        s.require(actual['memory'][at]==want[at],'exact squeeze storage/counter/ready effect')
    s.require(actual['events']==events,'exact copy and terminal mask call population')
    if not failed:
        expected=dict(r9=lane,r8=112*lane,rdx=WORK+3624+156*lane,r14=INPUT,r12=CONTROL,rbx=WORK,r15=STAGING)
        s.require(all(actual['registers'][k]==v for k,v in expected.items()),'lane continuation pointer/index restoration')
    return actual
