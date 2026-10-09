"""Bounded public-metadata interpreter, not a general x86 or secret-flow proof.

Calls model only reviewed clearing and C byte-copy contracts. Caller-saved
registers are poisoned, not assumed preserved. No secret input page is mapped.
"""
import windows_enclave_sha2_index_machine as index
import windows_enclave_sha3_simd_frame_shape as shape
s=shape.s
REGS=dict(index.REGS)
for full,word in (('rax','ax'),('rbx','bx'),('rcx','cx'),('rdx','dx'),('r8','r8w')):
    REGS['%'+word]=(full,2)
MASK=(1<<64)-1
STACK,WORK,INPUT,EXEC,STAGING,RESULT,TABLE=0x10000,0x20000,0x30000,0x40000,0x50000,0x60000,0x70000


def run(lines,n,lanes,threshold=1,poison=0xa5,max_steps=4096):
    s.require(len(lanes)==4 and 0<=threshold<=MASK,'bounded frame model inputs')
    regs={name:poison*0x0101010101010101 for name,_ in REGS.values()}
    regs.update(rbp=STACK,rbx=WORK,r14=INPUT,rsi=RESULT,rdi=EXEC)
    memory={};writable=set(range(STACK-80,STACK+1000))|set(range(WORK,WORK+5260))
    vectors={};cf=zf=None
    def seed(at,size,value):
        memory.update(enumerate(value.to_bytes(size,'little'),at))
    seed(STACK+1104,8,WORK);seed(STACK+1112,8,STAGING);seed(EXEC+8,8,threshold)
    for i in range(5260):memory[WORK+i]=poison
    for i,lane in enumerate(lanes):
        tag,msg,name,custom,out=lane if lane is not None else (255,0,0,0,0)
        s.require(tag==255 or 0<=tag<8,'frame identity domain')
        for offset,size,value in ((104,1,tag),(16,8,msg),(48,8,name),(80,8,custom),(96,8,out)):
            seed(INPUT+112*i+offset,size,value)
    targets={TABLE+0x100+16*label:f'.B{label}' for label in shape.TARGETS}
    for i,label in enumerate(shape.TARGETS):seed(TABLE+4*i,4,0x100+16*label)
    def address(operand):
        if operand=='.LJTI30_0(%rip)':return TABLE
        return index.address(operand,regs)
    def read(operand,size):
        mask=(1<<(8*size))-1
        if operand.startswith('$'):return int(operand[1:])&mask
        if operand.startswith('%'):
            if operand.startswith(('%ymm','%xmm')):
                key=operand[2:];s.require(key in vectors,'initialized public vector')
                return vectors[key]&mask
            s.require(operand in REGS and REGS[operand][1]==size,'public frame register read width')
            return regs[REGS[operand][0]]&mask
        at=address(operand)
        s.require(all(at+i in memory for i in range(size)),'initialized public frame memory read')
        return int.from_bytes(bytes(memory[at+i] for i in range(size)),'little')
    def put(at,size,value):
        s.require(all(at+i in writable for i in range(size)),'public frame write bounds')
        seed(at,size,value)
    def write(operand,size,value):
        mask=(1<<(8*size))-1;value&=mask
        if operand.startswith('%'):
            if operand.startswith(('%ymm','%xmm')):vectors[operand[2:]]=value;return
            s.require(operand in REGS and REGS[operand][1]==size,'public frame register write width')
            key,_=REGS[operand]
            regs[key]=value|(regs[key]&~mask) if size<4 else value
        else:put(address(operand),size,value)
    def condition(op):
        s.require(cf is not None and zf is not None,'initialized public frame flags')
        return {'e':zf,'ne':not zf,'b':cf,'ae':not cf,'a':not cf and not zf}[op]
    labels={line[:-1]:i for i,line in enumerate(lines) if line.endswith(':')}
    s.require(len(labels)==sum(line.endswith(':') for line in lines),'unique frame labels')
    pc=labels['.B11'];calls=0
    for steps in range(max_steps):
        s.require(0<=pc<len(lines),'public frame control stays in region')
        if pc==labels['.B63']:
            return dict(workspace=bytes(memory[WORK+i] for i in range(5260)),
                output_bytes=regs['r8'],lanes=regs['r12'],steps=steps,calls=calls)
        line=lines[pc];pc+=1
        if line.endswith(':'):continue
        op,_,rest=line.partition(' ');a=rest.split(', ') if rest else []
        if op in ('jmp','je','jne','jb','jae','ja'):
            if op=='jmp' or condition(op[1:]):
                s.require(a[0] in labels,'public framing rejected/escaped')
                pc=labels[a[0]]
            continue
        if op=='jmpq':
            s.require(a==['*%rax'] and regs['rax'] in targets,'bounded identity dispatch')
            pc=labels[targets[regs['rax']]];continue
        if op=='vzeroupper':
            vectors={k:v&((1<<128)-1) for k,v in vectors.items()};continue
        if op=='callq':
            calls+=1;dst=regs['rcx']
            if a==[n['workspace_wipe']]:
                s.require(dst==WORK,'reviewed workspace wipe receiver');size=5260;value=0
            elif a==[shape.life.ZERO]:size=regs['rdx'];value=0
            elif a==['memset']:
                size=regs['r8'];s.require(regs['rdx']==0,'only public zero memset');value=0
            elif a==['memcpy']:
                size=regs['r8'];src=regs['rdx']
                s.require(size<=256 and (src+size<=dst or dst+size<=src),'bounded nonoverlap encoding copy')
                s.require(all(src+i in memory for i in range(size)),'initialized encoding copy')
                value=int.from_bytes(bytes(memory[src+i] for i in range(size)),'little')
            else:raise ValueError('unassigned public frame call')
            s.require(0<=size<=5260,'bounded public frame call extent');put(dst,size,value)
            for key in ('rax','rcx','rdx','r8','r9','r10','r11'):regs[key]=poison*0x0101010101010101
            vectors={}
            if a[0] in ('memcpy','memset'):regs['rax']=dst
            cf=zf=None;continue
        if op=='vmovups':
            size=32 if any(x.startswith('%ymm') for x in a) else 16
            write(a[1],size,read(a[0],size));continue
        size={'q':8,'l':4,'w':2,'b':1}.get(op[-1],0)
        if op in ('leaq','leal'):write(a[1],size,address(a[0]));continue
        if op in ('movzbl','movslq'):
            value=read(a[0],1 if op=='movzbl' else 4)
            if op=='movslq' and value&(1<<31):value-=1<<32
            write(a[1],4 if op=='movzbl' else 8,value);continue
        if op in ('movq','movl','movw','movb','movabsq'):write(a[1],size,read(a[0],size));continue
        if op in ('setae','setne'):write(a[0],1,int(condition(op[3:])));continue
        if op in ('cmovbl','cmovaeq'):
            if condition(op[4:-1]):write(a[1],size,read(a[0],size))
            continue
        if op in ('divl','divq'):
            divisor=read(a[0],size);bits=8*size;mask=(1<<bits)-1
            value=((regs['rdx']&mask)<<bits)|(regs['rax']&mask)
            s.require(divisor>0 and value//divisor<=mask,'nontrapping frame division')
            regs['rax'],regs['rdx']=divmod(value,divisor);cf=zf=None;continue
        if op=='bswapq':write(a[0],8,int.from_bytes(read(a[0],8).to_bytes(8,'little'),'big'));continue
        if op=='notb':write(a[0],1,~read(a[0],1));continue
        if op=='imulq':write(a[2],8,read(a[0],8)*read(a[1],8));cf=zf=None;continue
        if op.startswith(('cmp','test')) and size:
            x,y=read(a[0],size),read(a[1],size)
            cf,zf=(y<x,y==x) if op.startswith('cmp') else (False,(x&y)==0)
            continue
        s.require(op in ('xorl','andq','orq','shrq','shll','incl','addq','subq','adcq'),
                  'assigned public frame instruction: '+op)
        dst=a[-1];before=read(dst,size);mask=(1<<(8*size))-1
        x=1 if op=='incl' else read(a[0],size)
        if op=='xorl':value=before^x;cf=False
        elif op=='andq':value=before&x;cf=False
        elif op=='orq':value=before|x;cf=False
        elif op in ('shrq','shll'):
            s.require(0<x<8*size,'bounded frame shift')
            value=before>>x if op=='shrq' else before<<x
            cf=bool((before>>(x-1 if op=='shrq' else 8*size-x))&1)
        elif op=='subq':value=before-x;cf=before<x
        else:
            carry=int(cf) if op=='adcq' else 0
            value=before+x+carry
            if op!='incl':cf=value>mask
        write(dst,size,value);zf=(value&mask)==0
    raise ValueError('bounded public frame instruction budget exhausted')
