"""Bounded public admission/normal-cleanup replay, not a general x86 emulator."""
import windows_enclave_sha2_index_machine as index
import windows_enclave_sha3_simd_reject_shape as shape
s=shape.s
STACK,WORK,EXEC,AUTH,STAGING,RESULT,CONTROL,VTABLE,CONTEXT,CALLBACK=range(0x10000,0xb0000,0x10000)
MASK=(1<<64)-1
ROUTINE={6,8,9,10,11,12,13}
VALID_ERRORS=(0,1,2,3,4,6,7,8,9,10,11,12,13,14)


def run(code,n,*,kernel=0,mode=2,eligible=(1,1,1,1),total=1024,cancel=False,
        outputs=(256,256,256,256),error=None,poison=0xa5,max_steps=1024):
    s.require(kernel in (None,0,1) and mode in (0,1,2) and len(eligible)==len(outputs)==4,
              'bounded public rejection inputs')
    regs={name:poison*0x0101010101010101 for name,_ in index.REGS.values()}
    regs.update(rbp=STACK,rbx=WORK,rdi=EXEC,r15=STAGING,r8=total)
    memory={};writable=set();events=[];cf=zf=None
    def seed(at,size,value):memory.update(enumerate(value.to_bytes(size,'little'),at))
    def area(at,size):
        writable.update(range(at,at+size))
        for i in range(size):memory[at+i]=poison
    area(STACK+592,104);area(WORK,5260);area(STAGING,1024);area(RESULT,136)
    for at in (800,912,928,936,944):area(STACK+at,8)
    seed(EXEC,8,0 if kernel is None else AUTH);seed(EXEC+16,1,0);seed(EXEC+17,1,mode)
    writable.add(EXEC+16)
    if kernel is not None:
        seed(AUTH+16,1,1);seed(AUTH+17,1,kernel);writable.add(AUTH+16)
    seed(STACK+968,8,0xd0000);seed(STACK+976,8,RESULT)
    seed(STACK+1104,8,WORK);seed(STACK+1120,8,CONTROL)
    seed(CONTROL,8,CONTEXT);seed(CONTROL+8,8,VTABLE);seed(VTABLE+32,8,CALLBACK)
    destinations=[]
    for i,(flag,length) in enumerate(zip(eligible,outputs)):
        seed(WORK+5252+i,1,flag)
        ptr=0 if length is None else 0xe0000+512*i
        seed(STACK+592+16*i,8,ptr);seed(STACK+600+16*i,8,0 if length is None else length)
        if length is not None:
            s.require(0<=length<=256,'bounded modeled output storage');area(ptr,256)
        destinations.append(ptr)
    if error is not None:seed(STACK+944,8,(regs['rax']&~255)|error)
    before=dict(memory)
    def read(operand,size):
        mask=(1<<(8*size))-1
        if operand.startswith('$'):return int(operand[1:])&mask
        if operand.startswith('%'):
            s.require(operand in index.REGS and index.REGS[operand][1]==size,'rejection register read width')
            return regs[index.REGS[operand][0]]&mask
        at=index.address(operand,regs)
        s.require(all(at+i in memory for i in range(size)),'initialized rejection memory read')
        return int.from_bytes(bytes(memory[at+i] for i in range(size)),'little')
    def write(operand,size,value):
        mask=(1<<(8*size))-1;value&=mask
        if operand.startswith('%'):
            s.require(operand in index.REGS and index.REGS[operand][1]==size,'rejection register write width')
            key,_=index.REGS[operand]
            regs[key]=value|(regs[key]&~mask) if size<4 else value
        else:
            at=index.address(operand,regs)
            s.require(all(at+i in writable for i in range(size)),'rejection assigned write range')
            seed(at,size,value)
            if at in (EXEC+16,AUTH+16):events.append(('quarantine',at,value))
    def condition(which):
        s.require(cf is not None and zf is not None,'initialized rejection flags')
        return {'e':zf,'ne':not zf,'b':cf,'be':cf or zf,'ae':not cf}[which]
    labels={line[:-1]:i for i,line in enumerate(code) if line.endswith(':')}
    s.require(len(labels)==sum(l.endswith(':') for l in code),'unique rejection labels')
    pc=labels['.B72'] if error is not None else 0
    for steps in range(max_steps):
        s.require(0<=pc<len(code),'bounded rejection control flow')
        if pc in (labels['.B85'],labels['.B86']):
            return dict(accepted=pc==labels['.B86'],memory=memory,before=before,
                events=events,destinations=destinations,steps=steps)
        line=code[pc];pc+=1
        if line.endswith(':') or line in ('vzeroupper','nop'):continue
        op,_,rest=line.partition(' ');args=rest.split(', ')
        if op in ('jmp','je','jne','jb','jbe','jae'):
            if op=='jmp' or condition(op[1:]):
                s.require(args[0] in labels,'assigned rejection branch');pc=labels[args[0]]
            continue
        if op=='callq':
            if args==['*%rax']:
                s.require(regs['rax']==CALLBACK and regs['rcx']==CONTEXT,'control context and exact slot32 callback')
                events.append(('cancel',CONTEXT,CALLBACK))
            else:
                at=regs['rcx'];size=5260 if args==[n['workspace_wipe']] else regs['rdx']
                s.require(args in ([n['workspace_wipe']],[shape.life.ZERO]),'assigned clearing helper')
                s.require(args!=[n['workspace_wipe']] or at==WORK,'workspace receiver')
                allowed=[(WORK,5260),(STAGING,1024),(STACK+688,4),(STACK+656,32)]
                allowed += [(p,length) for p,length in zip(destinations,outputs) if p and length]
                s.require((at,size) in allowed,'exact live wipe extent')
                for i in range(size):memory[at+i]=0
                events.append(('wipe',at,size))
            for name in ('rax','rcx','rdx','r8','r9','r10','r11'):regs[name]=poison*0x0101010101010101
            if args==['*%rax']:regs['rax']=(regs['rax']&~255)|int(cancel)
            cf=zf=None;continue
        if op in ('sete','setb'):write(args[0],1,int(condition(op[3:])));continue
        size={'q':8,'l':4,'b':1}.get(op[-1],0)
        if op in ('leaq','leal'):write(args[1],size,index.address(args[0],regs));continue
        if op=='movzbl':write(args[1],4,read(args[0],1));continue
        if op in ('movq','movl','movb','movabsq'):write(args[1],size,read(args[0],size));continue
        if op.startswith(('cmp','test')) and size:
            a,b=read(args[0],size),read(args[1],size)
            cf,zf=(b<a,b==a) if op.startswith('cmp') else (False,(a&b)==0)
            continue
        s.require(op in ('xorl','addl','addq','shrb','shlb','shrq'),'assigned rejection instruction: '+op)
        a=read(args[0],1 if args[0]=='%cl' else size);b=read(args[1],size);mask=(1<<(size*8))-1
        if op=='xorl':value=b^a;cf=False
        elif op.startswith('add'):value=b+a;cf=value>mask
        else:
            shift=a&(63 if size==8 else 31)
            if not shift:continue
            value=b<<shift if op=='shlb' else b>>shift
            cf=False  # Shift carry is not consumed before a subsequent test.
        write(args[1],size,value);zf=value&mask==0
    raise ValueError('bounded rejection instruction budget exhausted')


def check(code,n,**case):
    got=run(code,n,**case);m,b=got['memory'],got['before']
    kernel=case.get('kernel',0);mode=case.get('mode',2);flags=case.get('eligible',(1,1,1,1))
    err=case.get('error');expected_callback=False
    if err is None:
        if case.get('total',1024)>1024:err=9
        elif mode==2 and (kernel is None or sum(x==1 for x in flags)<(4 if kernel==0 else 2)):err=10
        else:
            expected_callback=True
            if case.get('cancel',False):err=13
    s.require(got['accepted']==(err is None),'independent eligibility/cancellation decision')
    s.require(sum(e[0]=='cancel' for e in got['events'])==int(expected_callback),'first cancellation poll ordering')
    outputs=case.get('outputs',(256,256,256,256))
    if err is None:
        s.require(not any(e[0] in ('wipe','quarantine') for e in got['events']),'no retirement before accepted inner entry')
        for at in [*range(WORK,WORK+5260),*range(STAGING,STAGING+1024),*range(RESULT,RESULT+136)]:
            s.require(m[at]==b[at],'admitted path preserves data and result')
    else:
        quarantine=err not in ROUTINE
        want=[('wipe',WORK,5260),('wipe',STAGING,1024)]
        if quarantine:
            want+=[('quarantine',EXEC+16,1)]
            if kernel is not None:want+=[('quarantine',AUTH+16,0)]
        want += [('wipe',ptr,length) for ptr,length in zip(got['destinations'],outputs) if ptr and length]
        want += [('wipe',STACK+688,4),('wipe',STACK+656,32)]
        s.require([e for e in got['events'] if e[0]!='cancel']==want,'complete ordered rejection retirement')
        for at in range(WORK,WORK+5260):s.require(m[at]==0,'workspace retirement')
        for at in range(STAGING,STAGING+1024):s.require(m[at]==0,'staging retirement')
        for i in range(136):s.require(m[RESULT+i]==(err if i==0 else 255 if i==129 else b[RESULT+i]),'error-only result publication')
        s.require(m[EXEC+16]==int(quarantine),'executor quarantine classification')
        if kernel is not None:s.require(m[AUTH+16]==int(not quarantine),'authority quarantine classification')
    for ptr,length in zip(got['destinations'],outputs):
        if ptr:
            for i in range(256):s.require(m[ptr+i]==(0 if err is not None and i<length else b[ptr+i]),'bounded destination retirement')
    return got
