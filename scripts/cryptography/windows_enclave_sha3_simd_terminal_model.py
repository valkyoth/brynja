"""Independent terminal metadata/retirement oracles with synthetic buffers."""
import windows_enclave_sha3_simd_terminal_machine as m
s,MASK=m.s,m.MASK
ROUTINE={6,8,9,10,11,12,13}


def prepare(tags=(0,1,6,7),bits=(224,256,513,9),calls=0x123456789abcdef0,
            blocks=0xfedcba9876543210,scalar=13,accelerated=15,kernel=0,
            authority=True,healthy=True,quarantined=False,poison=0xa5):
    s.require(len(tags)==len(bits)==4 and all(v in (*range(8),255) for v in tags) and
        all(type(v) is int and 0<=v<=MASK for v in (*bits,calls,blocks,scalar,accelerated)),
        'typed terminal metadata')
    mem={};writable=set()
    def seed(at,size,value):mem.update(enumerate(value.to_bytes(size,'little'),at))
    def area(at,size):
        writable.update(range(at,at+size));mem.update((at+i,(poison+i*29)&255) for i in range(size))
    for at,size in ((m.WORK,5260),(m.STAGING,1024),(m.RESULT,136),(m.STACK+592,104),
        (m.STACK+944,8),(m.STACK+976,8),(m.STACK+4096-16,16),(m.STACK+472,1)):area(at,size)
    for i,(tag,width) in enumerate(zip(tags,bits)):
        seed(m.INPUT+104+112*i,1,tag);seed(m.INPUT+96+112*i,8,width)
        ptr=0 if tag==255 else 0xe0000+512*i
        seed(m.STACK+592+16*i,8,ptr);seed(m.STACK+600+16*i,8,(width+7)//8)
        if ptr:area(ptr,256)
    seed(m.STACK+656,32,0);seed(m.STACK+688,4,0)
    for offset,value in {744:blocks,808:scalar,856:accelerated,928:m.CONTEXT,912:m.CALLBACK,
        968:m.INPUT,976:m.RESULT,1104:m.WORK,944:13}.items():seed(m.STACK+offset,8,value)
    seed(m.STACK+991,1,kernel);seed(m.EXEC,8,m.AUTH if authority else 0);seed(m.EXEC+16,1,int(quarantined))
    seed(m.AUTH+8,8,m.REVALIDATE);seed(m.AUTH+16,1,int(healthy));seed(m.AUTH+17,1,0)
    writable.update((m.EXEC+16,m.AUTH+16))
    regs={name:poison*0x0101010101010101 for name,_ in m.REGS.values()}
    regs.update(rbp=m.STACK,rbx=m.WORK,rsi=m.RESULT,rdi=m.EXEC,r12=m.CONTROL,
        r13=calls,r14=m.INPUT,r15=m.STAGING)
    return mem,writable,regs


def report(code,n,**case):
    mem,writable,regs=prepare(**case);before=dict(mem)
    regs.update(r12=m.STAGING,rsi=regs['r13']>>8)
    result=m.run(code,n,mem,writable,regs,'.B270',{'.B85','.B79'})
    kernel=case.get('kernel',0);want=[('wipe',m.WORK,5260),('wipe',m.STAGING,1024)]
    s.require(result['events']==want and result['exit']==('.B79' if kernel==255 else '.B85'),
        'report clearing precedes metadata publication')
    def copy(dst,src,size):
        for i in range(size):before[dst+i]=mem[src+i]
    def seed(at,size,value):before.update(enumerate(value.to_bytes(size,'little'),at))
    seed(m.WORK,5260,0);seed(m.STAGING,1024,0)
    if kernel!=255:
        tags=case.get('tags',(0,1,6,7));bits=case.get('bits',(224,256,513,9))
        for i,(tag,width) in enumerate(zip(tags,bits)):
            if tag!=255:
                seed(m.STACK+688+i,1,tag+1);seed(m.STACK+656+8*i,8,width)
        copy(m.RESULT,m.STACK+592,64)
        for i,(tag,width) in enumerate(zip(tags,bits)):
            seed(m.RESULT+64+8*i,8,0 if tag==255 else width);seed(m.RESULT+96+i,1,0 if tag==255 else tag+1)
        # The emitted qword copy also transfers four padding bytes. They are
        # not meaningful report fields and are NOT claimed erased/initialized.
        copy(m.RESULT+100,m.STACK+692,4)
        seed(m.RESULT+104,8,case.get('calls',0x123456789abcdef0))
        seed(m.RESULT+112,8,case.get('blocks',0xfedcba9876543210));seed(m.RESULT+120,8,case.get('scalar',13))
        seed(m.RESULT+128,1,case.get('accelerated',15)&255);seed(m.RESULT+129,1,kernel)
    s.require(result['memory']==before,'byte-exact terminal report including unchanged padding and caller storage')
    if kernel==255:s.require(result['registers']['rsi']==m.RESULT,'invalid report carries result pointer to common error return')
    return result


def preflight(code,n,**case):
    mem,writable,regs=prepare(**case);regs.update(r12=m.STAGING,r14=m.EXEC)
    result=m.run(code,n,mem,writable,regs,'.B230',{'.B72','.B8','.B223','fallthrough'})
    tags=case.get('tags',(0,1,6,7));bits=case.get('bits',(224,256,513,9));kernel=case.get('kernel',0)
    total=sum((width+7)//8 for tag,width in zip(tags,bits) if tag!=255)
    edge='.B8' if kernel==255 else '.B72' if total>1024 else 'fallthrough'
    s.require(result['exit']==edge and result['events']==([] if kernel==255 else [('validate',)]),
        'independent final identity and aggregate size admission')
    for at,value in mem.items():
        if m.STACK+944<=at<m.STACK+952 or at==m.STACK+472:continue
        s.require(result['memory'][at]==value,'final preflight has no data/metadata/output effects')
    if edge=='fallthrough':
        s.require(result['registers']['rsi']==case.get('calls',0x123456789abcdef0)>>8 and
            result['registers']['rax']==total and result['memory'][m.STACK+472]==0,
            'high vector counter bits retained and commit guard assigned')
    return result


def error_result(result,initial,err,authority,initial_events=()):
    want=list(initial_events)+[('wipe',m.WORK,5260),('wipe',m.STAGING,1024)]
    if err not in ROUTINE:
        want.append(('quarantine',m.EXEC+16,1))
        if authority:want.append(('quarantine',m.AUTH+16,0))
    for i in range(4):
        at=m.STACK+592+16*i
        ptr=int.from_bytes(bytes(initial[at+j] for j in range(8)),'little')
        length=int.from_bytes(bytes(initial[at+8+j] for j in range(8)),'little')
        if ptr and length:want.append(('wipe',ptr,length))
    want += [('wipe',m.STACK+688,4),('wipe',m.STACK+656,32)]
    s.require(result['exit']=='.B85' and result['events']==want,'bridge composes exact ordered rejection/quarantine/clearing')
    for event in want:
        if event[0]=='wipe':
            _,at,size=event
            s.require(all(result['memory'][at+i]==0 for i in range(size)),'complete terminal rejection wipe')
    for i in range(136):
        s.require(result['memory'][m.RESULT+i]==(err if i==0 else 255 if i==129 else initial[m.RESULT+i]),
            'rejection publishes only error and discriminant')


def bridge(code,n,entry,err=14,authority=True,poison=0xa5):
    mem,writable,regs=prepare(authority=authority,poison=poison)
    regs.update(rax=m.AUTH,rsi=m.RESULT,r14=0)
    if entry=='.B210':regs['r12']=m.WORK+3584
    if entry=='.B223':regs.update(rax=err,r14=m.EXEC,r12=m.STAGING)
    if entry=='.B226':regs['rax']=err
    if entry in ('.B227','.B228'):regs['rsi']=err
    if entry=='.B209':regs['r13']=err
    fixed={'.B215':2,'.B216':13,'.B217':12,'.B218':4,'.B224':13,'.B225':12}
    expected=fixed.get(entry,err)
    s.require(entry!='.B215' or authority,'revocation predecessor requires live authority')
    result=m.run(code,n,mem,writable,regs,entry,{'.B85'})
    initial=[('quarantine',m.AUTH+16,0)] if entry=='.B215' else []
    error_result(result,mem,expected,authority,initial)
    return result


def final_health(code,n,*,authority=True,healthy=True,quarantined=False,cancel=False,revalidate=True,poison=0xa5):
    mem,writable,regs=prepare(authority=authority,healthy=healthy,quarantined=quarantined,poison=poison)
    result=m.run(code,n,mem,writable,regs,'.B219',{'.B85','.B230'},cancel=cancel,revalidate=revalidate,poison=poison)
    events=[('poll',)];err=None
    if cancel:err=13
    else:
        events.append(('check',))
        if quarantined:err=4
        elif authority:
            if healthy:events.append(('revalidate',))
            if not healthy or not revalidate:events.append(('quarantine',m.AUTH+16,0));err=2
    if err is not None:error_result(result,mem,err,authority,events)
    else:
        s.require(result['exit']=='.B230' and result['events']==events,'final health precedes output admission')
        for at,value in mem.items():
            if m.STACK+4096-16<=at<m.STACK+4096:continue
            s.require(result['memory'][at]==value,'healthy terminal path preserves caller data')
        s.require(result['registers']['r12']==m.STAGING and result['registers']['r14']==m.EXEC,
            'final health retains staging/executor for all later error exits')
    return result
