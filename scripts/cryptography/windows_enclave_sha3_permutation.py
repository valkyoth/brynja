"""Saved scalar Keccak schedule/erasure and buffer destructor, not an OS claim."""
import windows_enclave_sha3_setup as setup

u,t,ops,life,shared = setup.u,setup.t,setup.ops,setup.life,setup.shared
require,digest = setup.require,setup.digest
PERMUTE,ZERO = u.PERMUTE,u.ZERO
DROP = '_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtCsgzEJPm6isiJ_18sha3_stream_worker7BuffersEBD_'
CONSTANT = 'anon.de85d9caac8b76a58a10288df6d71ce6.0'
PINS = {
    PERMUTE:(795,'516dd389cd63be6f44b15c2af0f34bcdb14fda6be2b61ead22625b9306f79c49',24),
    DROP:(43,'2595fc450edc826184fcfbbf0ae88689d386b3ebad37995b3fe88a2571fbc6ab',40),
}


def body_check(name,code,refs):
    size,sha,_ = PINS[name]
    require(len(code)==size and digest(code)==sha,'complete reviewed scalar leaf/destructor bytes')
    expected = [(12,CONSTANT)] if name==PERMUTE else [(21,ZERO),(39,ZERO)]
    require(refs==[dict(offset=at,symbol=s,trailing=0,addend=0) for at,s in expected],
            'complete scalar leaf/destructor relocations')


def round_constants():
    """Keccak's x^8+x^6+x^5+x^4+1 LFSR; not copied from the Rust table."""
    lfsr=1;result=[]
    for _ in range(24):
        value=0
        for j in range(7):
            value ^= (lfsr & 1) << ((1<<j)-1)
            lfsr=((lfsr<<1) ^ (0x71 if lfsr & 128 else 0)) & 255
        result.append(value)
    return b''.join(v.to_bytes(8,'little') for v in result)


def rho_pi():
    """Generate offsets by the Keccak coordinate recurrence, not source arrays."""
    rotations=[0]*25;x,y=1,0
    for n in range(24):
        rotations[x+5*y]=((n+1)*(n+2)//2)%64
        x,y=y,(2*x+3*y)%5
    return [(i,rotations[i],(i//5)+5*((2*(i%5)+3*(i//5))%5)) for i in range(25)]


def mem(offset,base,index=''):
    return (str(offset) if offset else '')+'('+base+(','+index if index else '')+')'


def opaque_shape():
    """Complete inspected scalar schedule, including all loop limits and wipes."""
    lines=['xorl %r10d, %r10d','.Ltmp4:','xorl %r11d, %r11d','.Ltmp5:']
    lines += ['movq (%rdi,%r11), %rax']
    lines += [f'xorq {y*40}(%rdi,%r11), %rax' for y in range(1,5)]
    lines += ['movq %rax, (%rsi,%r11)','addl $8, %r11d','cmpl $40, %r11d','jne .Ltmp5']
    for x in range(5):
        lines += [f'movq {mem(8*((x-1)%5),"%rsi")}, %rax',
                  f'movq {mem(8*((x+1)%5),"%rsi")}, %rcx','rolq %rcx','xorq %rcx, %rax',
                  f'movq %rax, {mem(8*x,"%r8")}']
    lines += ['xorl %r11d, %r11d','.Ltmp6:','movq (%r8,%r11), %rax']
    lines += [f'xorq %rax, {mem(40*y,"%rdi","%r11")}' for y in range(5)]
    lines += ['addl $8, %r11d','cmpl $40, %r11d','jne .Ltmp6']
    for source,rotation,destination in rho_pi():
        lines += [f'movq {mem(8*source,"%rdi")}, %rax']
        if rotation: lines += ['rolq '+('' if rotation==1 else f'${rotation}, ')+'%rax']
        lines += [f'movq %rax, {mem(8*destination,"%r9")}']
    lines += ['xorl %r11d, %r11d','.Ltmp7:']
    for x in range(5):
        lines += [f'movq {mem(8*x,"%r9","%r11")}, %rax',
                  f'movq {mem(8*((x+1)%5),"%r9","%r11")}, %rcx',
                  f'movq {mem(8*((x+2)%5),"%r9","%r11")}, %rdx',
                  'notq %rcx','andq %rdx, %rcx','xorq %rcx, %rax',
                  f'movq %rax, {mem(8*x,"%rdi","%r11")}']
    lines += ['addl $40, %r11d','cmpl $200, %r11d','jne .Ltmp7',
              'movq (%rbx,%r10), %rax','xorq %rax, (%rdi)','addl $8, %r10d',
              'cmpl $192, %r10d','jne .Ltmp4','xorl %r11d, %r11d','.Ltmp8:',
              'movq $0, (%rsi,%r11)','movq $0, (%r8,%r11)','addl $8, %r11d',
              'cmpl $40, %r11d','jne .Ltmp8','xorl %r11d, %r11d','.Ltmp9:',
              'movq $0, (%r9,%r11)','addl $8, %r11d','cmpl $200, %r11d','jne .Ltmp9']
    lines += [f'xorl %{r}, %{r}' for r in ('eax','ecx','edx','r10d','r11d')]
    return lines


def normalized(body):
    return [' '.join(line.split()) for line in body.splitlines()
            if line.strip() and not line.lstrip().startswith('#')]


def permutation_assembly(body):
    require(body.count('#APP')==body.count('#NO_APP')==1,'one opaque scalar block')
    before,opaque=body.split('#APP');opaque,after=opaque.split('#NO_APP')
    require(normalized(opaque)==opaque_shape(),'complete round schedule and erasure order')
    for marker in ('BEGIN','ERASE','END'):
        require(opaque.count('BRYNJA_SCALAR_'+marker)==1,'unique scalar boundary marker')
    require(not normalized(opaque.split('# BRYNJA_SCALAR_BEGIN')[0]) and
            not normalized(opaque.split('# BRYNJA_SCALAR_END')[1]),'markers enclose the complete opaque work')
    erase=opaque.split('BRYNJA_SCALAR_ERASE')[1].split('# BRYNJA_SCALAR_END')[0]
    require(normalized(erase)==opaque_shape()[-5:],'erasure marker brackets all used working registers')
    require(normalized(before)[3:]==[
        'pushq %rsi','.seh_pushreg %rsi','pushq %rdi','.seh_pushreg %rdi',
        'pushq %rbx','.seh_pushreg %rbx','.seh_endprologue','movq %rdx, %rsi',
        'movq %rcx, %rdi','leaq '+CONSTANT+'(%rip), %rbx'],
        'pointer saves precede secret work; specialized constant input')
    require(normalized(after)[:-1]==['.seh_startepilogue','popq %rbx','popq %rdi',
        'popq %rsi','.seh_endepilogue','retq'],'only pointer register restores after opaque work')


def destructor_assembly(body):
    lines=normalized(body)
    require(lines[3:-1]==['pushq %rsi','.seh_pushreg %rsi','subq $32, %rsp',
        '.seh_stackalloc 32','.seh_endprologue','movq %rcx, %rsi','addq $1024, %rcx',
        'movl $96, %edx','callq '+ZERO,'movl $1024, %edx','movq %rsi, %rcx',
        '.seh_startepilogue','addq $32, %rsp','popq %rsi','.seh_endepilogue','jmp '+ZERO],
        'complete header then payload cleanup, restored-frame tail call')


def buffer_exits(body):
    """Finite normal-CFG check after Buffers construction, not OS unwind proof."""
    lines=normalized(body);labels={line[:-1]:i for i,line in enumerate(lines) if line.endswith(':')}
    require('.LBB0_11' in labels,'actual buffer-construction block')
    pending=[(labels['.LBB0_11'],False)];seen=set();returns=set();drops=set()
    while pending:
        at,cleared=pending.pop()
        if (at,cleared) in seen: continue
        seen.add((at,cleared));require(at<len(lines),'no fallthrough outside worker')
        line=lines[at]
        if line=='callq '+DROP: cleared=True;drops.add(at)
        if line=='retq':
            require(cleared,'every normal post-construction return passes buffer destructor')
            returns.add(at);continue
        if line.startswith('j'):
            opcode,target=line.split(maxsplit=1)
            require(target in labels,'no unassigned indirect/escaping worker branch')
            pending.append((labels[target],cleared))
            if opcode in ('jmp','jmpq'): continue
        require(not line.startswith('callq *'),'no unassigned indirect worker call')
        pending.append((at+1,cleared))
    require(len(returns)==1 and len(drops)==2,'both normal and rejection destructor paths')
    return dict(normal_return_sites=1,destructor_call_sites=2,post_construction_paths_checked=True)


def constants(data,image,record):
    rows,symbols=ops.obj.tables(data)
    found=[s for s in symbols.values() if s['name']==CONSTANT]
    require(len(found)==1 and found[0]['value']==0 and 1<=found[0]['section']<=len(rows),
            'unique constant section start')
    row=rows[found[0]['section']-1];expected=round_constants()
    require(row['flags'] & 0xe0000000==0x40000000 and row['nrelocs']==0,'immutable relocation-free table')
    require(row['code']==expected,'all 24 object round constants agree with independent LFSR')
    address=record['reference_targets'][CONSTANT]
    require(ops.readonly(image,address,192)==expected,'actual immutable linked round constants')
    return dict(rva=address,bytes=192,sha256=digest(expected))


def inspect(data,image,assembly):
    require(digest(assembly)==life.ASM_HASH,'same saved scalar assembler')
    text=assembly.decode();records={}
    for name in PINS:
        code,refs=shared.caller.function(data,name);body_check(name,code,refs)
        label='\n'+name+':\n';require(text.count(label)==1,'unique assembler function')
        start=text.index(label);body=text[start:text.index('.seh_endproc',start)]
        (permutation_assembly if name==PERMUTE else destructor_assembly)(body)
        records[name]=shared.caller.bind(data,image,name)
    ops.frames(records,{n:dict(stack_bytes=p[2],saved_registers=[]) for n,p in PINS.items()})
    start=text.index('\nRetainedWork:\n')
    buffer_exits(text[start:text.index('.seh_endproc',start)])
    return records,constants(data,image,records[PERMUTE])
