"""Bounded indirect-store footprints, conditional on named live caller objects.

This is not an alias/lifetime proof: distinct symbolic objects must still be
placed and kept disjoint by the enclosing caller. Calls are not discharged here.
"""
import re
from dataclasses import dataclass
import windows_enclave_kmac_shapes as s


@dataclass(frozen=True)
class Value:
    object: str | None
    low: int
    high: int


def add(a,b):
    s.require(not (a.object and b.object),'no pointer plus pointer')
    low,high=a.low+b.low,a.high+b.high
    s.require(0<=low<=high<(1<<64),'nonwrapping effect address')
    return Value(a.object or b.object,low,high)


def register(name):
    small={'ax':('rax',16),'dx':('rdx',16),'cx':('rcx',16),
           'al':('rax',8),'dl':('rdx',8),'cl':('rcx',8),'bl':('rbx',8)}
    if name in small:return small[name]
    aliases={'eax':'rax','ecx':'rcx','edx':'rdx','esi':'rsi','edi':'rdi','ebx':'rbx'}
    if name in aliases:return aliases[name],32
    if re.fullmatch(r'r\d+d',name):return name[:-1],32
    s.require(name in ('rax','rcx','rdx','rsi','rdi','rbx','rbp','rsp') or
              re.fullmatch(r'r(?:[89]|1[0-5])',name),'assigned effect register')
    return name,64


def address(text,regs):
    match=re.fullmatch(r'(\d*)\((?:%(\w+))?(?:,%(\w+)(?:,([1248]))?)?\)',text)
    s.require(match is not None,'assigned effect address form')
    s.require(match[2] or match[3],'effect address has a base or index')
    result=Value(None,int(match[1] or 0),int(match[1] or 0))
    if match[2]:
        base,width=register(match[2]);s.require(width==64,'full-width address base')
        value=regs.get(base);s.require(value is not None,'known effect address base')
        result=add(result,value)
    if match[3]:
        index,width=register(match[3]);value=regs.get(index)
        s.require(width==64 and value is not None and value.object is None,'bounded integer index')
        scale=int(match[4] or 1)
        result=add(result,Value(None,value.low*scale,value.high*scale))
    return result


def evaluate(lines,registers,memory,copy,snapshots=None,precise=False):
    """Interpret address-producing operations on one successful fallthrough path.

Comparisons/conditional exits don't narrow intervals. The parent region review
    owns their control flow. Only explicitly assigned ABIs may be called;
    volatile registers are forgotten afterward. Optional snapshots capture
    argument values, not callee effects. Unassigned loads lose provenance.
"""
    regs=dict(registers);stores=[]
    for line in lines:
        if line.endswith(':') or line=='vzeroupper':continue
        op,_,rest=line.partition(' ');args=rest.split(', ')
        if op in ('cmpb','cmpq','testb','testq','jne','je'):continue
        if op=='callq':
            allowed={copy} if isinstance(copy,str) else set(copy)
            s.require(rest in allowed,'only assigned reviewed ABI in address slice')
            if snapshots is not None:snapshots.append((rest,dict(regs)))
            for reg in ('rax','rcx','rdx','r8','r9','r10','r11'):regs.pop(reg,None)
            continue
        if op in ('incq','decq','bswapq'):
            reg,width=register(rest[1:]);s.require(width==64,'full-width scalar operation')
            if precise and op in ('incq','decq'):
                old=regs.get(reg);s.require(old is not None,'known precise increment/decrement')
                delta=1 if op=='incq' else -1
                regs[reg]=add(old,Value(None,delta,delta));continue
            # These values are counter/length payloads, never address bases.
            s.require(regs.get(reg) is None or regs[reg].object is None,'no pointer arithmetic hidden in payload')
            regs.pop(reg,None);continue
        s.require(op in ('movq','movl','movzbl','movzwl','movb','leaq','andl','andq','addq','shlq','xorl'),
                  'assigned indirect effect instruction: '+op)
        src,dst=args
        if '(' in dst:
            s.require(op in ('movq','movl','movb'),'assigned indirect store width')
            target=address(dst,regs);s.require(target.object is not None,'store has named object')
            width={'movq':8,'movl':4,'movb':1}[op]
            stores.append(dict(instruction=line,object=target.object,
                               span=[target.low,target.high+width]))
            continue
        reg,width=register(dst[1:])
        if op=='xorl':
            s.require(src==dst and width==32,'assigned zero idiom only')
            regs[reg]=Value(None,0,0);continue
        if op=='leaq':value=address(src,regs)
        elif src.startswith('$'):value=Value(None,int(src[1:]),int(src[1:]))
        elif src.startswith('%'):
            source,source_width=register(src[1:]);value=regs.get(source)
            extension={'movzbl':8,'movzwl':16}.get(op)
            s.require((extension==source_width and width==32) if extension else source_width==width,
                      'matching move register widths')
            if extension and value is not None:
                s.require(value.object is None and value.low==value.high,'concrete integer extension')
                low=value.low & ((1<<extension)-1);value=Value(None,low,low)
        else:
            try:location=address(src,regs)
            except ValueError:location=None
            value=memory.get((location.object,location.low)) if location and location.low==location.high else None
        if op in ('movzbl','movzwl') and value is not None:
            s.require(value.object is None and value.low==value.high,'concrete zero-extension value')
            mask=255 if op=='movzbl' else 65535
            low=value.low & mask;value=Value(None,low,low)
        if op in ('andl','andq'):
            old=regs.get(reg)
            s.require(old is not None and old.object is None and src.startswith('$'),'integer mask provenance')
            mask=int(src[1:]) & ((1<<width)-1)
            value=Value(None,old.low & mask,old.low & mask) if precise and old.low==old.high else Value(None,0,mask)
        elif op=='shlq':
            old=regs.get(reg)
            s.require(precise and old is not None and old.object is None and src.startswith('$')
                      and 0<=int(src[1:])<64,'assigned precise integer shift')
            shift=int(src[1:]);value=add(Value(None,0,0),Value(None,old.low<<shift,old.high<<shift))
        elif op=='addq':
            old=regs.get(reg)
            s.require(old is not None and value is not None,'known addition operands')
            value=add(old,value)
        if value is not None and width==32:
            s.require(value.object is None and 0<=value.high<(1<<32),'no pointer truncation')
        if width<32 and value is not None:
            old=regs.get(reg)
            s.require(value.object is None and value.low==value.high,'integer partial write')
            if old is None:value=None
            else:
                s.require(old.object is None and old.low==old.high,'known upper bits for partial write')
                mask=(1<<width)-1;low=(old.low & ~mask)|(value.low & mask)
                value=Value(None,low,low)
        if value is None:regs.pop(reg,None)
        else:regs[reg]=value
    return stores


def slice_to(lines,start,end):
    s.require(lines.count(start)==lines.count(end)==1,'unique effect slice endpoints')
    a,b=lines.index(start),lines.index(end)
    s.require(a<=b,'ordered effect slice')
    return lines[a:b+1]


def inspect(lines,lane,inventory,copy):
    narrow=lane=='simd256';s.require(lane in ('simd256','simd512'),'assigned store route')
    number=Value(None,0,(1<<64)-1);frame=Value('frame',0,0)
    workspace=Value('workspace',0,0);control=Value('control',0,0)
    if narrow:
        cases=[('movq 168(%rbx), %rdx','movb $-128, (%r15)',
                {'rbx':frame},{('frame',168):number,('frame',112):Value('input',0,0)},
                [('frame',11688,11752)]),
               ('movq 88(%rbx), %rax','movb $0, 16(%rax)',
                {'rbx':frame},{('frame',88):Value('authority',0,0)},[('authority',16,17)])]
        # The authority reload occurs elsewhere too; restrict to the named block.
        health=lines[lines.index('.B188:'):]
    else:
        cases=[('movq %r13, %r8','movb $-128, (%r10)',
                {'rbp':frame,'r13':number,'rax':Value('input',0,0)},
                {('frame',928):Value('workspace',5476,5476)},[('workspace',5476,5604)]),
               ('movq 1176(%rbp), %rdx','movq %rcx, 24(%rdx)',
                {'rbp':frame},{('frame',1176):control,('frame',1168):workspace},
                [('control',16,24),('control',24,32)]),
               ('bswapq %r12','movq $0, 5588(%rdi)',
                {'rdi':workspace},{},[('workspace',5596,5604),('workspace',5588,5596)])]
    results=[]
    for i,(start,end,regs,memory,expected) in enumerate(cases):
        source=health if narrow and i==1 else lines
        if not narrow and i==0:
            source=lines[lines.index('.B189:'):lines.index('.B192:')]
        if not narrow and i==1:
            # Start after cancellation returned, not another reload of control.
            source=lines[lines.index('.B193:'):lines.index('.B201:')]
        code=slice_to(source,start,end)
        effects=evaluate(code,regs,memory,copy)
        s.require([(v['object'],*v['span']) for v in effects]==expected,'exact bounded indirect write footprints')
        results.extend(effects)
    s.require([v['instruction'] for v in results]==[v['instruction'] for v in inventory],
              'all and only inventoried indirect stores have effects')
    return dict(stores=results,store_count=len(results),
        footprints_conditional_on_named_live_objects=True,
        caller_object_placement_and_aliasing_pending=True,
        intervening_call_effects_pending=True,whole_frame_qualified=False)
