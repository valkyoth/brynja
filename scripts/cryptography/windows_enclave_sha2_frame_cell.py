"""Fixed frame-cell effects across the saved first-output-pointer lifetime.

This checks direct byte overlaps and direct address exposure, including RSP/RBP
aliases. Calls and non-frame stores are inventoried, not assumed harmless.
Transitive indirect effects and original allocation lifetimes remain separate.
"""
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_simd_finish as finish
import windows_enclave_sha2_simd_commit as commit
import windows_enclave_sha2_store_effects as effects

READ_ONLY={'cmpb','cmpw','cmpl','cmpq','testb','testw','testl','testq',
           'je','jne','ja','jae','jb','jbe','jmp','jmpq','nop','ud2','vzeroupper'}
WRITES={'movb':1,'movw':2,'movl':4,'movq':8,'movzbl':4,'movzwl':4,'movslq':8,
        'addq':8,'subq':8,'andq':8,'andl':4,'andb':1,'orb':1,'xorl':4,'subb':1,
        'incq':8,'decq':8,'decb':1,'shlq':8,'shrq':8,'shrl':4,'shlb':1,'shrb':1,
        'bswapq':8,'sbbw':2,'cmovnel':4}
BASE_ALIASES={'rbx':('rbx','ebx','bx','bl'),'rbp':('rbp','ebp','bp','bpl'),
              'rsp':('rsp','esp','sp','spl')}


def frame_span(operand,bases,width):
    used=set(re.findall(r'%(\w+)',operand)) & bases.keys()
    if not used:return None
    match=re.fullmatch(r'(-?\d*)\(%(\w+)\)',operand)
    s.require(match is not None and match[2] in bases,'direct assigned frame address only')
    low,high=bases[match[2]];offset=int(match[1] or 0)
    s.require(-(1<<31)<=offset<(1<<31),'representable x86 frame displacement')
    return offset+low,offset+high+width


def overlaps(span,cell):return span[0]<cell[1] and cell[0]<span[1]


def inspect_region(lines,bases,cell,initializer,clear_label):
    direct=[];indirect=[];calls=[];addresses=[];writes=[]
    aliases={'%'+alias for base in bases for alias in BASE_ALIASES[base]}
    for i,line in enumerate(lines):
        if line.endswith(':'):continue
        if line.startswith(('.p2align ','.seh_')):continue
        op,_,rest=line.partition(' ');args=rest.split(', ') if rest else []
        if op=='callq':calls.append(dict(line=i,target=rest));continue
        if op in READ_ONLY:continue
        s.require(op in WRITES or op in ('vmovaps','vmovups','leaq'), 'assigned frame-cell instruction: '+op)
        destination=args[-1]
        s.require(destination not in aliases,'frame bases unchanged during cell lifetime')
        s.require(not any(arg in aliases for arg in args[:-1]),
                  'no direct frame-base copy escapes this region')
        if op=='leaq':
            span=frame_span(args[0],bases,1)
            if span:
                s.require(not overlaps(span,cell),'saved cell address not directly exposed')
                addresses.append(dict(line=i,range=list(span)))
            continue
        if '(' not in destination:continue
        if op.startswith('vmov'):
            s.require(args[0].startswith(('%xmm','%ymm')),'known vector store width')
            width=16 if args[0].startswith('%xmm') else 32
        else:width=WRITES[op]
        span=frame_span(destination,bases,width)
        if span is None:
            indirect.append(dict(line=i,instruction=line));continue
        direct.append(dict(line=i,range=list(span)))
        if overlaps(span,cell):
            s.require(span==cell,'no partial, wider or boundary-crossing saved-pointer write')
            allowed=(line==initializer and not writes) or (
                i>0 and lines[i-1]==clear_label+':' and line.startswith('movq $0, '))
            s.require(allowed,'saved pointer only initialized once or cleared on absent output')
            writes.append(dict(line=i,kind='initialize' if line==initializer else 'absent'))
    s.require([w['kind'] for w in writes]==['initialize','absent'],'complete saved-pointer direct-write population')
    return dict(direct_stores=direct,non_frame_stores_pending=indirect,
                calls_pending_indirect_effect_composition=calls,frame_addresses=addresses,
                cell_writes=writes)


def inspect(bodies,lane):
    s.require(lane in ('simd256','simd512'),'assigned first-output-pointer route')
    narrow=lane=='simd256';name=s.one(bodies,r'Resident6digest$' if narrow else r'Executor13digest_secret$')
    body=bodies[name];lines=s.lines(body)
    start,end,clear=('.B143','.B222','.B192') if narrow else ('.B182','.B256','.B243')
    cell=(184,192) if narrow else (976,984);base='rbx' if narrow else 'rbp'
    # RBP precedes 32-byte alignment in the narrow frame, so include every
    # possible alignment delta, not just a lucky concrete runtime address.
    bases={'rbx':(0,0),'rsp':(0,0),'rbp':(128,159)} if narrow else {'rbp':(0,0),'rsp':(-128,-128)}
    if narrow:
        s.sequences(body,['leaq 128(%rsp), %rbp|.seh_setframe %rbp, 128|.seh_endprologue|'
            'andq $-32, %rsp|movq %rsp, %rbx'])
    else:
        s.sequences(body,['subq $1192, %rsp|.seh_stackalloc 1192|leaq 128(%rsp), %rbp|'
            '.seh_setframe %rbp, 128|.seh_endprologue'])
    finish.inspect(bodies,lane)
    (commit.narrow if narrow else commit.wide)(bodies)
    s.require(lines.count(start+':')==lines.count(end+':')==1,'unique saved cell lifetime boundaries')
    a,b=lines.index(start+':'),lines.index(end+':');s.require(a<b,'ordered saved cell lifetime')
    result=inspect_region(lines[a:b],bases,cell,f'movq %rax, {cell[0]}(%{base})',clear)
    result['conditional_indirect_store_effects']=effects.inspect(lines[a:b],lane,
        result['non_frame_stores_pending'],s.one(bodies,r'secret_memory18copy_secret_region$'))
    return result|dict(function=name,begin=start,end=end,cell=list(cell),frame_alias_ranges=bases,
        direct_overwrite_and_direct_address_exposure_checked=True,
        all_indirect_effects_and_frame_lifetimes_qualified=False,
        parent_control_flow_and_jump_table_binding_required=True,whole_frame_qualified=False)
