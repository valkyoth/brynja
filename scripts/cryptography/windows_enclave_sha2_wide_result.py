"""Saved wide SIMD result admission and descriptor handoff, not frame erasure.

All normal returns and direct stores are checked. Prior descriptor/physical
reviews, helper noninterference and Win64 ABI preservation remain prerequisites.
No error-tag-only path initializes a returned descriptor fact in the caller.
"""
import re
import windows_enclave_sha2_dynamic_cleanup as d
import windows_enclave_sha2_cleanup_invokes as invokes
r,n,o,g,s=d.r,d.n,d.o,d.g,d.s


def return_paths(lines,edges,copy_end,error_tag,result_tag):
    """Finite must-property: every ret follows error admission or complete copy.

The caller separately inventories every result-object write, their disjoint
extents and pointer origins, and verifies the uninterrupted copied region.
"""
    s.require(len({copy_end,error_tag,result_tag})==3,'distinct copy/error/result events')
    todo=[(0,'unset')];seen=set();returns={};events=set()
    while todo:
        at,state=todo.pop()
        if (at,state) in seen:continue
        seen.add((at,state));s.require(at in edges,'closed result-return CFG')
        if at==copy_end:state='copied';events.add(at)
        elif at==error_tag:state='error';events.add(at)
        elif at==result_tag:
            s.require(state=='copied','result discriminant follows the complete descriptor copy')
            state='result';events.add(at)
        if lines[at]=='retq':
            s.require(state in ('error','result'),'no uninitialized or partial normal return')
            returns.setdefault(at,set()).add(state)
        todo.extend((dest,state) for dest in edges[at])
    s.require(events=={copy_end,error_tag,result_tag} and returns,
              'both assigned result forms have real reachable events and returns')
    s.require(set().union(*returns.values())=={'error','result'},'both complete result forms reach normal return')
    return dict(states=len(seen),normal_returns={str(k):sorted(v) for k,v in returns.items()})


def child(bodies,assembly,prior):
    name=s.one(bodies,r'Executor13digest_secret$');lines=s.lines(bodies[name]);edges=d.graph(lines,assembly)
    tables=o.source.paths.jump_tables(assembly,lines);states=o.definitions(lines,name,tables)
    root=o.unique(lines,'movq %rcx, %rsi')
    s.require(root in states and states[root]['rcx']=={-1},'child return object is the original hidden ABI result argument')
    copied=prior['copies'][0]
    s.require(prior['function']==name and copied['source']==['rbp',816] and
              copied['destination']==['rsi',0] and copied['bytes']==72,
              'same original descriptor region and result-copy proof')
    first,last=copied['first_line'],copied['last_line']
    error=o.unique(lines,'movb $-1, 96(%rsi)');success=o.unique(lines,'movb %r15b, 96(%rsi)')
    n.straight(edges,error-1,error);n.straight(edges,first,success)
    expected=['movb %r14b, (%rsi)','movb $-1, 96(%rsi)',
        'vmovups %ymm1, 32(%rsi)','vmovups %ymm0, (%rsi)','movq %rax, 64(%rsi)',
        'movq %rax, 88(%rsi)','vmovups %xmm0, 73(%rsi)',
        'movl %eax, 97(%rsi)','movl %ecx, 100(%rsi)',
        'movb %r13b, 72(%rsi)','movb %r15b, 96(%rsi)']
    writes=[];uses=[];original_input_uses=[]
    for at in sorted(states):
        op,args=o.source.instruction(lines[at])
        if op=='callq':
            s.require(-1 not in states[at]['rcx'],'original result pointer never escapes as a call argument')
            continue
        # Include memory destinations (address reads), comparisons and partial
        # register aliases, but not the overwritten destination of a pure move.
        read_args=args[:-1] if args and args[-1].startswith('%') and op.startswith(('mov','vmov','lea','pop','set')) else args
        if op in o.source.READ:read_args=lines[at].split(' ',1)[1].split(', ')
        if op in ('xorl','xorq') and len(args)==2 and args[0]==args[1]:read_args=[]
        used=set(re.findall(r'%\w+',' '.join(read_args)))
        if any(o.ALIASES.get(v)=='rcx' for v in used) and -1 in states[at]['rcx']:
            s.require(at==root,'no hidden original result-pointer alias or escape')
        if any(o.ALIASES.get(v)=='r9' for v in used) and -1 in states[at]['r9']:
            s.require(at in prior['argument_copy'][:1] or at==prior['argument_copy'][0]+1,
                      'original descriptor argument consumed only by its two vector loads')
            original_input_uses.append(at)
        if any(o.ALIASES.get(v)=='rsi' for v in used) and root in states[at]['rsi']:
            s.require(states[at]['rsi']=={root},'no merged stale/result pointer origins')
            s.require(lines[at] in expected,'result pointer does not escape its assigned direct stores')
            uses.append(at)
        span=o.source.store_span(op,args,{'rsi':(0,0)})
        if span:
            s.require(states[at]['rsi']=={root},'every result store uses the original result argument')
            writes.append((at,span))
    s.require([lines[at] for at,_ in writes]==expected and uses==[at for at,_ in writes],
              'complete result-store/alias population, no extra partial or indexed writes')
    s.require(original_input_uses==[prior['argument_copy'][0],prior['argument_copy'][0]+1],
              'nonvacuous original R9 argument-copy consumption')
    for at,span in writes:
        if first<=at<=last:s.require(0<=span[0]<span[1]<=72,'descriptor copy result extent')
        elif at!=error-1:s.require(72<=span[0]<span[1]<=104,'metadata cannot overwrite returned descriptors')
    paths=return_paths(lines,edges,last,error,success)
    return dict(function=name,pointer_origin=root,result_bytes=104,descriptor_bytes=72,
        stores=[dict(line=at,span=list(span)) for at,span in writes],original_input_uses=original_input_uses,
        copy_complete=last,error_discriminant=error,result_discriminant=success,return_paths=paths,
        non_error_return_preserves_original_descriptors=True,
        helper_noninterference_and_nonvolatile_ABI_required=True)


def fixed_parent_frame(lines,edges):
    probe=o.unique(lines,'callq __chkstk')
    s.require(lines[probe-1:probe+8]==['movl $12984, %eax','callq __chkstk','subq %rax, %rsp',
        '.seh_stackalloc 12984','leaq 128(%rsp), %rbp','.seh_setframe %rbp, 128',
        '.seh_endprologue','andq $-32, %rsp','movq %rsp, %rbx'],'fixed aligned wide parent frame')
    n.straight(edges,probe-1,probe+7)
    end=o.unique(lines,'.seh_startepilogue');ret=o.unique(lines,'retq')
    aliases={'%'+v for names in o.source.cells.BASE_ALIASES.values() for v in names}
    for at,line in enumerate(lines):
        if at<=probe+7 or end<=at<=ret:continue
        op,args=o.source.instruction(line)
        s.require(not args or args[-1] not in aliases or op=='pushq','parent frame bases preserved through all normal paths')
    return probe


def parent(bodies,assembly,prior,child_proof):
    name=prior['parent'];lines=s.lines(bodies[name]);edges=d.graph(lines,assembly)
    probe=fixed_parent_frame(lines,edges)
    call=o.unique(lines,'callq '+child_proof['function']);forward,reverse=prior['copies'][1:]
    tag=call+5;first=forward['first_line'];end=forward['last_line']
    s.require(lines[call-5:call+6]==['leaq 4640(%rbx), %rcx','leaq 120(%rbx), %rdx',
        'leaq 192(%rbx), %r8','leaq 352(%rbx), %r9','vzeroupper','callq '+child_proof['function'],
        'nop','.Ltmp71:','movzbl 4736(%rbx), %ecx','cmpb $-1, %cl','je .B69'],
        'original argument/returned-result bridge and exact non-error discriminant test')
    s.require(first==tag+1,'non-error edge directly enters the preserved result copy')
    n.straight(edges,call-5,first)
    drop=d.storage.symbols(bodies)['output']
    drops=[at for at,line in enumerate(lines) if line=='callq '+drop]
    s.require(len(drops)==2,'complete parent normal output destructor population')
    for at,off in zip(drops,(4640,352),strict=True):
        s.require(lines[at-2:at]==[f'leaq {off}(%rbx), %rcx','vzeroupper'],
                  'parent drop receives the corresponding live descriptor object')
        n.straight(edges,at-2,at)
    n.straight(edges,reverse['first_line'],drops[0])
    guarded,unwind=invokes.inspect(bodies,assembly,'simd512',name,drop)
    regions={'original':(352,416),'returned':(4640,4704)}
    initializers={prior['construction'][1]:[('original',None)],end:[('original','returned')],
                  reverse['last_line']:[('returned','original')]}
    reads={call:['original'],first:['returned'],reverse['first_line']:['original'],
           drops[0]:['returned'],drops[1]:['original']}
    lifetime,_=r.lifetime(lines,edges,n.BASES,regions,initializers,reads,
        flags=(55,),guarded=guarded,edge_initializers={(tag,first):[('returned','original')]})
    return dict(function=name,probe=probe,child_call=call,success_edge=[tag,first],
        normal_drops=drops,unwind_requirements=unwind,direct_write_lifetime=lifetime,
        original_descriptor_argument=[352,416],returned_descriptors=[4640,4704],
        discriminant_offset=4736,only_non_error_edge_initializes_returned_descriptors=True)


def inspect(bodies,assembly,prior):
    s.require(prior['normal_direct_descriptor_write_lifetimes_checked'] is True and
        prior['exact_pointer_length_pair_and_all_loop_indices_checked'] is True and
        prior['geometry']['exact_lane_pointers_and_widths'] is True,
        'fresh dynamic descriptor lifetime and geometry checks required')
    child_proof=child(bodies,assembly,prior)
    return dict(child=child_proof,parent=parent(bodies,assembly,prior,child_proof),
        conditional_direct_descriptor_handoff_checked=True,
        earlier_indirect_effects_cleanup_order_and_physical_lifetimes_still_required=True,
        arbitrary_exception_or_whole_frame_qualification=False,whole_frame_qualified=False)
