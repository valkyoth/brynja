"""Whole-function normal-return workspace-cleanup ordering for saved SIMD.

Finite CFG traversal checks ordering, not callee arguments or alias freedom.
The parent binds the complete bodies, actual tables and full wipe contracts.
Invoked unwind handlers, abort paths and physical frame erasure are separate.
"""
import re
import windows_enclave_kmac_shapes as s
import windows_enclave_sha2_simd_storage as storage


def jump_tables(assembly,lines):
    result={};used=set()
    for at,line in enumerate(lines):
        if not line.startswith('jmpq *'):continue
        before=lines[max(0,at-5):at]
        matches=[(i,re.fullmatch(r'leaq (\.LJTI\d+_\d+)\(%rip\), %(\w+)',v))
                 for i,v in enumerate(before)]
        matches=[(i,m) for i,m in matches if m]
        s.require(len(matches)==1,'one explicit table base per indirect jump')
        i,m=matches[0];name,base=m[1],m[2];target=line.removeprefix('jmpq *%')
        pattern=r'movslq \(%'+base+r',%(\w+),4\), %'+target
        s.require(i+2<len(before) and re.fullmatch(pattern,before[i+1]) is not None
                  and before[i+2]==f'addq %{base}, %{target}', 'exact relative table dispatch')
        # The wide output-width jump restores two non-dispatch pointers after
        # forming its destination. No branch or target overwrite may intervene.
        extra=before[i+3:]
        s.require(not extra or (name=='.LJTI23_5' and extra==[
            'movq 1168(%rbp), %rdi','movq 1048(%rbp), %r15']), 'assigned dispatch restore only')
        found=re.findall(r'^'+re.escape(name)+r':\n((?:\s*\.long\s+[^\n]+\n)+)',assembly,re.M)
        s.require(len(found)==1 and name not in used,'one unique used table')
        entries=re.findall(r'\.long\s+(\S+)',found[0])
        destinations=[]
        for entry in entries:
            match=re.fullmatch(r'\.LBB\d+_(\d+)-'+re.escape(name),entry)
            s.require(match is not None,'local relative cleanup-CFG destination')
            destinations.append('.B'+match[1])
        s.require(destinations,'nonempty branch table')
        result[at]=destinations;used.add(name)
    return result


def check(lines,start,dirty,clear,tables):
    s.require(dirty and clear and not dirty.intersection(clear),'nonvacuous disjoint helper contracts')
    labels={v[:-1]:i for i,v in enumerate(lines) if v.endswith(':')}
    s.require(len(labels)==sum(v.endswith(':') for v in lines) and start in labels,
              'unique labels and explicit whole-function entry')
    pending=[(labels[start],False)];seen=set();returns=set();terminals=set();writes=set();wipes=set()
    while pending:
        at,live=pending.pop()
        if (at,live) in seen:continue
        seen.add((at,live));s.require(0<=at<len(lines),'no escaped normal cleanup path')
        line=lines[at]
        if line.startswith('callq '):
            target=line[6:]
            if target in dirty:live=True;writes.add(at)
            if target in clear:live=False;wipes.add(at)
        if line=='retq':
            s.require(not live,'normal return after a sensitive helper bypasses full workspace cleanup')
            returns.add(at);continue
        if line=='ud2':terminals.add(at);continue
        if line.startswith('j'):
            op,target=line.split(maxsplit=1)
            if target.startswith('*'):
                s.require(op=='jmpq' and at in tables,'assigned indirect branch table')
                targets=tables[at]
            else:targets=[target]
            s.require(all(v in labels for v in targets),'all branch destinations stay in reviewed function')
            pending.extend((labels[v],live) for v in targets)
            if op in ('jmp','jmpq'):continue
        pending.append((at+1,live))
    s.require(returns and writes and wipes,'nonvacuous normal returns, sensitive helpers and complete wipes')
    return dict(normal_return_sites=sorted(returns),sensitive_helper_sites=sorted(writes),
        full_workspace_cleanup_sites=sorted(wipes),terminal_sites=sorted(terminals),
        reachable_states=len(seen))


def inspect(bodies,assembly,lane):
    narrow=lane=='simd256';s.require(lane in ('simd256','simd512'),'assigned cleanup lane')
    name=s.one(bodies,r'Resident6digest$' if narrow else r'Executor13digest_secret$')
    dirty={s.one(bodies,pattern) for pattern in (r'secret_memory18copy_secret_region$',
        r'secret_memory22apply_secret_byte_mask$',r'Session14compress_bytes$',r'engine7padding$',
        r'hardened10compress'+('32' if narrow else '64')+r'6native6scalar$')}
    names=storage.symbols(bodies);clear={names['workspace'],names['drop']}
    # Required independently: a call name alone is not an erasure contract.
    storage.wiping(bodies,lane)
    lines=s.lines(bodies[name]);tables=jump_tables(assembly,lines)
    s.require(len(tables)==(0 if narrow else 11),'complete digest indirect branch population')
    return dict(function=name,**check(lines,name,dirty,clear,tables),
        sensitive_targets=sorted(dirty),complete_wipe_targets=sorted(clear),
        branch_tables={str(at):values for at,values in tables.items()},
        all_normal_return_paths_checked=True,
        helper_argument_and_original_storage_lifetimes_required=True,
        copy_calls_conservatively_mark_live_even_for_public_or_empty_input=True,
        terminal_paths_are_not_cleanup_success=True,arbitrary_exception_cleanup_qualified=False,
        whole_frame_qualified=False)
