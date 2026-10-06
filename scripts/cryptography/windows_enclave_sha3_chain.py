"""Close the saved scalar SHA-3 inner route; shared runtime remains separate."""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_sha3_permutation as p
import windows_enclave_sha3_terminal as terminal

setup,u,t,ops,life,shared = p.setup,p.u,p.t,p.ops,p.life,p.shared
require,digest = p.require,p.digest
BUILD_HASH = 'a6ba837a81247354958f57ad978d192fd5369f314f3f223e6ab86d7ffbea45c2'
SHARED = ('__chkstk','__umodti3','memcpy','memset','PublicSha3Input','PublicSha3Output',
          'PublicSha3Source','PublicSha3Observe')
DATA = ('.rdata',p.CONSTANT,'_RNvCsgzEJPm6isiJ_18sha3_stream_worker4LIVE.0',
        'switch.table._RNvMs0_Csgp9hxIs16B4_11sha3_streamNtB5_5Owner6rehash',
        'switch.table._RNvMs0_Csgp9hxIs16B4_11sha3_streamNtB5_5Owner6rehash.123')


def sources(raw,root):
    require(digest(raw)==BUILD_HASH,'saved source-to-build manifest identity')
    record=json.loads(raw)
    require(record['target']=='x86_64-pc-windows-msvc','saved compiler target')
    result={name.replace('\\','/'):sha for name,sha in record['source_sha256'].items()}
    require(len(result)==158,'complete saved worker build inputs')
    for name,sha in result.items():
        path=Path(name)
        require(not path.anchor and ':' not in name and '..' not in path.parts,'relative build input')
        require(digest((root/path).read_bytes())==sha,'unchanged saved implementation/build input: '+name)
    return result


def inventory(data):
    """Enumerate actual emitted code, not the list of functions we hoped to review."""
    rows,symbols=ops.obj.tables(data);names=set()
    for index,row in enumerate(rows,1):
        if not row['flags'] & 0x20000000 or not row['code']: continue
        functions=[s for s in symbols.values() if s['section']==index and s['kind']==32]
        require(len(functions)==1 and functions[0]['value']==0,'one named complete emitted code section')
        name=functions[0]['name'];require(name not in names,'unique emitted function')
        code,_=shared.caller.function(data,name)
        require(code==row['code'],'no unnamed trailing code outside reviewed function extent')
        names.add(name)
    return names


def reconcile(names,records,groups):
    require(names==set(records)==set(groups),'every emitted function has a semantic review assignment')
    require(len(names)==55,'frozen scalar route population')
    image=records['RetainedWork']['image_sha256'];external={};edges={};frames={}
    for name,r in records.items():
        require(r['entry']==name and r['image_sha256']==image,'same-image named record')
        fs=r.get('unwind',[])
        require(len(fs)<=1 and all(f['chain'] is None and f['frame']==0 for f in fs),
                'fixed scalar frames without chained extents')
        saved=[slot for f in fs for slot in f['saved_registers']]
        expected=([dict(register_class='xmm',register=6,offset=5984)]
                  if name=='_RNvMs0_Csgp9hxIs16B4_11sha3_streamNtB5_5Owner5setup' else [])
        require(saved==expected,'only the already reviewed setup XMM6 save slot')
        frames[name]=fs[0]['stack_bytes'] if fs else 0
        edges[name]=[]
        for target,address in r['reference_targets'].items():
            if target in records:
                require(address==records[target]['rva'],'every actual inner callee address')
                edges[name].append(target)
            elif target in SHARED:
                require(target not in external or external[target]['rva']==address,'consistent shared boundary')
                item=external.setdefault(target,dict(rva=address,assigned_completion_package=8,callers=[]))
                item['callers'].append(name)
            else:
                require(target in DATA,'no unassigned code/data reference: '+target)
        edges[name].sort()
    require(set(external)==set(SHARED),'exact shared boundary population')
    reached=set()
    def visit(n):
        if n in reached: return
        reached.add(n)
        for child in edges[n]: visit(child)
    visit('RetainedWork')
    require(reached==names,'all reviewed bodies reachable from the actual worker')
    for item in external.values(): item['callers'].sort()
    return edges,frames,external


def contributions(edges,frames,root='RetainedWork'):
    """Conservative local-only bound: even tail calls count as nested calls.

    Runtime callees are deliberately excluded, not assigned zero total depth.
    This is NOT maximum whole-image depth or an arbitrary-CFG stack analyzer.
    """
    memo={}
    def depth(name,active):
        require(name not in active,'no unaccounted recursive scalar call cycle')
        if name in memo: return memo[name]
        children=[depth(n,active | {name}) for n in edges[name]]
        size,path=max(children,default=(0,[]),key=lambda pair:pair[0])
        result=frames[name]+(8+size if children else 0),[name]+path
        memo[name]=result;return result
    size,path=depth(root,set())
    require(104+size<=65536,'local conservative chain fits the admitted window')
    return dict(local_bytes_below_worker_entry=size,local_rsp_bound_from_window_high=-104-size,
        conservative_path=path,tail_calls_counted_as_nested=True,
        shared_runtime_frames_excluded=True,maximum_whole_image_depth_qualified=False)


def inspect(base,root,mutate=False):
    reviewers=dict(lifecycle=life,operations=ops,state=setup.state,transfers=t,
        prefix=u.p,update=u,finalize=terminal.f,terminal=terminal,setup=setup)
    reports={name:review.inspect(base,mutate) for name,review in reviewers.items()}
    row=shared.catalog(shared.CATALOG.read_bytes())[3]
    profile=life.workers.specification(life.workers.SPEC.read_bytes())['profiles'][2]
    directory=(base/row['object']).parent
    build=sources((directory/'sha3-worker-build.json').read_bytes(),root)
    data=life.workers.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']]
    image=(base/row['image']).read_bytes()
    new,constants=p.inspect(data,image,(directory/'normal_rust.s').read_bytes())
    records={};groups={}
    def add(record,group):
        name=record['entry']
        if name in records:
            require(records[name]['rva']==record['rva'] and
                    records[name]['reference_targets']==record['reference_targets'],'overlapping review consistency')
        records[name]=record;groups.setdefault(name,group)
    for group,report in reports.items():
        for record in report['records'].values(): add(record,group)
    for record in reports['lifecycle']['anchors'].values(): add(record,'worker boundary/lifecycle')
    for record in new.values(): add(record,'permutation/destructor')
    edges,frames,external=reconcile(inventory(data),records,groups)
    # Shared transport/memory bindings are reproduced, not promoted to a full
    # runtime/stack guarantee. __chkstk and __umodti3 remain named Commit-8 work.
    memory=ops.memory.inspect(data,image,55)['runtime_targets']
    for name,address in memory.items(): require(external[name]['rva']==address,'reviewed memory boundary')
    require(external['__umodti3']['rva']==reports['operations']['runtime_boundaries_pending']['__umodti3'],
            'reviewed public remainder boundary')
    count=0
    if mutate:
        for name in new:
            code,refs=shared.caller.function(data,name)
            for at in range(len(code)):
                bad=bytearray(code);bad[at] ^= 1
                try: p.body_check(name,bad,refs)
                except ValueError: count += 1
                else: raise AssertionError('accepted scalar leaf/destructor byte mutation')
    result=dict(schema=1,status='AUTHOR_SAVED_SCALAR_SHA3_INNER_CHAIN_REVIEW',route=row['route'],
        image_sha256=digest(image),object_sha256=digest(data),build_inputs_sha256=build,
        function_inventory={name:dict(review=groups[name],rva=r['rva'],bytes=r['size'],
            fixed_frame_bytes=frames[name],saved_registers=[s for f in r.get('unwind',[]) for s in f['saved_registers']],
            inner_callees=edges[name],references=r['reference_targets'])
            for name,r in sorted(records.items())},round_constants=constants,
        runtime_boundaries_pending=external,geometry=contributions(edges,frames),
        reproduced_reviews={name:dict(status=r['status'],
            body_byte_mutations=r.get('actual_body_byte_mutations_rejected',0),
            table_byte_mutations=r.get('actual_table_byte_mutations_rejected',0)) for name,r in reports.items()},
        new_body_byte_mutations_rejected=count,inner_function_population=55,
        unassigned_inner_functions=[],scalar_permutation_internals_reviewed=True,
        buffer_destructor_normal_exit_paths_checked=True,
        normal_failure_cleanup_reviewed=True,outer_window_reclamation_required=True,
        individual_caller_spills_erased=False,whole_image_qualified=False,
        arbitrary_exception_cleanup_qualified=False,independently_verified=False,
        native_run_added=False,release_gate_changed=False)
    paths={Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    paths.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-sha3-chain.py')))
    result['source_sha256']={path.name:digest(path.read_bytes()) for path in sorted(paths)}
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    parser.add_argument('--mutate',action='store_true');parser.add_argument('--output',type=Path)
    args=parser.parse_args();text=json.dumps(inspect(args.saved_directory,args.source_root,args.mutate),indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
