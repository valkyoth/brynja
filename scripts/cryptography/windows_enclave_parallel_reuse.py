"""Replay prior reviews and partition exact reuse from explicit remaining work.

An unchanged helper body is not its new caller's pointer/lifetime proof. Selected
scheduler checks likewise retain their original limited scope, even when replayed.
"""
import argparse
import json
from pathlib import Path
import sys

import windows_enclave_parallel_inventory as inventory
import windows_enclave_root_return as root_return
import windows_enclave_root_setup as root_setup
import windows_enclave_publication_review as publication

c=inventory.common
require,digest=inventory.require,inventory.digest
EXACT={'scalar':25,'avx2':21,'concurrent':17}
CHANGED={'scalar':0,'avx2':3,'concurrent':6}


def partition(current,prior,current_ir,prior_ir):
    exact,changed=c.reuse.exact_reuse(current,prior,current_ir,prior_ir)
    distinct=sorted(set(current)-set(exact)-set(changed))
    require(not set(exact)&set(changed) and not set(exact)&set(distinct) and
        not set(changed)&set(distinct) and set(exact)|set(changed)|set(distinct)==set(current),
        'every emitted body assigned once without implied closure')
    return dict(exact_body_reference_extent_and_abi=exact,
        same_body_but_changed_abi=changed,distinct_bodies=distinct,
        new_callers_and_transitive_callees_still_require_composition=True,
        helper_equality_establishes_whole_path=False)


def prior_inputs(base,root,lane):
    pin=c.specification(c.SPEC.read_bytes())[lane]
    _,data,image,_,ir,_=c.load(base,root,lane,pin)
    return c.previous.inventory(data),ir,image,data


def constant_contract(data,image,records,functions,exact):
    """Same helper code must not inherit different linked constant data."""
    rows,symbols=c.obj.tables(data);constants={}
    for name in exact:
        for target,address in records[name]['reference_targets'].items():
            if target in functions or target in ('memcpy','memset','memcmp','__umodti3','__chkstk'):continue
            found=[v for v in symbols.values() if v['name']==target and v['section']>0]
            require(len(found)==1 and found[0]['value']==0,'unique reused-helper data origin')
            row=rows[found[0]['section']-1]
            require(row['code'] and not row['nrelocs'] and row['flags']&0xe0000000==0x40000000,
                'reused-helper constant is immutable and relocation-free')
            require(c.previous.readonly(image,address,len(row['code']))==row['code'],
                'actual current linked helper constant')
            constants[target]=dict(bytes=len(row['code']),sha256=digest(row['code']))
    return constants


def selected_scheduler(inputs,base):
    native=(base/'scheduler-register-nospill/concurrent.obj').read_bytes()
    data,image=inputs['object'],inputs['image']
    # These execute the original object/instruction/callee checks, not load old
    # JSON summaries. All are tied to this same current frozen signed image.
    reports={
        'outer_root_return':root_return.inspect(data,native,image),
        'root_setup':root_setup.inspect(data,image),
        'publication':publication.inspect(data,image),
        'slot':root_return.slot.inspect(data,image)}
    for report in reports.values():
        require(report['object_sha256']==digest(data) and report['image_sha256']==digest(image),
            'selected review belongs to exact current object/image')
        require(report['whole_image_qualified'] is False,'selected review is not whole-image qualification')
    return reports


def inspect(base,root,mutate=False):
    report=inventory.inspect(base,root,mutate)
    previous=c.inspect(base,root)
    spec=inventory.specification(inventory.SPEC.read_bytes())
    for lane,pin in spec.items():
        inputs,_=inventory.load(base,root,pin)
        current=c.previous.inventory(inputs['object'])
        old_lane='scalar' if lane=='scalar' else 'avx2'
        prior,old_ir,old_image,old_data=prior_inputs(base,root,old_lane)
        require(previous['routes'][old_lane]['image_sha256']==digest(old_image),'fresh prior review image')
        reused=partition(current,prior,inputs['ir'].decode(),old_ir)
        require(len(reused['exact_body_reference_extent_and_abi'])==EXACT[lane] and
            len(reused['same_body_but_changed_abi'])==CHANGED[lane],'fixed helper-reuse population')
        constants=constant_contract(inputs['object'],inputs['image'],report['routes'][lane]['records'],
            current,reused['exact_body_reference_extent_and_abi'])
        prior_records=c.previous.bind_all(old_data,old_image,prior)
        require(constants==constant_contract(old_data,old_image,prior_records,prior,
            reused['exact_body_reference_extent_and_abi']),'same actual constant contract as prior helper')
        reused.update(prior_image_sha256=digest(old_image),prior_semantics_replayed=True,
            immutable_constants_rebound_and_equal=constants,
            all_current_callee_addresses_rebound=True)
        row=report['routes'][lane];row['helper_reuse']=reused
        row['remaining_semantic_body_assignments']=sorted(
            set(reused['distinct_bodies'])|set(reused['same_body_but_changed_abi']))
        row['remaining_path_obligations']=(
            ['root/leaf state transitions and original allocation lifetimes',
             'framing, leaf completion, rehash and terminal output paths',
             'normal failure, invoked handlers, worker/page retirement'] if lane!='concurrent' else
            ['root/leaf entry and per-thread authority/storage composition',
             'slot publication, generations, join-before-reuse and ordered CV reduction',
             'cancellation, partial workers, invoked handlers and per-window retirement'])
        if lane=='concurrent':row['selected_prior_reviews']=selected_scheduler(inputs,base)
    report.update(status='AUTHOR_PARALLELHASH_REUSE_AND_REMAINING_MAP',
        passes=[dict(number=1,work='frozen populations, fresh primitive/selected scheduler replay and remaining map'),
                dict(number=2,work='both sequential routes'),
                dict(number=3,work='concurrent root/leaf and scheduler composition'),
                dict(number=4,work='combined regression, evidence and conditional family closure')],
        compiler_runtime_and_whole_window_qualification_package=8)
    report['source_sha256']={p.name:digest(p.read_bytes()) for p in sorted(
        {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')} | {Path(__file__)})}
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args=p.parse_args();result=inspect(args.saved_directory,args.source_root,args.mutate)
    text=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(text,encoding='utf-8')
    else:print(text,end='')
