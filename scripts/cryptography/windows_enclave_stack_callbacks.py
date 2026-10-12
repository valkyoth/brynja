"""Replay completed family provenance before assigning indirect stack callees.

For depth only, conservatively allow either of the two internal leaf callbacks
at every reviewed site. This is not a new proof of callback argument semantics;
the complete original family check supplies that prerequisite each time.
"""
import json
import re
import windows_enclave_sha2_batch_chains as sha2
import windows_enclave_sha3_batch_chains as sha3

require,digest=sha2.require,sha2.digest
ROUTES={'sha256_simd/mod.rs::open_avx2':('simd256',13),
    'sha512_simd/mod.rs::open_avx2':('simd512',16),
    'keccak_simd/mod.rs::open_avx2':('simd',15)}


def canonical(operand):
    return re.sub(r'0x[0-9a-f]+',lambda m:str(int(m[0],16)),operand)


def inspect(base,root,route,image_hash,functions,nodes):
    actual={name:['callq '+canonical(c['operand']) for c in node['scans'][0]['calls']
        if c['target'] is None] for name,node in nodes.items()}
    actual={n:v for n,v in actual.items() if v}
    if route not in ROUTES:
        require(not actual,'no new unassigned indirect call route');return None
    lane,count=ROUTES[route];checker=sha3 if lane=='simd' else sha2
    pin=checker.specification(checker.SPEC.read_bytes())[lane]
    report=checker.inspect_route(base,root,lane,pin,False)
    require(report['image_sha256']==image_hash,'callback review binds identical signed image')
    if lane=='simd':
        require(report['private_chain_complete'],'complete SHA-3 family callback provenance')
        expected=report['transfers']['indirect_calls_pending']
        leaves=dict(callback=report['simd_digest']['callbacks']['slots']['32'],
            compiled=report['simd_resident_construction']['compiled_callback'])
    else:
        require(not report['callback_callsite_review_pending'],'complete SHA-2 callback provenance')
        expected=report['reviewed_indirect_call_population']
        leaves=report['semantics']['simd_control_call_effects']['leaf_targets']
    require({n:sorted(v) for n,v in actual.items()}=={n:sorted(v) for n,v in expected.items()} and
        sum(map(len,actual.values()))==count,'exact decoded versus family indirect-call population')
    require(set(leaves)=={'callback','compiled'} and len(set(leaves.values()))==2,
        'two distinct internal leaf identities, not arbitrary host callbacks')
    for role,hex_code in (('callback','31c0c3'),('compiled','89c83401c3')):
        name=leaves[role]
        require(name in functions and functions[name][0]==bytes.fromhex(hex_code) and
            not functions[name][1] and name in nodes and all(
                s['local_low']==0 and not s['calls'] for s in nodes[name]['scans']),
            'complete actual stack-free callback body '+role)
    return dict(targets=sorted(leaves.values()),sites=count,family_provenance_replayed=True,
        family_report_sha256=digest(json.dumps(report,sort_keys=True).encode()),
        conservative_target_union_for_depth_only=True)
