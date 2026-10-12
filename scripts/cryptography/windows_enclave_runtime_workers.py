"""Bind every saved worker body before composing shared runtime contracts.

Actual archive members and linked PE bytes are authoritative, including cleanup
funclets. This inventory does not itself prove execution paths or stack bounds.
"""
import windows_enclave_runtime_catalog as catalog
import windows_enclave_sha3_avx2_chain as chain
import windows_enclave_sha2_batch_chains as batch
import windows_enclave_bounded_dispatch as bounded
import windows_enclave_bounded_export as export

require,digest=catalog.require,catalog.digest


def load(base,route):
    image=(base/route['image']).read_bytes()
    require(digest(image)==route['sha256'],'original signed worker image')
    if route['route'].startswith('parallel_concurrent/'):
        pin=catalog.parallel.specification(catalog.parallel.SPEC.read_bytes())['concurrent']
        directory=base/pin['directory'];member=pin['member'];sha=pin['object_sha256']
    elif route['route']=='mod.rs::open':
        directory=(base/route['object']).parent;member=bounded.MEMBER;sha=bounded.OBJECT
    else:
        profiles=chain.w.specification(chain.w.SPEC.read_bytes())['profiles']
        found=[p for p in profiles if p['route']==route['route']]
        require(len(found)==1,'one original route profile')
        pin=found[0];directory=(base/route['object']).parent
        member=pin['member'];sha=pin['object_sha256']
    members=chain.w.archive.members((directory/'normal_rust.lib').read_bytes())
    require(member in members,'original Rust archive member exists')
    data=members[member];require(digest(data)==sha,'original worker object')
    return data,image


def bind(data,image):
    functions=chain.inventory(data)
    ordinary=dict(functions);token=ordinary.pop('RetainedTokenWord',None)
    records=batch.bind_all(data,image,ordinary)
    if token:
        code,refs,_=token;export.check_body('RetainedTokenWord',code,refs)
        at,size,_,_=export.SPECS['RetainedTokenWord']
        rows,fs=catalog.sdk.pe.linked(image)
        export.mapped_code(rows,fs,at,export.linked_bytes(code,refs,at,export.TARGETS),True)
        records['RetainedTokenWord']=dict(rva=at,size=size,
            reference_targets={v['symbol']:export.TARGETS[v['symbol']] for v in refs})
    require(set(functions)==set(records),'every actual emitted function bound')
    return functions,records
