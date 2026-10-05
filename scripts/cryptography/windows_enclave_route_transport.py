"""Saved family-specific C transport/SDK bindings, not Rust worker qualification."""
import argparse
import json
from pathlib import Path

import windows_enclave_bounded_callbacks as callbacks
import windows_enclave_bounded_export as exported

shared = callbacks.shared
require,digest = shared.require,shared.digest
SPEC = shared.CATALOG.with_name('transport-templates-20261005.json')
SPEC_HASH = '914a2f40f006b1120e0e415e51f0ae79b7de060fbc4f45fdd088865a4ea8d7ad'
ROLES = ('Source','Input','Output','Observe','InputSource','Control')
DATA = {'active':4,'retained_call':4,'retained_live':4,'retained_operation':8,
        'retained_output':8,'PublicLockedLow':8,'PublicLockedHigh':8,
        'source':8,'report':56,'last_kind':8}
SDK = {'EnclaveCopyIntoEnclave','EnclaveCopyOutOfEnclave'}


def specification(raw):
    require(digest(raw) == SPEC_HASH,'reviewed transport templates')
    result = json.loads(raw)
    require(result['schema'] == 1 and len(result['profiles']) == 17,'transport profile population')
    used = set()
    for profile in result['profiles']:
        require(set(profile['bodies']) == set(ROLES),'six transport roles')
        for role,key in profile['bodies'].items():
            template = result['templates'][key];used.add(key)
            require(template['role'] == role and key == digest(shared.encoded([template['bytes'],template['references']])),
                    'role and complete template identity')
            require(all(r['symbol'] in {*DATA,*SDK} for r in template['references']),'known transport references')
    require(used == set(result['templates']),'no unassigned template')
    return result


def canonical(profile,refs):
    g = profile['global_prefix']
    aliases = {g+'_source':'source',g+'_report':'report','simd_last_kind':'last_kind'}
    return [r | {'symbol':aliases.get(r['symbol'],r['symbol'])} for r in refs]


def body_check(profile,role,templates,code,refs):
    template = templates[profile['bodies'][role]]
    require(template['role'] == role and code.hex() == template['bytes'],'complete reviewed transport body')
    require(canonical(profile,refs) == template['references'],'complete reviewed transport references')


def reconcile_targets(identities,refs,start,code):
    for ref in refs:
        at = ref['offset'];require(0 <= at <= len(code)-4,'complete linked reference')
        target = start+at+4+ref['trailing']+int.from_bytes(code[at:at+4],'little',signed=True)-ref['addend']
        name = ref['symbol']
        require(name not in identities or identities[name] == target,'same transport global/callee')
        identities[name] = target


def leaf_at(data,image,name,profile,role,templates,identities,address=None):
    code,refs = shared.caller.function(data,name);body_check(profile,role,templates,code,refs)
    refs = canonical(profile,refs);rows,functions = shared.caller.pe.linked(image)
    require(role in ('InputSource','Control','Source','Observe'),'reviewed leaf roles')
    require(all(r['symbol'] in DATA for r in refs),'leaf references only data')
    if address is None:
        # Source and observer use identities already established by named
        # exported setup/control and the framed input/output callers.
        require(all(r['symbol'] in identities for r in refs),'anchored leaf data references')
        candidates = []
        for row in rows:
            if row['flags'] & 0xe0000000 != 0x60000000: continue
            # The initial active load is present in both fully pinned bodies.
            for at in range(min(len(row['code']),row['virtual_size'])-len(code)+1):
                if row['code'][at:at+2] != code[:2]: continue
                start = row['rva']+at
                expected = exported.linked_bytes(code,refs,start,identities)
                if row['code'][at:at+len(code)] == expected: candidates.append(start)
        require(len(candidates) == 1,'unique fully relocated anchored leaf')
        address = candidates[0]
    linked = callbacks.dispatch.mapping.mapped(rows,address,len(code))
    reconcile_targets(identities,refs,address,linked)
    expected = exported.linked_bytes(code,refs,address,identities)
    exported.mapped_code(rows,functions,address,expected,True)
    return dict(rva=address,bytes=len(code),reference_targets={r['symbol']:identities[r['symbol']] for r in refs})


def metadata(rows,identities):
    result=[]
    for name,size in DATA.items():
        if name not in identities: continue
        address=identities[name]
        owners=[r for r in rows if r['rva'] < address+size and address < r['rva']+r['virtual_size']]
        require(len(owners)==1 and owners[0]['rva'] <= address and
                address+size <= owners[0]['rva']+owners[0]['virtual_size'] and
                owners[0]['flags'] & 0xe0000000 == 0xc0000000,'complete writable nonexecutable transport metadata')
        result.append(dict(name=name,rva=address,bytes=size))
    ordered=sorted(result,key=lambda s:s['rva'])
    require(all(a['rva']+a['bytes'] <= b['rva'] for a,b in zip(ordered,ordered[1:])),'separate metadata spans')
    return result


def inspect(data,image,wrapper,sdk,profile,templates,mutate=False):
    parent=shared.inspect(data,image,wrapper);identities={};records={};count=0
    for role in ROLES:
        code,refs=shared.caller.function(data,profile['prefix']+role);body_check(profile,role,templates,code,refs)
        if mutate:
            for i in range(len(code)):
                bad=bytearray(code);bad[i]^=1
                try: body_check(profile,role,templates,bad,refs)
                except ValueError: count+=1
                else: raise AssertionError('accepted actual transport body mutant')
    for role in ('Input','Output'):
        name=profile['prefix']+role;record=shared.caller.bind(data,image,name)
        frames=record['unwind']
        require(len(frames)==1 and frames[0]['stack_bytes']==40 and frames[0]['chain'] is None and
                frames[0]['saved_registers']==[],'fixed complete transport frame')
        refs=canonical(profile,record['references'])
        targets={r['symbol']:r['symbol_rva'] for r in refs}
        for name,address in targets.items():
            require(name not in identities or identities[name]==address,'same input/output metadata')
            identities[name]=address
        records[role]=dict(rva=record['rva'],bytes=record['size'],fixed_frame_bytes=40,reference_targets=targets)
    for role in ('InputSource','Control','Source','Observe'):
        name=profile['prefix']+role
        address=callbacks.exported(image,name) if role in ('InputSource','Control') else None
        records[role]=leaf_at(data,image,name,profile,role,templates,identities,address)
    for name,address in identities.items():
        if name in parent['reference_targets']:
            require(parent['reference_targets'][name]==address,'same outer wrapper/transport identity')
    rows,functions=shared.caller.pe.linked(image);imports=shared.sdk.imports(image)['vertdll.dll'];edges={}
    for name in SDK:
        thunk=shared.sdk.thunk(rows,functions,identities[name],imports[name])
        address=shared.sdk.export(sdk,name)
        require(address==shared.sdk.status.sdk.BODIES[name][0],'same reviewed saved SDK export')
        edges[name]=dict(thunk_rva=identities[name],thunk_hex=thunk,iat_rva=imports[name],sdk_export_rva=address)
    shared.sdk.copy_edges()
    return dict(route=profile['route'],image_sha256=digest(image),records=records,
                metadata=metadata(rows,identities),sdk_edges=edges,actual_body_byte_mutations_rejected=count,
                rust_incoming_edges_reconciled=False,loaded_application_iat_proven=False,
                public_output_transactional=False,whole_image_qualified=False)


def collect(base,raw,spec_raw,mutate=False):
    rows=shared.catalog(raw)[1:];spec=specification(spec_raw)
    require([r['route'] for r in rows]==[p['route'] for p in spec['profiles']],'all non-bounded sequential routes')
    wrapper=(base/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes()
    sdk=(base/'sdk-system32-review/vertdll.dll').read_bytes()
    shared.sdk.sdk_review.inspect(sdk)
    records=[]
    for row,profile in zip(rows,spec['profiles']):
        data,image=(base/row['object']).read_bytes(),(base/row['image']).read_bytes()
        require(digest(data)==row['object_sha256'] and digest(image)==row['sha256'],'saved transport input identity')
        records.append(inspect(data,image,wrapper,sdk,profile,spec['templates'],mutate))
    return dict(schema=1,date='2026-10-05',status='SAVED_FAMILY_TRANSPORT_BINDINGS',records=records,
                templates_sha256=SPEC_HASH,unique_templates=len(spec['templates']),sdk_sha256=digest(sdk),
                independently_verified=False,native_run_added=False,release_gate_changed=False,
                worker_semantics_inferred=False,whole_image_qualified=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path)
    p.add_argument('--catalog',type=Path,default=shared.CATALOG);p.add_argument('--templates',type=Path,default=SPEC)
    p.add_argument('--mutate',action='store_true');p.add_argument('--output',type=Path)
    args=p.parse_args();result=collect(args.saved_directory,args.catalog.read_bytes(),args.templates.read_bytes(),args.mutate)
    result['source_sha256']={n:digest(Path(__file__).with_name(n).read_bytes()) for n in
        ('windows_enclave_route_transport.py','test-windows-enclave-route-transport.py')}
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
