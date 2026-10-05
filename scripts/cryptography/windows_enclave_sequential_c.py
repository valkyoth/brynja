"""Bind shared sequential C scaffolding across saved images, not their workers.

Offline author inspection only. Complete COFF function sections and chained PE
runtime extents are required; an entry-only fragment is insufficient.
"""
import argparse
import hashlib
import json
from pathlib import Path

import windows_enclave_caller_binding as caller
import windows_enclave_sdk_return as sdk

require = caller.require
CATALOG = Path(__file__).resolve().parents[2] / 'assurance/windows-protection-observations/sequential-c-inputs-20261005.json'
CATALOG_SHA256 = 'c6585463c9e930cd9d8eacf47abdf308cd7b5af65f10c1b5a6a5622849b5895a'
WRAPPER = '9eaba4a1d7ed3e7e180ff915865e294eaee86fa4a0fc4b567bac77f6b2fb25b8'
BODIES = {
    'PublicLockedAdmit': (604,46,'669e46ed7445b65b9bae313c3040e98872ed621b82c2ab98182ab7630c3cb387',
                          'f4f7632ee227f8282d18449c32f0d476151913373a9cbe2ec660bf5e420433d9'),
    'PublicLockedFinish': (111,4,'6ce889882a081e3c1eca1fa62282be1876eaac9f5d53e95fa367b58830e0f3f6',
                           '4b053b2f66afc83d68d38b87d72afdfaa6ca674a1da0b3b584f6043a12eba93c'),
    'PublicGuardRestore': (230,18,'676fb391a0a2b23f3fa173844f5463aeb3e8d0b99da2b0c110849a4f02ad6cbf',
                           '2dcf0c996d8ce3b5ed7b576d8c07943e40d75f6420dc9ccf03002a5958dfab0c'),
    'PublicRustBody': (870,63,'50b2f7a2167340cfe40bd34d8cc7086109200832d827467055ea20c8f764a5c0',
                       '1545c05f626156a248ac7979e59cd4e9307faf15627cc0147b6db60ea15712c9'),
}
# Selected normal-control landmarks. Whole-body pins remain mandatory; these
# checks expose the inspected decisions rather than pretending to be a decoder.
LANDMARKS = (
    ('PublicLockedAdmit',0x6d,'483d00000100'),
    ('PublicLockedAdmit',0x79,'48f7c1ff0f0000'),
    ('PublicLockedAdmit',0x86,'4881f900100000'),
    ('PublicLockedAdmit',0xe6,'ba00100000488bcb41b801000000'),
    ('PublicLockedAdmit',0x124,'833d0000000004c7050000000001000000'),
    ('PublicLockedAdmit',0x16e,'833d0000000004c7050000000001000000'),
    ('PublicLockedFinish',0x4d,'48397c243074028bfb85ff480f45de'),
    ('PublicGuardRestore',0x49,'c7050000000000000000'),
    ('PublicGuardRestore',0x9c,'c7050000000000000000'),
    ('PublicRustBody',0xa8,'ba0030000033c9448bc241b904000000'),
    ('PublicRustBody',0x1d2,'4883f8010f854b010000'),
    ('PublicRustBody',0x28f,'4883fe030f858e0000004883f8040f8584000000'),
    ('PublicRustBody',0x2a3,'891d00000000'),
    ('PublicRustBody',0x2b7,'0fb68c180010000048ffc3400af94881fb00100000'),
    ('PublicRustBody',0x2ce,'4084ff'),
    ('PublicRustBody',0x2d3,'48c7050000000071000000'),
    ('PublicRustBody',0x2e0,'b90a000000'),
    ('PublicRustBody',0x2f5,'85c0750d'),
    ('PublicRustBody',0x30b,'85c07518'),
    ('PublicRustBody',0x32e,'488b7c2458488b742450488b5c2440'),
    ('PublicRustBody',0x360,'4883c4305dc3'),
)
BRANCHES = (
    ('PublicLockedFinish',0x2f,0x74,0x54),('PublicLockedFinish',0x4b,0x74,0x54),
    ('PublicGuardRestore',0x34,0x75,0x49),('PublicGuardRestore',0x83,0x75,0x9c),
    ('PublicRustBody',0x2cc,0x72,0x2b0),('PublicRustBody',0x2d1,0x74,0x2e0),
    ('PublicRustBody',0x2de,0xeb,0x327),('PublicRustBody',0x304,0xeb,0x327),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def catalog(raw):
    require(digest(raw) == CATALOG_SHA256,'saved sequential catalog identity')
    rows = json.loads(raw)
    require(len(rows) == 18 and len({r['route'] for r in rows}) == 18 and
            len({r['sha256'] for r in rows}) == 18,'distinct sequential image population')
    return rows


def check_body(name,code,refs):
    size,count,body_hash,ref_hash = BODIES[name]
    require(len(code) == size and digest(code) == body_hash,'complete sequential C body')
    require(len(refs) == count and digest(encoded(refs)) == ref_hash,'complete sequential C relocations')


def check_instructions(bodies):
    require(set(bodies) == set(BODIES),'sequential instruction population')
    for name,offset,hexcode in LANDMARKS:
        code = bytes.fromhex(hexcode)
        require(bodies[name][offset:offset+len(code)] == code,'sequential C instruction landmark')
    for name,offset,opcode,target in BRANCHES:
        branch = bodies[name][offset:offset+2]
        require(len(branch) == 2 and branch[0] == opcode and
                offset+2+int.from_bytes(branch[1:],'little',signed=True) == target,'sequential C branch')


def reconcile(records,wrapper,imports):
    require(set(records) == set(BODIES),'sequential C entry population')
    identities = dict(wrapper['global_target_rvas'])
    for name,record in records.items():
        size,count,_,_ = BODIES[name]
        require(record['image_sha256'] == wrapper['image_sha256'],'same sequential image')
        require(record['size'] == size and len(record['references']) == count,'not an entry-only fragment')
        require(record['rva'] == wrapper['call_target_rvas'][name],'same wrapper callee')
        for symbol,target in record['reference_targets'].items():
            require(symbol not in identities or identities[symbol] == target,'shared C symbol agreement')
            identities[symbol] = target
            if symbol.startswith('__imp_'):
                require(imports.get(symbol[6:]) == target,'named sequential SDK import')
    return identities


def inspect(data,image,wrapper):
    require(digest(wrapper) == WRAPPER,'tested sequential wrapper object')
    for name in BODIES:
        check_body(name,*caller.function(data,name))
    check_instructions({name:caller.function(data,name)[0] for name in BODIES})
    # bind(), unlike the handler/funclet selector, covers the complete section
    # and rejects incomplete, overlapping, gapped or unrelated unwind chains.
    records = {name:caller.bind(data,image,name) for name in BODIES}
    wrap = caller.pe.bind(wrapper,image,'PublicLockedFrame')
    imports = sdk.imports(image)['vertdll.dll']
    identities = reconcile(records,wrap,imports)
    compact = {}
    for name,r in records.items():
        compact[name] = dict(rva=r['rva'],bytes=r['size'],references=len(r['references']),
                             runtime_fragments=[dict(start=f['start'],end=f['end'],
                                                     stack_bytes=f['stack_bytes'],chain=f['chain'])
                                                for f in r['unwind']])
    return dict(image_sha256=digest(image),object_sha256=digest(data),entries=compact,
                wrapper_rva=wrap['rva'],reference_targets=identities,
                retained_worker_rva=identities['RetainedWork'],callee_semantics_qualified=False,
                whole_image_qualified=False)


def collect(base,raw,wrapper):
    records = []
    for row in catalog(raw):
        data,image = (base/row['object']).read_bytes(),(base/row['image']).read_bytes()
        require(digest(data) == row['object_sha256'],'saved sequential C object identity')
        require(digest(image) == row['sha256'],'saved sequential image identity')
        records.append(dict(route=row['route'],**inspect(data,image,wrapper)))
    return dict(schema=1,date='2026-10-05',status='SAVED_SHARED_SEQUENTIAL_C_BINDINGS',
                catalog_sha256=CATALOG_SHA256,wrapper_object_sha256=WRAPPER,
                images=len(records),complete_function_bindings=len(records)*len(BODIES),
                unique_template_bytes=sum(s[0] for s in BODIES.values()),
                templates={name:dict(bytes=s[0],references=s[1],body_sha256=s[2],references_sha256=s[3])
                           for name,s in BODIES.items()},records=records,
                shared_template_implies_shared_callee_semantics=False,
                worker_review_transferred=False,whole_image_qualified=False,
                native_run_added=False,release_gate_changed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('saved_directory',type=Path)
    parser.add_argument('--catalog',type=Path,default=CATALOG)
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    wrapper = (args.saved_directory/'register-cleanup-nospill/baseline/window_rust_x64.obj').read_bytes()
    result = collect(args.saved_directory,args.catalog.read_bytes(),wrapper)
    sources = ('windows_enclave_sequential_c.py','test-windows-enclave-sequential-c.py',
               'windows_enclave_caller_binding.py','windows_enclave_caller_unwind.py',
               'windows_enclave_wrapper_binding.py','windows_enclave_sdk_return.py')
    result['source_sha256'] = {n:digest(Path(__file__).with_name(n).read_bytes()) for n in sources}
    text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
