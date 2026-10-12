"""Bind the separate 08A transport-data image; not an OS/SDK cleanup proof."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import windows_enclave_resident_review as resident
import windows_enclave_transport_data as data
import windows_enclave_transport_probe as probe

require,bridge = resident.require,resident.bridge
digest = lambda raw: hashlib.sha256(raw).hexdigest()
PINS = {
    'transport_identity': ('094483d107f53cca02c99b885217408d6be5680880462365071f9abca9818955',
        '4efd8b862ef3a9181f67863f1a308519c71dbfe207e708f4a84c85f3947058dc'),
    'isolated_text_sdk': ('e1f4e0f0ed8299658ddbbe83e9a948059c3f63036af9e26c20b23d603f425741',
        '777a729717120ea7a0168671fb621365e3929a88861f535dcbb7794331b5a166'),
    'PublicTransportIdentity': ('2c88e3a59400aa075757db4bb206971d355180bd38e262d507cca409b02f2fcd',
        'ba945c571d7fae216548644096beffd704425f1e27f61d62cd30733db3971e78'),
}


def bind(obj,image,name,rva):
    raw,refs,targets = bridge.bind(obj,image,name,rva)
    require((digest(raw),digest(json.dumps(refs,sort_keys=True).encode()))==PINS[name],
            'complete reviewed transport body and references '+name)
    return dict(rva=rva,size=len(raw),reference_targets=targets)


def root_bind(obj,image):
    name='PublicIsolatedSha256'
    rva=resident.exported(image,name)
    raw,refs,targets=bridge.bind(obj,image,name,rva)
    # Exact original root instructions and relocations except the two reviewed
    # identity calls. Do not expand the old checker or alter its saved evidence.
    changed=[r for r in refs if r['symbol']=='transport_identity']
    require([r['offset'] for r in changed]==[151,233],'two exact identity call edges')
    normalized=[r|{'symbol':'isolated_sdk'} if r in changed else r for r in refs]
    require((digest(raw),digest(json.dumps(normalized,sort_keys=True).encode()))==resident.PINS[name],
            'original resident lifecycle with only identity-call substitution')
    return raw,refs,dict(rva=rva,size=len(raw),reference_targets=targets)


def constants(image,identity,text_identity,saved_sdk):
    parts=data.reference(saved_sdk)
    rows,_=bridge.caller.pe.linked(image)
    offset,=struct.unpack_from('<I',image,60)
    base,=struct.unpack_from('<Q',image,offset+48)
    targets=identity['reference_targets']
    table=data.diagnostic.extract(rows,targets['sdk_data'],72,False)
    actual={}
    for (name,(rva,size,_)),row in zip(data.SPECS.items(),struct.iter_unpack('<QQQ',table)):
        require(row[:2]==(rva,size) and row[2]>=base,'exact ordered range descriptor')
        expected=data.diagnostic.extract(rows,row[2]-base,size,False)
        require(expected==parts[name],'complete embedded expected data '+name)
        actual[name]=dict(rva=rva,bytes=size,expected_rva=row[2]-base,sha256=digest(expected))
    sdk_rows,_=bridge.caller.pe.linked(saved_sdk)
    expected_text=data.diagnostic.extract(sdk_rows,0x1000,0x1dc4b,True)
    embedded=data.diagnostic.extract(rows,text_identity['reference_targets']['sdk_expected'],len(expected_text),False)
    require(embedded==expected_text,'entire embedded expected SDK text')
    for record in (identity,text_identity):
        names=[v for k,v in record['reference_targets'].items() if k.startswith('??_C@')]
        require(len(names)==1 and data.diagnostic.extract(rows,names[0],24,False)==
                'vertdll.dll\0'.encode('utf-16le'),'exact loaded SDK module name')
    return actual


def compute(directory,image,obj,root,text):
    """Rebind/recompose the actual new image, rather than reusing an old receipt."""
    workers,review=resident.workers,resident.review
    members=workers.chain.w.archive.members((directory/'normal_rust.lib').read_bytes())
    selected=[d for n,d in members.items() if n.startswith('isolated_sha256.')]
    require(len(selected)==1,'one Rust canary object')
    rust=selected[0]
    functions,records=workers.bind(rust,image)
    require(len(functions)==7 and 'IsolatedSha256' in functions,'seven complete Rust functions')
    wrapper=workers.catalog.sdk.pe.bind((directory/'window.obj').read_bytes(),image,'PublicLockedFrame')
    raw,refs,adapter=resident.bind(obj,image,'PublicRustBody',wrapper['call_target_rvas']['PublicRustBody'])
    require(adapter['reference_targets']['IsolatedSha256']==records['IsolatedSha256']['rva'],
            'actual SDK-free compute tail')
    for name in ('busy','active','admitted','stage_admitted','stage_region','body_calls','request'):
        require(adapter['reference_targets'][name]==root['reference_targets'][name],'same phase/storage '+name)
    functions['PublicRustBody']=(raw,refs,False)
    records['PublicRustBody']=adapter
    memory=workers.catalog.memory.inspect(image,records['IsolatedSha256']['reference_targets']['memset'])
    runtime={name:dict(rva=memory['frames'][role]['rva'],bytes=memory['frames'][rep]['fixed_frame_bytes'])
        for name,role,rep in [('memcpy','copy','copy_rep'),('memset','fill','fill_rep')]}
    instructions,nodes=review.decode.parse(text),{}
    for name,(_,refs,_) in functions.items():
        decoded=review.decode.body(image,records[name],instructions)
        tables=[] if name=='PublicRustBody' else review.decode.destinations(rust,image,name,records[name],refs)
        nodes[name]=dict(incoming_bytes=32,scans=review.flow.inspect(decoded,records[name]['rva'],tables,set()))
    population=review.assign(functions,records,nodes,runtime,None)
    closure=resident.original.compute_closure(nodes,['PublicRustBody'])
    bound=review.composition.compose(nodes)['PublicRustBody']
    require(all(v['finite_transitive_bound_proven'] and v['complete_stack_bytes']==2544
                for v in bound.values()),'bounded new-image SDK-free compute')
    return dict(**population,closure=closure,normal_compute_bound=bound,wrapper=wrapper,
                entry_adapter=adapter,memory_runtime=memory)


def inspect(directory,text,saved_sdk):
    image=(directory/'signed.dll').read_bytes()
    obj=(directory/'normal.obj').read_bytes()
    raw,refs,root=root_bind(obj,image)
    targets=root['reference_targets']
    identity=bind(obj,image,'transport_identity',targets['transport_identity'])
    text_identity=bind(obj,image,'isolated_text_sdk',identity['reference_targets']['isolated_text_sdk'])
    public=bind(obj,image,'PublicTransportIdentity',resident.exported(image,'PublicTransportIdentity'))
    require(all(public['reference_targets'][n]==targets[n]
                for n in ('busy','active','stage_region','transport_identity')),'same diagnostic and real entry')
    imports=bridge.sdk.imports(image)['vertdll.dll']
    for body in (identity,text_identity):
        for name,address in body['reference_targets'].items():
            if name.startswith('__imp_'): require(imports[name[6:]]==address,'actual SDK identity import '+name)
    phases=resident.lifecycle(image,root,raw,refs,text)
    code=resident.review.decode.body(image,root,resident.review.decode.parse(text))
    dom=resident.control_flow(code)
    require(all(150 in dom[site] for site in (175,534,576,638)),
            'identity before descriptor/payload admission and publication')
    retirement=resident.retire((directory/'retire.obj').read_bytes(),image,targets['IsolatedRetirePage'])
    _,_,notify=resident.bind(obj,image,'stage_notify',targets['stage_notify'])
    require(notify['reference_targets']['__imp_CallEnclave']==imports['CallEnclave'],'actual callback import')
    for name in ('stage_region','host_callback'):
        require(notify['reference_targets'][name]==targets[name],'same notify storage')
    for name in ('VirtualAlloc','VirtualProtect','VirtualFree'):
        require(targets['__imp_'+name]==imports[name],'actual storage import')
    rows,unwind=bridge.caller.pe.linked(image)
    for name in ('EnclaveCopyIntoEnclave','EnclaveCopyOutOfEnclave'):
        bridge.sdk.thunk(rows,unwind,targets[name],imports[name])
    build=json.loads((directory/'build.json').read_text())
    require(build['status']=='PUBLIC_TRANSPORT_DATA_CANARY_BUILD_ONLY' and
            build['dirty_staging_mutant'] is False,'exact transport-data variant')
    root_path=Path(__file__).resolve().parents[2]
    for name,expected in build['source_sha256'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,'relative build source')
        require(digest((root_path/name).read_bytes())==expected,'current build source '+name)
    native=json.loads((directory/'native-final.json').read_text())
    require(native['image_sha256']==digest(image),'same native image')
    probe.validate(native['identity_samples'])
    probe.resident.validate(native['cases'])
    return dict(schema=1,status='AUTHOR_LOADED_TRANSPORT_STATUS_DATA_IDENTITY_CHECKPOINT',
        image_sha256=digest(image),sdk_sha256=digest(saved_sdk),disassembly_sha256=digest(text.encode()),
        root=root,identity=identity,text_identity=text_identity,diagnostic_export=public,
        embedded_data=constants(image,identity,text_identity,saved_sdk),lifecycle=phases,retirement=retirement,
        compute=compute(directory,image,obj,root,text),native_cases=len(native['cases']),
        identity_observations=sum(map(len,native['identity_samples'])),
        loaded_status_data_identity_checked=True,os_return_registers_qualified=False,
        formatter_and_exception_transitive_payload_proof=False,whole_image_qualified=False,
        completion_package_closed=False,production_qualified=False,
        source_sha256={p.name:digest(p.read_bytes()) for p in sorted(
            {Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
            |{Path(__file__)})})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--sdk',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(inspect(args.directory,(args.directory/'disassembly.txt').read_text(),
                            args.sdk.read_bytes()),indent=2))
