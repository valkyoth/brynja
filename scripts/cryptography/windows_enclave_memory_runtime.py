"""Saved scheduler memcpy/memset frame and dispatch review; author aid only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import windows_enclave_session_runtime as session
from windows_enclave_frame_geometry import Frame, Window, require

BODIES = {
    'copy_rep': (0xb710,16,'25b23c83d168ccbe2481d06e4096e25d14b8d1745a23fa1a009f3c023f2d533f'),
    'copy': (0xb720,1677,'e16a8525a5c6326ba266e7c9ce85720fe639dd512663f6635e45ae04eacc7b27'),
    'fill_rep': (0xbdd0,16,'b8721ef30a9f19d1d9aee591d1ccc36ad691dc4c7b9c04ac8e6e771202f9d9fe'),
    'fill': (0xbde0,908,'c425589d68efc92cc45d536e6078970c5ce1d32d9ab2d900e736e9917ae86c11'),
}
# The REP leaves have version-2 epilogue metadata. Bind it exactly without
# extending the intentionally version-1-only decoder or claiming unwind safety.
UNWIND = {
    'copy_rep': (0xf570,'020204000316000602600170',16),
    'copy': (0xf4f8,'01000000',0),
    'fill_rep': (0xf580,'020103000216000601700000',8),
    'fill': (0xf4f8,'01000000',0),
}
TABLES = {
    0xe900: (0xb752,0xb844,0xb798,0xb7cf,0xb84a,0xb82f,0xb820,0xb7a0,
             0xb83d,0xb805,0xb7f6,0xb780,0xb813,0xb7e0,0xb7b8,0xb760),
    0xe940: (0xba2a,0xba23,0xba15,0xba07,0xb9f9,0xb9e5,0xb9d1,0xb9bd,0xb9a9)+(0xba2a,)*7,
    0xe980: (0xbb6a,0xbb63,0xbb55,0xbb47,0xbb39,0xbb25,0xbb11,0xbafd,0xbae9)+(0xba2a,)*7,
    0xe9c0: (0xbcc6,0xbcbf,0xbcb1,0xbca3,0xbc95,0xbc87,0xbc79,0xbc6b,0xbc5d)+(0xbcc6,)*7,
    0xea00: (0xbe36,0xbe32,0xbe3f,0xbe2d,0xbe64,0xbe54,0xbe3b,0xbe29,
             0xbe8a,0xbe77,0xbe80,0xbe69,0xbe60,0xbe50,0xbe37,0xbe25),
    0xea40: (0xbfbf,0xbfb8,0xbfb1,0xbfaa,0xbfa3,0xbf99,0xbf8f,0xbf85,0xbf7b)+(0xbfbf,)*7,
    0xea80: (0xc07f,0xc078,0xc071,0xc06a,0xc063,0xc059,0xc04f,0xc045,0xc03b)+(0xc07f,)*7,
    0xeac0: (0xc167,0xc160,0xc159,0xc152,0xc14b,0xc144,0xc13d,0xc136,0xc12f)+(0xc167,)*7,
}
# Each index load is followed by addition of the image base and an indirect
# branch. Table entries are RVAs, not process addresses or writable callbacks.
DISPATCH = (
    ('copy',0xb744,0xe900,True), ('copy',0xb99b,0xe940,False),
    ('copy',0xbadb,0xe980,False), ('copy',0xbc4f,0xe9c0,False),
    ('fill',0xbe17,0xea00,True), ('fill',0xbf6d,0xea40,False),
    ('fill',0xc02d,0xea80,False), ('fill',0xc121,0xeac0,False),
)
RIP_READS = (
    ('copy',0xb723,'4c8d15',0,''), ('fill',0xbde6,'4c8d15',0,''),
    ('copy',0xb881,'833d',0x11060,'03'), ('copy',0xb8a0,'f605',0x118bc,'02'),
    ('copy',0xbb89,'f605',0x118bc,'02'), ('fill',0xbea6,'833d',0x11060,'03'),
    ('fill',0xbeb3,'4c3b05',0x11068,''), ('fill',0xbebc,'4c3b05',0x11070,''),
    ('fill',0xbec5,'f605',0x118bc,'02'), ('fill',0xbef5,'4c3b05',0x11070,''),
    ('fill',0xc090,'4c3b05',0x11068,''), ('fill',0xc099,'f605',0x118bc,'02'),
)
ANCHORS = (
    ('copy_rep',0xb710,'5756488bf9488bf2498bc8f3a45e5fc3'),
    ('fill_rep',0xbdd0,'578bc2488bf9498bc8f3aa498bc15fc3'),
    ('copy',0xb720,'488bc1'), ('copy',0xb740,'4983e00f'),
    ('copy',0xb856,'f30f6f0af3420f6f5402f0f30f7f09f3420f7f5401f0c3'),
    ('copy',0xb86d,'4e8d0c02483bca4c0f46c9493bc9'),
    ('copy',0xb88e,'4981f800200000'), ('copy',0xb897,'4981f800001800'),
    ('copy',0xb8ad,'c5fe6f02c4a17e6f6c02e0'),
    ('copy',0xb8c5,'4c8bc94983e11f4983e920492bc9492bd14d03c1'),
    ('copy',0xb966,'4881c1000100004881c2000100004981e8000100004981f800010000'),
    ('copy',0xb988,'4d8d481f4983e1e04d8bd949c1eb054983e30f'),
    ('copy',0xba23,'c4a17e7f6c01e0c5fe7f00c5f877c3'),
    ('copy',0xbb63,'c4a17e7f6c01e0c5fe7f000faef8c5f877c3'),
    ('copy',0xbb80,'4981f800080000'),
    ('copy',0xbb96,'f30f6f02f3420f6f6c02f0'),
    ('copy',0xbbae,'4c8bc94983e10f4983e910492bc9492bd14d03c1'),
    ('copy',0xbc3c,'4d8d480f4983e1f04d8bd949c1eb044983e30f'),
    ('copy',0xbcbf,'f3420f7f6c01f0f30f7f00c3'),
    ('copy',0xbcd0,'0f1012482bd14903c80f104411f04883e9104983e810'),
    ('copy',0xbd90,'0f11014883e9100f10041149ffc9'),
    ('copy',0xbda6,'0f11100f1101c3'),
    ('fill',0xbde0,'488bc14c8bc9'),
    ('fill',0xbded,'0fb6d249bb01010101010101014c0fafda66490f6ec3'),
    ('fill',0xbe10,'4983e00f4903c8'),
    ('fill',0xbe9a,'f30f7f01f3420f7f4401f0c3'),
    ('fill',0xbed2,'c4e37d18c0014c8bc94983e11f4983e920492bc9492bd14d03c1'),
    ('fill',0xbf43,'4881c1000100004981e8000100004981f800010000'),
    ('fill',0xbf5a,'4d8d481f4983e1e04d8bd949c1eb054983e30f'),
    ('fill',0xbfb8,'c4a17e7f4401e0c5fe7f00c5f877c3'),
    ('fill',0xc078,'c4a17e7f4401e0c5fe7f000faef8c5f877c3'),
    ('fill',0xc0a6,'4c8bc94983e10f4983e910492bc9492bd14d03c1'),
    ('fill',0xc10e,'4d8d480f4983e1f04d8bd949c1eb044983e30f'),
    ('fill',0xc160,'f3420f7f4401f0f30f7f00c3'),
)
BRANCHES = (
    ('copy',0xb72e,b'\x0f\x87',0xb850), ('copy',0xb854,b'\x77',0xb86d),
    ('copy',0xb87b,b'\x0f\x82',0xbcd0), ('copy',0xb888,b'\x0f\x82',0xbb80),
    ('copy',0xb8a7,b'\x0f\x85',0xb710), ('copy',0xbb90,b'\x0f\x85',0xb710),
    ('copy',0xb8bf,b'\x0f\x86',0xb988), ('copy',0xb8e0,b'\x0f\x86',0xb988),
    ('copy',0xb8ed,b'\x0f\x87',0xba40), ('copy',0xb982,b'\x0f\x83',0xb900),
    ('copy',0xbac2,b'\x0f\x83',0xba40), ('copy',0xbba8,b'\x0f\x86',0xbc3c),
    ('copy',0xbbc9,b'\x76',0xbc3c), ('copy',0xbc3a,b'\x73',0xbbd0),
    ('copy',0xbd9e,b'\x75',0xbd90),
    ('fill',0xbe07,b'\x0f\x87',0xbe90), ('fill',0xbe98,b'\x77',0xbea6),
    ('fill',0xbead,b'\x0f\x82',0xc090), ('fill',0xbecc,b'\x0f\x85',0xbdd0),
    ('fill',0xc0a0,b'\x0f\x85',0xbdd0), ('fill',0xbef3,b'\x76',0xbf5a),
    ('fill',0xbefc,b'\x0f\x87',0xbfd0), ('fill',0xbf58,b'\x73',0xbf10),
    ('fill',0xc018,b'\x73',0xbfd0), ('fill',0xc0c1,b'\x76',0xc10e),
    ('fill',0xc10c,b'\x73',0xc0d0),
)


def check_bodies(bodies):
    require(set(bodies)==set(BODIES),'complete memory runtime population')
    for n,(_,size,digest) in BODIES.items():
        require(len(bodies[n])==size and hashlib.sha256(bodies[n]).hexdigest()==digest,
                'reviewed memory runtime bytes: '+n)


def check_instructions(bodies):
    require(set(bodies)==set(BODIES),'memory runtime instruction population')
    for n,address,h in ANCHORS:
        o=address-BODIES[n][0]; b=bytes.fromhex(h)
        require(bodies[n][o:o+len(b)]==b,'memory runtime landmark')
    for n,address,op,target in BRANCHES:
        o=address-BODIES[n][0]; width=4 if len(op)==2 else 1
        end=o+len(op)+width
        require(bodies[n][o:o+len(op)]==op and BODIES[n][0]+end+
                int.from_bytes(bodies[n][end-width:end],'little',signed=True)==target,
                'memory runtime branch')
    for n,address,prefix,target,suffix in RIP_READS:
        o=address-BODIES[n][0]; p=bytes.fromhex(prefix); s=bytes.fromhex(suffix)
        end=o+len(p)+4+len(s)
        require(bodies[n][o:o+len(p)]==p and bodies[n][end-len(s):end]==s and
                BODIES[n][0]+end+int.from_bytes(bodies[n][o+len(p):o+len(p)+4],
                                                'little',signed=True)==target,'runtime RIP reference')
    for n,address,table,small in DISPATCH:
        o=address-BODIES[n][0]
        code=bytes.fromhex('478b8c82' if small else '478b9c9a')+struct.pack('<I',table)
        code+=bytes.fromhex('4d03ca41ffe1' if small else '4d03da41ffe3')
        require(bodies[n][o:o+len(code)]==code,'complete indexed dispatch')


def check_tables(rows):
    records={}
    for address,targets in TABLES.items():
        expected=struct.pack('<16I',*targets)
        record=session.setup.construction.constant(rows,address,expected)
        n='copy' if address<0xea00 else 'fill'
        require(all(BODIES[n][0]<=t<BODIES[n][0]+BODIES[n][1] for t in targets),
                'dispatch stays inside reviewed body')
        records[hex(address)]=record|dict(targets=targets)
    return records


def check_unwind(rows,functions):
    records={}
    for n,(unwind,h,frame) in UNWIND.items():
        rva,size,_=BODIES[n]
        found=[f for f in functions if f[0]<rva+size and rva<f[1]]
        require(found==[(rva,rva+size,unwind)],'memory helper exact runtime extent')
        code=bytes.fromhex(h)
        session.setup.construction.constant(rows,unwind,code)
        records[n]=dict(unwind_rva=unwind,bytes_hex=h,version=code[0]&7,
                        instruction_review_fixed_frame_bytes=frame,unwind_semantics_qualified=False)
    return records


def forward_spans(length,alignment,width):
    """Bounded vector-forward write-range model, NOT native helper execution."""
    require(type(length) is int and 33<=length<=65536 and type(width) is int and width in (16,32) and
            type(alignment) is int and 0<=alignment<width,'modeled vector-forward domain')
    cursor=0; remaining=length; spans=[(0,width),(length-width,width)]
    if remaining>8*width:
        cursor=width-alignment; remaining-=cursor
        while remaining>=8*width:
            spans.append((cursor,8*width)); cursor+=8*width; remaining-=8*width
    index=(remaining+width-1)//width
    require(0<=index<=8,'valid vector tail index')
    spans.extend((cursor+i*width,width) for i in range(max(0,index-1)))
    return spans,index


def geometry():
    w=Window(0,65536)
    body=Frame.enter(w,65504,168); root=Frame.enter(w,body.current,11160,32)
    new=Frame.enter(w,root.current,7736,32)
    spans=[]
    for n,pushes in (('copy_rep',16),('fill_rep',8)):
        spans.append(w.span(n+' saved caller GPRs',new.current-8-pushes,pushes))
    return dict(root_constructor_spans=spans,vector_paths_fixed_frame_bytes=0,
                rep_paths_are_tail_transfers=True,saved_register_slots_individually_erased=False,
                volatile_payload_registers_erased=False,maximum_transitive_depth_qualified=False)


def inspect(data,image,mutate=False):
    prior=session.inspect(data,image)
    root=session.setup.inspect(data,image)['entries']['new']
    require(root['reference_targets']['memcpy']==BODIES['copy'][0] and
            root['reference_targets']['memset']==BODIES['fill'][0],'actual root memory helper targets')
    rows,functions=session.cleanup.caller.pe.linked(image)
    bodies={n:session.executable(rows,rva,size) for n,(rva,size,_) in BODIES.items()}
    check_bodies(bodies); check_instructions(bodies)
    tables=check_tables(rows)
    frames=check_unwind(rows,functions)
    globals_=[]
    for rva,size in ((0x11060,4),(0x11068,8),(0x11070,8),(0x118bc,1)):
        matches=[r for r in rows if r['rva']<=rva and rva+size<=r['rva']+r['virtual_size']]
        require(len(matches)==1 and matches[0]['flags'] & 0x80000000 and
                not matches[0]['flags'] & 0x20000000,'mapped mutable nonexecutable runtime selector')
        globals_.append(dict(rva=rva,bytes=size,live_value_established=False,written_by_helpers=False))
    count=0; table_count=0
    if mutate:
        for n,body in bodies.items():
            for i in range(len(body)):
                b=bytearray(body); b[i]^=1
                try: check_bodies(bodies|{n:b})
                except ValueError: count+=1
                else: raise AssertionError('memory runtime body mutation escaped')
        for address in TABLES:
            index=next(i for i,r in enumerate(rows) if r['rva']<=address<r['rva']+r['virtual_size'])
            row=rows[index]
            for i in range(64):
                b=bytearray(row['code']); b[address-row['rva']+i]^=1
                changed=rows[:index]+[row|{'code':bytes(b)}]+rows[index+1:]
                try: check_tables(changed)
                except ValueError: table_count+=1
                else: raise AssertionError('actual memory dispatch table mutation escaped')
    return dict(schema=1,date='2026-10-05',status='AUTHOR_SELECTED_MEMORY_RUNTIME_REVIEW',
                object_sha256=prior['object_sha256'],image_sha256=prior['image_sha256'],
                bodies={n:dict(rva=s[0],bytes=s[1],sha256=s[2]) for n,s in BODIES.items()},
                frames=frames,tables=tables,mutable_selectors=globals_,geometry=geometry(),
                body_byte_mutations_rejected=count,table_byte_mutations_rejected=table_count,
                unreviewed_direct_callees=[],
                payload_registers_require_outer_return_cleanup=True,
                general_memmove_correctness_qualified=False,live_dispatch_values_qualified=False,
                whole_image_qualified=False,native_run_added=False,release_gate_changed=False,
                independently_verified=False,arbitrary_exception_cleanup_qualified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object',type=Path); parser.add_argument('image',type=Path)
    parser.add_argument('--mutate',action='store_true'); parser.add_argument('--output',type=Path)
    args=parser.parse_args(); result=inspect(args.object.read_bytes(),args.image.read_bytes(),args.mutate)
    sources={Path(m.__file__) for n,m in sys.modules.items() if n.startswith('windows_enclave_')}
    sources.update((Path(__file__),Path(__file__).with_name('test-windows-enclave-memory-runtime.py')))
    result['source_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)}
    text=json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text,encoding='utf-8')
    else: print(text,end='')
