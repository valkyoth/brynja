"""SHA-NI receiver length preconditions, dispatch and explicit public export."""
import windows_enclave_sha_ni_lifecycle as life

shared,obj = life.shared,life.workers.obj
require,digest = life.require,life.digest
IR_HASH = '09ae62288bf0e8c150242cd11d7163ab52af1f8b1f0fd1d748f1a3901f0dada4'
TABLE = bytes.fromhex('f50000004d0100002e0100004b0100000f0100006d010000'
                      'a1010000df010000c9010000da010000c1010000fc0100000d020000')
TARGETS = (241,325,290,315,251,341,413,471,445,458,429,484,497)
# Complete operand/branch bytes at the reviewed boundaries, not merely opcodes.
SEGMENTS = (
    (24,'4c8dbf000400004531e441b94000000031c94c89fa4989c0e80000000085c0756c'),
    (80,'488b5c24604881fb0004000077444885db74194c8b442468b9010000004889fa4989d9e80000000085c07526'),
    (131,'488d4c24404c89f24d89f8e800000000807c244001751c4889f1e800000000'),
    (182,'4531e4483b5c24600f859f000000488b4424484883c0f54883f8050f879c000000'),
    (215,'488b5424504c8b442458488d0d00000000486304814801c8ffe0'),
    (241,'4889f1e800000000eb62'),
    (251,'4d89c6488d4c24304989d04889f241b102e8000000000fb65c243880fb02755c0fb6442430eb3b'),
    (290,'0fb6442470884424204889f14989f84989d9e800000000eb22'),
    (315,'4889f1e800000000eb18'),
    (325,'4889f14989f84989d9e800000000eb08'),
    (341,'4889f1e8000000003cff410f94c44889f14489e2e800000000e932ffffff31c0ebe6'),
    (375,'488b7c24300fb787000800004883f8060f87ca000000488d0d18000000486304814801c8ffe0'),
    (413,'ba1c0000004983fe017478e9aa000000ba1c0000004983fe057468e99a000000'),
    (445,'b0034983fe03747fe98d000000b0034983fe047472e980000000'),
    (471,'ba200000004983fe02743eeb73ba200000004983fe067431eb66'),
    (497,'0fb787020800000fb7d04889d14881c9001000004939ce754dc1ea0383e0076683f8014883daffb0036683fa207724'),
    (544,'488d8fd0070000e80000000089c1b00585c97510488b8ff0070000e8000000003cff7424'),
    (580,'4889f989da89c7e80000000089f8e906ffffff4889f989dae80000000031c0e9f5feffff'),
    (616,'4889f9e800000000c6870408000000b0ffe9dffeffff'),
)


def instructions(code):
    for at,h in SEGMENTS:
        raw = bytes.fromhex(h)
        require(code[at:at+len(raw)] == raw, 'receiver readback/admission/export instruction')


def table_targets(raw,address,start):
    require(len(raw) == 52, 'six operation and seven identity entries')
    targets = tuple(address+(0 if at<24 else 24)+int.from_bytes(raw[at:at+4],'little',signed=True)-start
                    for at in range(0,52,4))
    require(targets == TARGETS, 'exact receiver dispatch destinations')
    return targets


def table(data,image,record):
    rows,symbols,selected,_,refs = obj.select(data,life.RECEIVE)
    refs = [r for r in refs if r['symbol'] == '.rdata']
    require([(r['offset'],r['addend'],r['trailing']) for r in refs] == [(228,0,0),(400,24,0)],
            'exact two receiver table operands')
    indices = {r['symbol_index'] for r in refs};require(len(indices) == 1,'same table section')
    symbol = symbols[indices.pop()]
    require(symbol['value'] == 0 and 1 <= symbol['section'] <= len(rows),'defined table')
    section = rows[symbol['section']-1]
    require(section['code'] == TABLE and section['flags'] & 0xe0000000 == 0x40000000,'readonly complete table')
    refs = obj.relocations(data,section,symbols)
    require(set(refs) == set(range(0,52,4)), 'complete table relocation population')
    for at,ref in refs.items():
        target = symbols[ref['symbol']]
        require(ref['kind'] == 4 and target['section'] == selected['section'] and
                target['value'] == 0 and target['name'] == '.text','table targets receiver only')
        require(int.from_bytes(TABLE[at:at+4],'little')-(at if at<24 else at-24)-4 == TARGETS[at//4],
                'object subtable destination')
    rows,_ = shared.caller.pe.linked(image);address = record['reference_targets']['.rdata']
    raw = life.bounded.mapping.mapped(rows,address,52)
    life.constants.constant(rows,address,raw)
    return raw,dict(rva=address,bytes=52,destinations=table_targets(raw,address,record['rva']))


def preconditions(raw):
    require(digest(raw) == IR_HASH,'saved SHA-NI compiler IR')
    lines = raw.decode('utf-8').splitlines()
    for suffix in ('6update','6finish'):
        declarations = [l for l in lines if l.startswith('define ') and '@'+life.PREFIX+suffix+'(' in l]
        require(len(declarations) == 1 and declarations[0].startswith('define internal fastcc ') and
                'i64 noundef range(i64 0, 1025) %3' in declarations[0], 'private bounded-input compiler precondition')
    return dict(sha256=digest(raw),private_update_finish_maximum_input=1024,
                standalone_length_checks_claimed=False,receiver_enforces_bound_before_dispatch=True)


def inspect(data,image,record,ir,mutate=False):
    code,_ = shared.caller.function(data,life.RECEIVE);instructions(code)
    raw,t = table(data,image,record);bounded_input = preconditions(ir);count = 0
    if mutate:
        for i in range(len(raw)):
            changed = bytearray(raw);changed[i] ^= 1
            try: table_targets(changed,t['rva'],record['rva'])
            except ValueError: count += 1
            else: raise AssertionError('accepted receiver table mutant')
    return dict(dispatch=t,compiler_preconditions=bounded_input,actual_table_byte_mutations_rejected=count,
                copied_header_bytes=64,payload_bound=1024,post_copy_authority_rechecked=True,
                export_host_bytes_rollback_claimed=False,request_decoder_semantics_qualified=False,
                state_operation_callees_qualified=False,whole_image_qualified=False)
