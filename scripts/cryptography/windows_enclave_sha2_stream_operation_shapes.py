"""Instruction-level landmarks for the saved scalar owner-operation review."""
import windows_enclave_sha2_stream_operations as r

# These are interpreted instruction sequences, checked independently of body hashes.
LANDMARKS = {
    r.BEGIN:((0x12,'488d4c24204531c9e800000000'),
             (0x38,'488d57ff4883fa067230488d8700eeffff483d01feffff0f92c2'
                   '4881ff80110000410f94c031c04108d0756d'),
             (0x64,'c1e71081e70000ff0183cf0689fa89d0c1e8106683faff7454'),
             (0x7d,'8996de040000488d4c24204189c0e800000000'),
             (0x90,'488d7e480fb646483cff741731c93c060f93c1488d0449488d0c0748ffc1e800000000'),
             (0xb3,'488d54242041b8960400004889f9e800000000c686e204000001b0ff'),
             (0xd1,'f6c101755a')),
    r.UPDATE:((0x17,'488d4c242041b101e800000000'),
              (0x3e,'0fb646484883f8060f87a6000000'),
              (0x5c,'488d4e494889da4989f8e800000000eb0f488d4e494889da4989f8e800000000'),
              (0x7c,'89c1b0ffb30384c9746040f6c5017558'),
              (0xfc,'488d4e4ce95bffffff')),
    r.FINISH:((0x19,'488d4c244041b101e800000000'),
              (0x3b,'440fb6b424c0090000488b7424404885db744d'),
              (0x4e,'418d4effb00480f9070f87400100004180fe077723'),
              (0x63,'488d43ffb2ff4489f1d2ea4801f84889c1e80000000089c1b00483f9010f8517010000'),
              (0x86,'410fb6c6488d04d84883c0f84889d948c1e908eb14'),
              (0x9b,'b0044584f60f85f700000031db31c931c04531f6'),
              (0xaf,'894c24294889ca48c1ea308854242f48c1e92066894c242d4889442430'
                    '448874243848897c2420885c2428'),
              (0xda,'0fb786de0400004883f806771e'),
              (0x113,'0fb786e004000089c1c1e90383e0076683f8016683d9ffb0036683f940776b'),
              (0x13c,'0fb65e48440fb67649c64648ff80fbff744d488d564a488d8c24dc040000'
                     '41b894040000e800000000889c24da0400004488b424db040000'),
              (0x174,'488d8c24da040000488d5424204989f04989f9e8000000003cff750d'
                     'c686e204000002b0ffeb62b00240f6c501755a')),
    r.REHASH:((0x1a,'488d8c248800000041b102e800000000'),
              (0x4e,'0fb786de0400003dffff00007479'),
              (0x63,'498d7eff4883ff067235498d9600eeffff4881fa01feffff0f92c2'
                    '4981fe80110000410f94c031db4108d0754c'),
              (0x90,'41c1e6104181e60000ff014183ce064489f789fbc1eb106683ffff742f'),
              (0xed,'0fb7d1c1ea0389c883e0076683f8016683daffb0036683fa410f83ee010000'),
              (0x10c,'4189c84180e007410fb6c0bd080000000f45e8b0046685c90f84d0010000'),
              (0x12a,'440fb7f24584c07422498d46ffb2ff89e9d2ea4801f04889c1e800000000'
                     '89c1b00483f9010f85a5010000'),
              (0x189,'0f57c00f294424700f294424600f294424500f29442440'),
              (0x1ed,'0f57c00f294424700f294424600f294424500f29442440'),
              (0x246,'4c8dbc24880000004c89f989fa4189d8e800000000488d5424204c8d442440'
                     '4c89f94d89f1e8000000003cff7573'),
              (0x274,'41bf40000000ba400000004889f1e800000000'),
              (0x2c7,'4c8d4424404889f14c89fa4d89f1e80000000089c1b00580f9ff0f848e000000'),
              (0x2e7,'488d4c2440ba4000000089c7e80000000089f841f6c4017563'),
              (0x375,'89bede040000488d4c2440ba40000000e800000000b0ffebd5')),
    r.EXPORT:((0x13,'488d4c242841b102e800000000'),
              (0x39,'0fb786de0400004883f8060f8722010000'),
              (0x5a,'ba1c0000004883ff010f8487000000e9fe000000'),
              (0x6e,'ba1c0000004883ff057477e9ee000000'),
              (0x7e,'ba300000004883ff037467e9de000000'),
              (0x8e,'ba400000004883ff047457e9ce000000'),
              (0x9e,'ba200000004883ff027447e9be000000'),
              (0xae,'ba200000004883ff067437e9ae000000'),
              (0xbe,'0fb786e00400004889c14881c9001000004839cf0f8594000000'),
              (0xd8,'89c2c1ea0383e0076683f8014883daffb0036683fa407714'),
              (0xf0,'4889f1e80000000089c1b00585c90f84ce000000'),
              (0x104,'f6c3010f851d010000'),(0x16c,'f6c301740731c0e9b2000000')),
}
COPY_SITES = {r.BEGIN:((0xd8,32,3),),r.UPDATE:((0x8c,32,3),),r.FINISH:((0x1a5,64,3),),
              r.REHASH:((0x302,136,3),),r.EXPORT:((0x10f,40,3),(0x178,40,3),(0x1d2,40,0))}
# Admission discriminant must propagate the already-cleaned error, never continue execution.
BRANCHES = {r.BEGIN:((0x27,'75',0x33),(0x2e,'e9',0x130)),
            r.UPDATE:((0x2d,'75',0x39),(0x34,'e9',0xe6),(0xf8,'74',0x8c)),
            r.FINISH:((0x2f,'75',0x3b),(0x36,'e9',0x1fd)),
            r.REHASH:((0x37,'75',0x46),(0x41,'e9',0x363)),
            r.EXPORT:((0x28,'75',0x34),(0x2f,'e9',0x22a))}


def copy_shape(name,stack,phase):
    r.require(name in COPY_SITES and stack in (32,40,64,136) and phase in (0,3),'operation copy shape')
    disp = bytes([stack]) if stack < 128 else stack.to_bytes(4,'little')
    lea = bytes.fromhex('488d4c24' if stack < 128 else '488d8c24')+disp
    load = bytes.fromhex('0fb64424' if stack < 128 else '0fb68424')+disp
    add = bytes.fromhex('4883c1')+bytes([stack+1]) if stack < 128 else bytes.fromhex('4881c1')+(stack+1).to_bytes(4,'little')
    raw = bytes.fromhex('488d5648')+lea+bytes.fromhex('41b896040000e800000000c64648ff')
    if name == r.UPDATE:
        raw = bytes.fromhex('488d7e48')+lea+bytes.fromhex('41b8960400004889fae800000000c607ff')
    raw += load+bytes.fromhex('3cff74')+bytes([24 if stack < 128 else 27])
    raw += bytes.fromhex('31c93c060f93c1488d0449488d0c04')+add+bytes.fromhex('e800000000')
    raw += bytes.fromhex('ba400000004889f1e80000000066c786de040000ffffc686e2040000')+bytes([phase])
    return raw


def instructions(name,code):
    for at,h in LANDMARKS[name]:
        raw = bytes.fromhex(h);r.require(code[at:at+len(raw)] == raw,'operation admission/dataflow instruction')
    for at,stack,phase in COPY_SITES[name]:
        raw = copy_shape(name,stack,phase)
        r.require(code[at:at+len(raw)] == raw,'complete operation take/wipe/clear/phase path')
    for at,h,target in BRANCHES[name]:
        op = bytes.fromhex(h);width = 4 if op == b'\xe9' else 1
        disp = code[at+len(op):at+len(op)+width]
        r.require(code[at:at+len(op)] == op and len(disp) == width and
                  at+len(op)+width+int.from_bytes(disp,'little',signed=True) == target,'operation branch destination')
