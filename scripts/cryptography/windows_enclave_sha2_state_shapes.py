"""Interpreted machine-code landmarks for the saved scalar SHA-2 state."""
import windows_enclave_sha2_stream_operations as ops

NEW,FINISH = ops.NEW,ops.STATE_FINISH
PINS = {
    NEW:(3100,'cf7a022acf68686f4575b75c3285ecb66247cc2578f8c8c7704578cdc028fe08',
         '895a36652574b3c48af1b9741af0f49c4a14c036a74d8c6c6cfdf8d6669c4470'),
    FINISH:(2738,'2a5b7c1448353f8c693e6f9bfdca0ac0fa2e73e6b7d5a7023e4d84be28b032a4',
            '83baf26f6b2d094c915acc1a718a883b28081242115c9419c5e1d0b0679e861d'),
}
TABLE_SITES = {NEW:((36,0),),FINISH:((63,0),(1156,84),(1363,140),(1570,112),(1777,56),
                                    (1887,196),(2088,168),(2692,28))}
TABLES = {NEW:(49,1248,636,942,330,1530,1836),FINISH:(76,527,289,408,170,621,740)}
# Cleanup tables skip the already consumed variant, not every other active variant.
for consumed in (6,5,4,3,2,1,0):
    TABLES[FINISH] += tuple(2716 if i == consumed else 2101 if i == 6 else 2705 for i in range(7))

LANDMARKS = {
    NEW:((0,'4157415641554154565755534881ecd80400000f29b424c00400004989ce0fb7c2'
            '488d0d00000000486304814801c8ffe0'),
         (0xb74,'488d8c24c000000041b88003000031d2e80000000041b800040000'
                '488b8c24b0000000488d9424c0000000e800000000'),
         (0xbf5,'664189460240b6064188360f28b424c00400004881c4d8040000'
                '5b5d5f5e415c415d415e415fc3')),
    FINISH:((0,'4157415641554154565755534881ec280500004c89cf4c89c34989d64889ce'
               '0f57c00f298424800000000f294424700f294424600f294424500fb601'
               '488d0d00000000486304814801c8ffe0'),
            (0x898,'488b7424404885f641b8010000004c0f45c64c8b7424484d89f14c0f44ce'
                   '4889d94889fae8000000003cff0f94c3f6db4885f6740b4889f14c89f2'
                   'e80000000080cb05488d4c2450ba40000000e80000000089d8e9ad010000'),
            (0x953,'488d8c2496000000410fb7c5c1e8034183e507664183fd016683d8ff0fb7c0'
                   '4c8964242048894424284c89f24189e84d89f9e800000000'),
            (0x98a,'0fb78c249400000089c8c1e8034531c089ca6683e207410f95c04101c0'
                   '450fb7c04983f8014983d0ff4983f840732e4a8d04044805d6040000'
                   'f6d980e107b2ffd2e24889c14531c0e8000000000fb7942494000000'
                   '89d0c1e80383e2076683fa016683d8ff6683f8407760440fb7f04c39f77257'),
            (0x9fe,'488d9424d6040000488d4c24504d89f0e8000000004c39f7753d'
                   '488d8c2496000000e800000000488d7424504889d94889fa4989f04989f9'
                   'e8000000003cff0f94c3f6db80cb054889f14889fae800000000e986feffff'),
            (0xa55,'488d4c24504889fae800000000488d8c2496000000e800000000'
                   '488d4c2450ba40000000e8000000000fb606488d0d1c000000'
                   '486304814801c8ffe048ffc64889f1e800000000b004'),
            (0xa9e,'4881c4280500005b5d5f5e415c415d415e415fc3'),
            (0x835,'4883c604e956020000')),
}


def spans(name):
    result = list(LANDMARKS[name])
    if name == NEW:
        for call in (183,461,767,1073,1380,1661):
            result.append((call-20,'488d9c24c000000041b8800300004889d931d2e800000000'))
            result.append((call+4,'41b8000400004889f94889dae800000000'))
    else:
        # Six named variants: copy their entire active workspace, then finalize.
        for at in (76,170,289,408,527,621):
            result.append((at,'488d5601488d8c249400000041b892040000e800000000'))
        result.append((740,'488d5602488d8c249400000041b894040000e800000000'))
        # Six early failures wipe the copied workspace regardless of staging length.
        for at in (0x3ef,0x4be,0x58d,0x65c,0x72b,0x7f4):
            result.append((at,'4885ff740d488d4c24504889fae800000000488d8c2494000000e800000000'))
        # All six named write-secret results are followed by the workspace wipe.
        for call in (1122,1329,1536,1743,1977,2187):
            result.append((call-9,'0fb66c24384c89e1e800000000'))
        # Every named error and the common success path clear all 64 staging bytes.
        for at in (0x46f,0x53e,0x60d,0x6dc,0x74a,0x813,0x8db):
            result.append((at,'488d4c2450ba40000000e800000000'))
        # Fixed-output length at write_secret: ordinary 224,256,384,512,512/224,/256.
        for call,width in ((1109,28),(1316,48),(1523,64),(1730,32),(1964,28),(2174,32)):
            result.append((call-7,'41b8'+width.to_bytes(4,'little').hex()+'e800000000'))
    return result


def instructions(name,code):
    for at,h in spans(name):
        raw = bytes.fromhex(h)
        ops.require(code[at:at+len(raw)] == raw,'state construction/cleanup instruction')


def width_model(t):
    """Arithmetic cross-check for admitted t, not execution of the artifact."""
    ops.require(type(t) is int and 1 <= t <= 511 and t != 384,'admitted general-t parameter')
    n = (t>>3)+int((t & 7) != 0)
    return n,n-1,(255 << ((-t) & 7)) & 255
