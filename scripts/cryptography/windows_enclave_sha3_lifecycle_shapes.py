"""Reviewed scalar SHA-3 cancellation/destruction machine shapes, not all operations."""
PREFIX = '_RNvMs0_Csgp9hxIs16B4_11sha3_streamNtB5_5Owner'
QUARANTINE, CLEAR_OWNER, CANCEL = (PREFIX+s for s in ('10quarantine','5clear','6cancel'))
DROP = '_RINvNtCs8xEFJqa6dYS_4core3ptr9drop_glueNtNtCsgp9hxIs16B4_11sha3_stream17sha3_stream_state5StateEBF_'
WIPE = '_RNvMNtNtCs58M5yX2Qwr5_16brynja_hash_sha38hardened5ownerINtB2_20HardenedFips202OwnerKj48_E4wipeB6_'
ZERO = '_RNvNtCsjNKEhcqdpKw_11brynja_core22secret_memory_volatile23zeroize_region_volatile'
RECEIVE = '_RNvCsgzEJPm6isiJ_18sha3_stream_worker7receive'
PINS = {
    QUARANTINE:(73,'ca69c5d6c024059696737be2db03b486f58bf4fc6894faedd79e150163d401e8','e56a88343b727c6986b50b2caaed0a94731e756e954716ae1124a249796f6943'),
    CLEAR_OWNER:(66,'72b6cbe020c8717ca825c0593d18c94602c58f5f99599a7ec32529195f7def3e','e56a88343b727c6986b50b2caaed0a94731e756e954716ae1124a249796f6943'),
    CANCEL:(130,'7f4cf04c220c8d8fe68df307a518fef1f70a4bc0522a4a3f7a451e51d39ee4ee','967d81e31c4881fc16d2c905eacc07bb8af6d4e66e5bed5e76ed524e9ffdd863'),
    DROP:(176,'0594389faafcc24b519991903fc4677c863f233c2f7b7a7a397efdffb92f37db','e1744ee3e545403a0679a0c483ebe7d9acf5cbea797e707fd979e30b63a093ba'),
    WIPE:(224,'0c4f3fda5b34fbf61d78888f5b0626d441caa88d178751c3cf54c47043e37ed6','b5d4540b35edeb47029ad289294bf1ca8f5ba402fec17ed5fc26896880fb5948'),
    ZERO:(105,'1d1fb26eaddd4029151c3bce70b49cba0f5a2678f6b0a30d8bc8a3f70893d9b6','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
}
FRAMES = {QUARANTINE:40,CLEAR_OWNER:40,CANCEL:56,DROP:56,WIPE:40}
TABLE = bytes.fromhex('ac000000280000002c00000030000000340000003d000000410000004b000000')
DESTINATIONS = (168,32,32,32,32,37,37,43)
# Byte ranges are owner-relative. Their union is exactly [0,1040).
REGIONS = ((48,200),(248,168),(0,16),(16,16),(32,16),(1036,1),(1037,3),
           (1032,4),(416,168),(584,168),(752,40),(792,40),(832,200))

# The small lifecycle bodies are checked in full, not just at marker offsets.
OWNER_HEAD = '564883ec204889ce4881c100040000e800000000'
OWNER_CLEAR = 'c6860004000000ba000400004889f1e80000000048c786780800000000000066c7868008000000ff'
EXACT = {
    QUARANTINE:OWNER_HEAD+OWNER_CLEAR+'c68682080000074883c4205ec3',
    CLEAR_OWNER:OWNER_HEAD+OWNER_CLEAR+'4883c4205ec3',
    CANCEL:('5657534883ec204889ce0fb68182080000fec8b30240b7073c057721b3014885d2741a'
            '488b867008000048ffc04839d0750b48899670080000b3ff31ff488d8e00040000e800000000'
            +OWNER_CLEAR+'4088be8208000089d84883c4205b5f5ec3'),
    DROP:('5657534883ec200fb6014883f807771b488d1500000000486304824801d0ffe0'
          '48ffc1eb774883c102eb71488d7910807953017523488d71544889cb4889f1e800000000'
          '4889d9807b5300740b4889f1e8000000004889d9c6415300488d4150ba010000004889ce4889c1'
          'e80000000066c746510003c68664040000000f57c00f2947300f2947200f2947100f2907'
          '807e530074134889f14883c1544883c4205b5f5ee9000000004883c4205b5f5ec3'),
    ZERO:('4885d274634989d04889c84983e007741a4889c86666662e0f1f840000000000c6000048ffc049ffc8'
          '75f54883fa0872374801d16666662e0f1f840000000000c60000c6400100c6400200c6400300c6400400'
          'c6400500c6400600c64007004883c0084839c875d8c3'),
}


def wipe_shape(regions=REGIONS):
    """Encode only this saved straight-line pointer/length/call sequence."""
    code = bytearray.fromhex('564883ec204889ce');refs = []
    for i,(offset,size) in enumerate(regions):
        if i == 0: code += bytes.fromhex('4883c1')+offset.to_bytes(1,'little')
        elif i == 12: code += bytes.fromhex('4881c6')+offset.to_bytes(4,'little')
        elif offset:
            code += (bytes.fromhex('488d4e')+offset.to_bytes(1,'little') if offset < 128 else
                     bytes.fromhex('488d8e')+offset.to_bytes(4,'little'))
        code += b'\xba'+size.to_bytes(4,'little')
        if offset == 0 or i == 12: code += bytes.fromhex('4889f1')
        if i == 12: code += bytes.fromhex('4883c4205e')
        code += b'\xe9' if i == 12 else b'\xe8'
        refs.append(dict(offset=len(code),symbol=ZERO,trailing=0,addend=0));code += bytes(4)
    return bytes(code),refs
