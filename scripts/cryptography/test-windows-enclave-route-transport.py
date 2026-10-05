"""Transport template, relocation, role and metadata regressions."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

import windows_enclave_route_transport as r


def saved_spec():
    path=r.SPEC if r.SPEC.exists() else Path(__file__).with_name(r.SPEC.name)
    return r.specification(path.read_bytes())


class Tests(unittest.TestCase):
    def test_all_reviewed_templates_and_each_byte_mutation(self):
        spec=saved_spec();seen=set()
        for profile in spec['profiles']:
            for role,key in profile['bodies'].items():
                template=spec['templates'][key];code=bytes.fromhex(template['bytes'])
                g=profile['global_prefix'];aliases={'source':g+'_source','report':g+'_report','last_kind':'simd_last_kind'}
                refs=[v | {'symbol':aliases.get(v['symbol'],v['symbol'])} for v in template['references']]
                r.body_check(profile,role,spec['templates'],code,refs)
                if key in seen:continue
                seen.add(key)
                for i in range(len(code)):
                    bad=bytearray(code);bad[i]^=1
                    with self.assertRaises(ValueError):r.body_check(profile,role,spec['templates'],bad,refs)
                for bad in (refs[:-1],refs+[refs[0]],list(reversed(refs))):
                    with self.assertRaises(ValueError):r.body_check(profile,role,spec['templates'],code,bad)
                for change in ({'symbol':'other'},{'offset':9999},{'addend':100},{'trailing':9}):
                    bad=copy.deepcopy(refs);bad[0].update(change)
                    with self.assertRaises(ValueError):r.body_check(profile,role,spec['templates'],code,bad)
        self.assertEqual(len(seen),27)
        with self.assertRaises(ValueError):r.specification(b'{}')

    def test_linked_target_consistency_including_addend_and_trailing(self):
        refs=[dict(offset=2,symbol='report',trailing=4,addend=24)]
        code=b'\x90\x90'+(200-100-2-4-4+24).to_bytes(4,'little',signed=True)+bytes(4)
        known={'report':200};r.reconcile_targets(known,refs,100,code)
        self.assertEqual(known,{'report':200})
        for i in range(2,6):
            bad=bytearray(code);bad[i]^=1
            with self.assertRaises(ValueError):r.reconcile_targets(known.copy(),refs,100,bad)
        for change in ({'offset':3},{'trailing':0},{'addend':0},{'offset':99}):
            with self.assertRaises(ValueError):r.reconcile_targets(known.copy(),[refs[0] | change],100,code)

    def test_metadata_complete_mapping_permissions_and_aliases(self):
        row=dict(rva=10000,virtual_size=1000,flags=0xc0000040)
        identities={name:10000+100*i for i,name in enumerate(r.DATA)}
        self.assertEqual(len(r.metadata([row],identities)),len(r.DATA))
        for rows in ([],[row,row],[row | {'flags':0x40000040}],[row | {'flags':0xe0000040}],
                     [row | {'virtual_size':999-100}]):
            with self.assertRaises(ValueError):r.metadata(rows,identities)
        with self.assertRaises(ValueError):r.metadata([row],identities | {'report':identities['source']})

    def test_exported_leaf_checks_complete_relocated_bytes(self):
        spec=saved_spec();profile=spec['profiles'][0];role='InputSource'
        template=spec['templates'][profile['bodies'][role]];code=bytes.fromhex(template['bytes'])
        refs=template['references'];names={v['symbol'] for v in refs}
        identities={name:10000+i*100 for i,name in enumerate(sorted(names))}
        expected=r.exported.linked_bytes(code,refs,1000,identities)
        row=dict(rva=1000,virtual_size=len(code),code=expected,flags=0x60000020)
        original=[v | {'symbol':{'source':'sha2_source','report':'sha2_report'}.get(v['symbol'],v['symbol'])} for v in refs]
        with patch.object(r.shared.caller,'function',return_value=(code,original)), \
             patch.object(r.shared.caller.pe,'linked',return_value=([row],[])):
            result=r.leaf_at(b'obj',b'image','PublicSha2InputSource',profile,role,spec['templates'],identities.copy(),1000)
            self.assertEqual(result['rva'],1000)
            for i in range(len(expected)):
                bad=bytearray(expected);bad[i]^=1
                with patch.object(r.shared.caller.pe,'linked',return_value=([row | {'code':bytes(bad)}],[])):
                    with self.assertRaises(ValueError):r.leaf_at(b'obj',b'image','name',profile,role,spec['templates'],identities.copy(),1000)
            with patch.object(r.shared.caller.pe,'linked',return_value=([row],[(1000,1001,9000)])):
                with self.assertRaises(ValueError):r.leaf_at(b'obj',b'image','name',profile,role,spec['templates'],identities.copy(),1000)


if __name__=='__main__':unittest.main()
