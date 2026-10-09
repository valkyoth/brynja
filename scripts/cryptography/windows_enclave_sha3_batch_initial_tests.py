"""Actual saved constructor mutations: reuse must not erase data dependencies."""
import copy
from unittest.mock import patch

import windows_enclave_sha3_batch_chains as c


class InitialTests:
    def initial_fixture(self):
        data,image,_,ir,functions,_=self.routes['avx2']
        reviewer=c.c.previous
        report=reviewer.inspect(self.saved,self.root)
        _,_,old_data,_,_,old_ir,_=reviewer.inputs(
            self.saved,self.root,reviewer.specification(reviewer.SPEC.read_bytes()))
        prior=reviewer.inventory(old_data)
        exact,_=c.c.reuse.exact_reuse(functions,prior,ir,old_ir)
        records=c.binding.bind_all(data,image,functions)
        constants,_,_,_,_=c.binding.data_bindings(data,image,records,functions,
            {'memcpy','memset','memcmp','__chkstk','__umodti3','PublicProbeAbort'} |
            {'PublicSha3Batch'+s for s in ('Input','Output','Source','Observe')},'scalar')
        return functions,prior,ir,old_ir,exact,report['constants'],constants

    def test_initial_rebinding_checks_every_byte_and_relocation(self):
        args=self.initial_fixture();m=c.initial
        result=m.rebind(*args)
        self.assertEqual(result['body_bytes'],1123)
        self.assertEqual(result['relocations'],16)
        code,refs,kind=args[0][m.NAME]
        for at in range(len(code)):
            bad=bytearray(code);bad[at]^=1
            with self.assertRaises(ValueError):
                m.rebind(args[0]|{m.NAME:(bytes(bad),refs,kind)},*args[1:])
        for at in range(len(refs)):
            for key,value in [('symbol','wrong'),('offset',-1),('trailing',1),('addend',1)]:
                bad=copy.deepcopy(refs);bad[at][key]=value
                with self.assertRaises(ValueError):
                    m.rebind(args[0]|{m.NAME:(code,bad,kind)},*args[1:])
        for bad in ((code+b'\0',refs,kind),(code,refs,not kind),(code,refs[:-1],kind)):
            with self.assertRaises(ValueError):m.rebind(args[0]|{m.NAME:bad},*args[1:])
        print('SHA-3 initial: 1123 byte, 64 relocation and 3 extent mutations rejected')

    def test_initial_rebinding_requires_actual_linked_constants_and_helpers(self):
        args=self.initial_fixture();m=c.initial;result=m.rebind(*args)
        for index in (5,6):
            for name in result['linked_constants']:
                key=m.OLD if index==5 and name==m.NEW else name
                for field,value in [('bytes',0),('sha256','0'*64)]:
                    bad=copy.deepcopy(args[index]);bad[key][field]=value
                    changed=list(args);changed[index]=bad
                    with self.assertRaises(ValueError):m.rebind(*changed)
                changed=list(args);changed[index]={k:v for k,v in args[index].items() if k!=key}
                with self.assertRaises(ValueError):m.rebind(*changed)
        # Matching corrupt tables in BOTH images still violate independent definitions.
        for name in (m.TABLE,m.NEW):
            changed=list(args);changed[5]=copy.deepcopy(args[5]);changed[6]=copy.deepcopy(args[6])
            changed[5][m.OLD if name==m.NEW else name]['sha256']='0'*64
            changed[6][name]['sha256']='0'*64
            with self.assertRaises(ValueError):m.rebind(*changed)
        for name in result['reviewed_callees']:
            changed=list(args);changed[4]={k:v for k,v in args[4].items() if k!=name}
            with self.assertRaises(ValueError):m.rebind(*changed)
        self.assertFalse(result['batch_caller_lifetimes_qualified'])
        self.assertFalse(result['private_frame_erasure_qualified'])

    def test_initial_rebinding_requires_abi_and_exact_allowed_rename(self):
        args=self.initial_fixture();m=c.initial
        declaration=next(l for l in args[2].splitlines() if l.startswith('define ') and '@'+m.NAME+'(' in l)
        for token in ('noalias ','nonnull ','noundef '):
            self.assertIn(token,declaration)
            changed=list(args);changed[2]=args[2].replace(declaration,declaration.replace(token,''))
            with self.assertRaises(ValueError):m.rebind(*changed)
        for symbol in (m.OLD,m.NEW+'.extra'):
            code,refs,kind=args[0][m.NAME]
            bad=[r|{'symbol':symbol} if r['symbol']==m.NEW else r for r in refs]
            with self.assertRaises(ValueError):m.rebind(args[0]|{m.NAME:(code,bad,kind)},*args[1:])

    def test_initial_rebinding_is_required_by_integrated_review(self):
        with patch.object(c.initial,'rebind',side_effect=ValueError('constructor failed')) as check:
            with self.assertRaisesRegex(ValueError,'constructor failed'):
                c.inspect_route(self.saved,self.root,'avx2',self.spec['avx2'])
            check.assert_called_once()
