"""Actual descriptor byte provenance, bounded bit admission and failure regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_descriptors as t


class SimdDescriptorModelTests:
    def test_simd_descriptors_initial_array_provenance(self):
        lines=t.array_shape();report=t.array_provenance(lines)
        self.assertEqual(report['physical_written_bytes'],441)
        self.assertFalse(report['padding_initialization_or_cleanup_claimed'])
        count=0
        for at,line in enumerate(lines):
            # Shift all reads of empty descriptors and plan fields, plus every
            # semantic slot publication. These must affect actual output bytes.
            bad=None
            if line=='vmovups (%r8), %ymm0':bad='vmovups 1(%r8), %ymm0'
            if line.startswith('movq ') and '(%rdx)' in line:
                bad=line.replace('(%rdx)','1(%rdx)') if line.startswith('movq (') else line.replace('16(%rdx)','17(%rdx)').replace('32(%rdx)','33(%rdx)').replace('48(%rdx)','49(%rdx)')
            if line.startswith('movq %') and any(f', {v}(%rcx)' in line for v in (96,208,320,432)):
                bad='movq %rax, 447(%rcx)'
            if bad is not None:
                self.assertNotEqual(bad,line)
                with self.assertRaises(ValueError):t.array_provenance(lines[:at]+[bad]+lines[at+1:])
                count+=1
        self.assertEqual(count,12)
        # This spill is redundant: its value is not used to construct the result.
        # The semantic model must not invent a load-bearing cleanup guarantee.
        redundant=lines.index('vmovups %ymm0, (%rsp)')
        self.assertEqual(t.array_provenance(lines[:redundant]+lines[redundant+1:]),report)

    def test_simd_descriptors_all_terminal_byte_predicates(self):
        count=0
        for length in (0,1,2,1024):
            for last in range(256):
                for tail in range(256):
                    valid=(last==0) if not length else (1<=last<=8 and tail<1<<last)
                    expected=None if not valid else dict(bits=0 if not length else (length-1)*8+last,
                        read_index=length-1 if length and last<8 else None)
                    self.assertEqual(t.bit_admission(length,last,tail),expected)
                    count+=1
        self.assertEqual(count,262144)


class SimdDescriptorSavedTests:
    def simd_descriptor_fixture(self):
        args=self.simd_receive_fixture();receiver=t.receive.inspect(*args)
        return args[0],args[1],receiver

    def test_simd_descriptors_complete_helper_instruction_mutations(self):
        args=self.simd_descriptor_fixture();bodies,ir,receiver=args;report=t.inspect(*args);count=0
        for name in report['instruction_positions']:
            lines=t.life.code(bodies[name])
            for at in range(len(lines)):
                for replacement in ([],['ud2'],['retq',lines[at]]):
                    bad=lines[:at]+replacement+lines[at+1:]
                    with self.assertRaises(ValueError):t.inspect(bodies|{name:name+':\n'+'\n'.join(bad)},ir,receiver)
                    count+=1
        self.assertEqual(count,486)
        print('Keccak descriptor/bitstring/predicate instruction mutations rejected:',count)

    def test_simd_descriptors_predicate_abis_and_composition(self):
        args=self.simd_descriptor_fixture();bodies,ir,receiver=args;report=t.inspect(*args);count=0
        for role in ('mask','predicate'):
            name=report['functions'][role]
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            for token in ('noundef','nonnull','noalias','nofree','readonly','dereferenceable(1)',
                'captures(address, read_provenance)','zeroext','range(i8 -128, 0)','fastcc'):
                if token not in row:continue
                with self.assertRaises(ValueError):t.inspect(bodies,ir.replace(row,row.replace(token,'')),receiver)
                count+=1
        print('Keccak terminal-bit predicate ABI mutations rejected:',count)
        for key in ('all_twelve_inputs_bounded_to_separate_1024_byte_worker_slots',
                    'actual_bitstring_inputs_use_local_buffers_not_host_addresses'):
            bad=copy.deepcopy(receiver);bad[key]=False
            with self.assertRaises(ValueError):t.inspect(bodies,ir,bad)
        for role in ('array','bits'):
            bad=copy.deepcopy(receiver);bad['functions'][role]='wrong'
            with self.assertRaises(ValueError):t.inspect(bodies,ir,bad)

    def test_simd_descriptors_integrated_review_does_not_promote_digest(self):
        report=t.inspect(*self.simd_descriptor_fixture())
        self.assertTrue(report['no_input_pointer_published_to_global_or_heap_storage'])
        self.assertTrue(report['descriptor_helpers_do_not_erase_their_full_frames'])
        self.assertFalse(report['digest_caller_and_final_frame_cleanup_qualified'])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('descriptor review failed')) as call:
            with self.assertRaisesRegex(ValueError,'descriptor review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()
