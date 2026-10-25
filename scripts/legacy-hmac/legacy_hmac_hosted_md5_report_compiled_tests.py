"""Compile report/count/guard mistakes in private Linux and Apple workers."""
from pathlib import Path

from legacy_hmac_hosted_compiled_fixture import prepare


class Md5ReportCompiledTests:
    def test_compiled_md5_report_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'md5-report-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            path = leaf / 'src' / directory / 'md5_compiled/worker.rs'
            original = path.read_text()
            clauses = ('report.backend != parameters.backend',
                       'report.vector_width != parameters.backend.lane_width()',
                       'report.inner.active_lanes != active', 'report.outer.active_lanes != active',
                       'report.inner.vector_blocks < parameters.backend.lane_width()',
                       'report.outer.vector_blocks < parameters.backend.lane_width()')
            variants = [original.replace(clause, 'false', 1) for clause in clauses]
            variants.extend((original.replace('report.inner.vector_blocks <', 'report.inner.vector_blocks <='),
                             original.replace('report.outer.active_lanes != active', 'report.inner.active_lanes != active'),
                             original.replace('inputs.iter().filter(|v| v.is_some()).count()', '0'),
                             original.replace('inputs.iter().filter(|v| v.is_some()).count()',
                                              'inputs.iter().take(7).filter(|v| v.is_some()).count()'),
                             original.replace('inputs.iter().filter(|v| v.is_some()).count()',
                                              'inputs.iter().filter(|v| v.is_none()).count()')))
            marker = 'report(actual, &parameters, active)?;'
            offsets = [i for i in range(len(original)) if original.startswith(marker, i)]
            self.assertEqual(len(offsets), 2)
            for at in offsets:
                for replacement in ('/* missing report guard */', marker.replace('?', '.ok()')):
                    variants.append(original[:at] + replacement + original[at + len(marker):])
            for mutant in variants:
                self.assertTrue(mutant != original)
                try:
                    path.write_text(mutant)
                    artifacts = emit()  # Compilation errors are not credited as a rejection.
                    with self.subTest(target=target, mutation=count), self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 30)
        print('MD5 reports: 30 compiled Rust defects rejected; restored baselines pass', flush=True)
