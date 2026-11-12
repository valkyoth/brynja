"""Address/value control plumbing for the accelerated timing experiment."""
import re
import subprocess

CONTROLS = ('separate-values', 'shared-values', 'separate-identical', 'shared-identical')
TESTS = {'controls::tests::control_names_are_closed_and_roundtrip',
         'controls::tests::controls_preserve_or_equalize_the_complete_input',
         'controls::tests::address_control_is_independent_of_values_and_class_order',
         'controls::tests::invalid_class_does_not_invoke_operation'}


def require(ok, message):
    if not ok:
        raise ValueError('AES timing controls: ' + message)


def substitutions():
    return (
        ('fn run(phase: &str)', 'fn run(phase: &str, control: controls::Control)', 1),
        ('    println!("AES_FIXED_RANDOM_POLICY',
         '    println!("AES_TIMING_CONTROL: {}", control.name());\n    println!("AES_FIXED_RANDOM_POLICY', 1),
        ('                let cases = corpus(campaign);',
         '                let mut common = controls::Common::default();\n                let cases = corpus(campaign);', 1),
        ('                        for class in 0..2 {\n                            let (key, block) = inputs(case, mode, class);\n                            let (_, hex) = trial(authority, owner, mode, &key, &block, false)?;',
         '                        let pair = control.pair([inputs(case, mode, 0), inputs(case, mode, 1)]);\n'
         '                        for class in 0..2 {\n'
         '                            let (_, hex) = control.invoke(&pair, class, &mut common, |key, block|\n'
         '                                trial(authority, owner, mode, key, block, false))??;', 1),
        ('\n                    let pair = [inputs(case, mode, 0), inputs(case, mode, 1)];',
         '\n                    let pair = control.pair([inputs(case, mode, 0), inputs(case, mode, 1)]);', 1),
        ('trial(authority, owner, mode, &pair[class].0, &pair[class].1, true)?.0;',
         'control.invoke(&pair, class, &mut common, |key, block|\n'
         '                                trial(authority, owner, mode, key, block, true))??.0;', 1),
        ('if args.len() != 1', 'if args.len() != 2', 1),
        ('expected one phase', 'expected phase and control', 1),
        ('run(&args[0])', 'run(&args[0], controls::Control::parse(&args[1])?)', 1),
        ('run("unknown")', 'run("unknown", controls::Control::SeparateValues)', 1),
    )


def fixture(source, module):
    for old, new, count in substitutions():
        require(source.count(old) == count, 'fixture anchor changed: ' + old)
        source = source.replace(old, new)
    return source + '\nmod controls {\n' + module + '\n}\n'


def payload(output, control):
    require(control in CONTROLS, 'unknown control')
    first, separator, rest = output.partition('\n')
    require(separator and first == 'AES_TIMING_CONTROL: ' + control, 'wrong/missing control marker')
    return rest


def check_tests(output, timing, extra=frozenset()):
    names = re.findall(r'^test (\S+) \.\.\. ok$', output, re.M)
    summaries = re.findall(r'^test result:.*$', output, re.M)
    total = 8 + len(extra)
    require(len(names) == total and set(names) == TESTS | timing.TESTS | extra and len(summaries) == 1
            and re.fullmatch(rf'test result: ok\. {total} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9.]+s', summaries[0]),
            'missing/failed control fixture tests')


def preflight(output, control, executable, env, timing):
    require(control in CONTROLS, 'unknown control')
    expected = [timing.HEADER]
    for campaign, (bits, owner, mode) in enumerate(timing.CAMPAIGNS):
        cases = list(timing.corpus(campaign))
        for sample in (0, timing.SAMPLES // 2, timing.SAMPLES - 1):
            for cls in (0, 1):
                value_class = 0 if control.endswith('-identical') else cls
                key, block = timing.inputs(cases[timing.WARMUP + sample], bits, mode, value_class)
                result = subprocess.run([str(executable), 'enc', f'-aes-{bits}-ecb', '-nopad', '-nosalt',
                                         '-K', key.hex(), '-d' if mode.startswith('decrypt-') else '-e'],
                                        input=block, env=env, capture_output=True, timeout=15)
                require(result.returncode == 0 and not result.stderr and len(result.stdout) == 16, 'oracle failed')
                expected.append(f'VECTOR {bits} {owner} {mode} {sample} {cls} {result.stdout.hex()}')
    require(output.splitlines() == expected + ['AES_FIXED_RANDOM_END preflight'], 'operation/corpus preflight mismatch')
