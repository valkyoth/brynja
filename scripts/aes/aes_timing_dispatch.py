"""Separately identified timing-dispatch experiment, never a baseline rewrite."""
import hashlib

TESTS = {'isolated_tests::timer_repetition_and_error_short_circuit_are_exact',
         'isolated_tests::overhead_never_mutates_input'}
MACRO_SHA256 = '82a4d8a75f631017fd34b7ef502923fde69ef355301620b8078ad86757feba24'


def require(ok, message):
    if not ok:
        raise ValueError('AES timing dispatch: ' + message)


def fixture(source, dispatch, overhead):
    start, end = '// Construction,', '\nwidth!(aes128,'
    require(source.count(start) == source.count(end) == 1, 'fixture boundary changed')
    a, b = source.index(start), source.index(end)
    require(hashlib.sha256(source[a:b].encode()).hexdigest() == MACRO_SHA256, 'original timer/macro changed')
    source = source[:a] + dispatch + source[b:]
    anchor = '    run(&args[0], controls::Control::parse(&args[1])?)'
    require(source.count(anchor) == 1, 'main dispatch changed')
    source = source.replace(anchor, '    if args[0] == "overhead" && args[1] == "shared-identical" {\n'
                            '        return overhead();\n    }\n' + anchor)
    return source + '\n' + overhead


def parse_overhead(output, timing):
    lines = output.splitlines()
    require(len(lines) == 2 * timing.SAMPLES + 2, 'wrong overhead population')
    require(lines[0] == f'AES_TIMING_OVERHEAD {timing.SAMPLES} {timing.REPEAT} {timing.WARMUP} {timing.SEED}'
            and lines[-1] == 'AES_TIMING_OVERHEAD_END', 'wrong overhead policy or termination')
    rows = []
    for campaign, name in enumerate(('timer', 'copy')):
        cases = list(timing.corpus(campaign))[timing.WARMUP:]
        pairs = []
        for sample, case in enumerate(cases):
            fields = lines[1 + campaign * timing.SAMPLES + sample].split()
            require(len(fields) == 6 and fields[:4] == ['OVERHEAD', name, str(sample), str(case[2])],
                    'wrong overhead identity/order')
            require(all(s.isascii() and s.isdecimal() for s in fields[4:]), 'invalid overhead duration')
            pairs.append(tuple(map(int, fields[4:])))
        rows.append({'control': name, **timing.screen(pairs)})
    return {'controls': rows, 'diagnostic_only': True,
            'policy': 'raw durations; no subtraction from AES samples; not an AES timing pass'}
