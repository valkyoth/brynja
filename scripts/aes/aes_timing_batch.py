"""Fixed 1024-operation experiment; original timing policy is never mutated."""
from types import SimpleNamespace

REPEAT = 1024


def require(ok, message):
    if not ok:
        raise ValueError('AES timing batch: ' + message)


def fixture(source):
    anchor = 'const REPEAT: usize = 4;'
    require(source.count(anchor) == 1, 'original repetition declaration changed')
    require('fn isolated_timer<const MEASURING: bool>' in source, 'dispatch-isolated fixture required')
    return source.replace(anchor, f'const REPEAT: usize = {REPEAT};')


def policy(original):
    require(original.REPEAT == 4, 'original policy changed')
    header = f'AES_FIXED_RANDOM_POLICY {original.SAMPLES} {REPEAT} {original.WARMUP} {original.SEED}'

    def parse(output):
        first, separator, rest = output.partition('\n')
        require(separator and first == header, 'wrong/missing long-batch policy')
        # The original strict population/order/statistical parser operates on
        # raw sample durations. Only its already-validated header is adapted;
        # retained raw output is never rewritten or normalized per operation.
        return original.parse(original.HEADER + '\n' + rest)

    return SimpleNamespace(REPEAT=REPEAT, HEADER=header, parse=parse,
                           **{name: getattr(original, name) for name in
                              ('SAMPLES', 'WARMUP', 'SEED', 'LIMIT', 'MAX_CV',
                               'CAMPAIGNS', 'corpus', 'inputs', 'screen', 'host_info')})
