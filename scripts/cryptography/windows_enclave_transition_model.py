"""Measurement validation, not a VBS register-sanitization policy."""
from windows_enclave_callback_stack import require


def words(seed, avx):
    require(type(seed) is int and seed in (90, 165) and type(avx) is int and avx in (0, 1), 'test identity')
    word = int.from_bytes(bytes([seed]) * 8, 'little')
    return ([word] * 4 if avx else [word, word, 0, 0]) * 16 + [word] * 11


def bounded(values):
    require(type(values) is list and len(values) == 75 and
            all(type(v) is int and 0 <= v < 1 << 64 for v in values), 'exact 75 register words')


def classify(values, seed, avx):
    bounded(values)
    words(seed, avx)  # Validate the explicit measurement identity.
    marker = bytes([seed]) * 4
    def kind(value):
        raw = b''.join(word.to_bytes(8, 'little') for word in value)
        # Catch partial low/upper-vector and zero-extended 32-bit remnants too.
        # This is a public-pattern observation, not proof about arbitrary bits.
        return 'pattern' if marker in raw else 'zero' if not any(value) else 'other'
    width = 4 if avx else 2
    return [kind(values[i:i+width]) for i in range(0, 64, 4)] + [
        kind([values[i]]) for i in range(64, 75)]


def validate(value, seed, avx):
    require(type(value) is dict and set(value) == {'scheduler', 'before', 'count', 'callbacks'}, 'exact transition fields')
    count = sum(lane == 4 and tag in (2, 3, 4) for _, lane, tag in value['scheduler']['events'])
    require(type(value['count']) is int and value['count'] == count, 'actual poison count')
    bounded(value['before'])
    require(value['before'] == (words(seed, avx) if count else [0] * 75), 'before-pattern measurement')
    wanted = [event for _, lane, event in value['scheduler']['events'] if lane == 4 and event in (2, 3, 4)]
    require(type(value['callbacks']) is list and len(value['callbacks']) == count, 'complete callback measurements')
    for index, (record, event) in enumerate(zip(value['callbacks'], wanted), 1):
        require(type(record) is dict and set(record) == {'event', 'count', 'registers'}, 'callback fields')
        require(type(record['count']) is int and record['count'] == index and
                type(record['event']) is int and record['event'] == event, 'ordered callback measurement')
        require(type(record['registers']) is list and len(record['registers']) == 27 and
                all(v in ('pattern', 'zero', 'other') for v in record['registers']), 'classified register population')
    # Deliberately no requirement for zero/absence: this is an observation,
    # not permission to assume undocumented OS transition sanitization.
    return value
