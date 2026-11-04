"""Replay an explicit instruction-stream review; not an assembly taint proof.

Do not auto-update the reviewed hashes after a mismatch. Review the changed
instructions, control flow, addresses and call targets first. The accompanying
development contract records the public-control argument and exclusions.
"""
import hashlib
from pathlib import Path
import re

ROLES = {'substitute', 'mix', 'expand', 'add_key', 'transform', 'inverse'}
POLICY = Path(__file__).with_name('machine-review.json')
CLEAR = r'(?:_RNvNt\w+_11brynja_core13secret_memory18clear_owned_region|_ZN11brynja_core13secret_memory18clear_owned_region17h[0-9a-f]+E)'


def require(condition, message):
    if not condition:
        raise ValueError('AES machine review: ' + message)


def canonical_body(assembly, symbol, symbols):
    """Preserve instructions, operands, local CFG, alignment and call identity.

    Ignore comments/whitespace and CFI unwind metadata (not executable code).
    Rename only exact selected helper symbols, the delegated core-clear symbol,
    and local labels. Never remove displacements, constants or register names.
    This is a fingerprint format, not a general-purpose assembler parser.
    """
    bodies = re.findall(r'^' + re.escape(symbol) + r':\n(.*?)^\s*\.size\s+' + re.escape(symbol) + r',',
                        assembly, re.M | re.S)
    require(len(bodies) == 1, 'missing/ambiguous helper body')
    lines = []
    for line in bodies[0].splitlines():
        line = line.split('#', 1)[0].strip()
        if line and not line.startswith('.cfi_'):
            lines.append(' '.join(line.split()))
    require(lines, 'empty helper body')
    text = '\n'.join(lines) + '\n'
    labels = re.findall(r'^(\.L[-\w.]+):$', text, re.M)
    require(len(labels) == len(set(labels)), 'duplicate local label')
    mapping = {label: f'@block{index}' for index, label in enumerate(labels)}
    mapping.update({name: '@aes.' + role for name, role in symbols.items()})
    clears = set(re.findall(CLEAR, text))
    require(len(clears) <= 1, 'ambiguous delegated clear target')
    mapping.update({name: '@core.clear_owned_region' for name in clears})
    # Match complete assembler identifiers; a prefix/suffix lookalike must not
    # become an approved call, memory operand or branch target.
    text = re.sub(r'(?<![-\w.])(?:' + '|'.join(re.escape(name) for name in sorted(mapping, key=len, reverse=True))
                  + r')(?![-\w.])', lambda match: mapping[match[0]], text)
    require(not re.search(r'\b_(?:RN|ZN)\w+|(?<!\w)\.L[-\w.]+', text), 'unknown symbol or local target')
    return text


def fingerprints(assembly, selected):
    require(set(selected) == ROLES, 'helper population changed')
    symbols = {item[0]: role for role, item in selected.items()}
    require(len(symbols) == len(ROLES), 'duplicate helper symbol')
    return {role: hashlib.sha256(canonical_body(assembly, item[0], symbols).encode()).hexdigest()
            for role, item in selected.items()}


def check(assembly, selected, compiler, panic, policy):
    require(set(policy) == {'schema', 'review', 'target', 'panics', 'compilers'} and policy['schema'] == 1,
            'unrecognized policy')
    require(policy['review'] == 'docs/assurance/aes128-development.md#six-helper-machine-review--2026-11-04'
            and policy['target'] == 'x86_64-unknown-linux-gnu'
            and policy['panics'] == ['abort', 'unwind']
            and set(policy['compilers']) == {'1.90.0', '1.99.1'}, 'review scope changed')
    require(compiler in policy['compilers'] and panic in policy['panics'], 'unreviewed configuration')
    for rows in policy['compilers'].values():
        require(set(rows) == ROLES and all(re.fullmatch(r'[0-9a-f]{64}', value) for value in rows.values()),
                'missing/invalid reviewed fingerprints')
    actual = fingerprints(assembly, selected)
    for role, digest in actual.items():
        require(digest == policy['compilers'][compiler][role],
                f'instruction stream changed: {compiler}/{panic}/{role}; explicit re-review required; got {digest}')
    return actual
