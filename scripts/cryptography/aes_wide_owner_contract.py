"""Development-only named wide AES owners, without inherited compiler claims."""
from copy import deepcopy
import re
import tomllib
import aes_owner_contract as aes
import rust_source_contract as rust

SOURCE = 'crates/brynja-crypto/src/aes/wide.rs'
PORTABLE = 'crates/brynja-crypto/src/aes/portable/wide.rs'
LAYOUT = 'crates/brynja-crypto/src/aes/portable/layout.rs'
REVIEWED_PATHS = {SOURCE, PORTABLE, 'crates/brynja-crypto/src/aes/tests/wide.rs',
                  'crates/brynja-crypto/tests/aes_wide.rs',
                  'crates/brynja-crypto/tests/aes_wide_kat.rs',
                  'crates/brynja-crypto/tests/aes_wide_differential.rs',
                  'scripts/aes/check-aes-wide-api.py',
                  'scripts/aes/check-aes-wide-operation-cleanup.py',
                  'scripts/aes/test-aes-wide-operation-cleanup.py',
                  'scripts/cryptography/aes_wide_owner_contract.py',
                  'scripts/cryptography/test-aes-wide-owner-contract.py'}


def record(bits, key, size, rounds):
    row = deepcopy(aes.RECORD)
    row.update(variant=f'AES-{bits}', milestone='0.27.1', key_bytes=key, rounds=rounds,
               symbol=SOURCE + f'#Aes{bits}Key', expanded_key_symbol=SOURCE + f'#Aes{bits}ExpandedKey',
               compiler_checks=['python3 scripts/aes/check-aes-owner-cleanup.py',
                                'python3 scripts/aes/check-aes-wide-operation-cleanup.py'],
               compiler_scope='bounded-owner-and-operation-scratch-dispatch-x86_64-rust-1.90.0-and-1.99.1-abort-and-unwind-not-whole-frame-or-timing',
               qualification='development-only-v0.27.1-in-progress-independent-review-pending',
               temporaries=[f'schedule:Scratch<{size}>', *row['temporaries'][1:]],
               cleanup_bindings=[SOURCE + '#clear', aes.SOURCE + '#SecretBlock::clear', aes.SOURCE + '#Scratch::drop'],
               excluded_scope=['other-AES-key-widths', *row['excluded_scope'][2:]],
               evidence=['crates/brynja-crypto/tests/aes_wide.rs', 'crates/brynja-crypto/src/aes/tests/wide.rs',
                         'crates/brynja-crypto/tests/aes_wide_kat.rs', 'crates/brynja-crypto/tests/aes_wide_differential.rs',
                         'scripts/aes/check-aes-wide-api.py', 'scripts/cryptography/test-aes-wide-owner-contract.py',
                         'docs/assurance/aes-wide-development.md'])
    for operation in row['operations']:
        operation['api'] = operation['api'].replace('Aes128', f'Aes{bits}')
    return row


RECORDS = {f'development.algorithm.aes{bits}': record(bits, key, size, rounds)
           for bits, key, size, rounds in ((192, 24, 208, 12), (256, 32, 240, 14))}


def validate(root, owner, current):
    row = RECORDS[owner['id']]
    aes.require(owner == {'id': owner['id'], **row}, 'canonical scoped record changed')
    aes.require(set(row['delegated_owners']) <= {r.get('id') for r in current}, 'delegated core owner absent')
    text = aes.compact(rust.scrub((root / SOURCE).read_text()))
    # The owners are macro-generated named types, not public const-generic ciphers.
    invocations = re.findall(r'owners!\(([^)]*)\)', text)
    aes.require(invocations == [
        'Aes192Key,Aes192ExpandedKey,AES192_KEY_BYTES,AES192_EXPANDED_KEY_BYTES,12',
        'Aes256Key,Aes256ExpandedKey,AES256_KEY_BYTES,AES256_EXPANDED_KEY_BYTES,14'],
        'wide AES named instantiations changed')
    for name in ('$key', '$cached'):
        aes.require(f"pubstruct{name}<'a>{{region:OwnedSecretRegion<'a>,local:PhantomData<*mut()>,}}" in text,
                    'wide owner region/local marker changed')
    aes.require(text.count('pubfnclear(self){let_=self.region.clear();}') == 2,
                'wide explicit clearing changed')
    aes.require(text.count('_authority:PublicCiphertext') == 2, 'wide public authority changed')
    aes.require('letdestination=SecretRegionInitialization::begin(output)?;letmutschedule=Scratch::<$s>::new();' in text,
                'wide output admission must precede expansion')
    aes.require('letmutdestination=SecretRegionInitialization::begin(storage)?;letmutschedule=Scratch::<$s>::new();' in text,
                'wide cached import guard changed')
    aes.require('letmutstate=Scratch::<BLOCK_BYTES>::new();' in text and
                'destination.write(&state.0)?;' in text and 'output.copy_from_slice(&state.0);' in text,
                'wide staged output guards changed')
    portable = aes.compact(rust.scrub((root / PORTABLE).read_text()))
    layout = aes.compact(rust.scrub((root / LAYOUT).read_text()))
    aes.require('(24,208,12)|(32,240,14)' in layout and
                'uselayout::valid_wide_parametersasvalid_parameters;' in portable and
                portable.count('const{assert!(valid_parameters(K,S,R))};') == 2,
                'wide parameter admission changed')
    for expression in ('layout::prior_word_index(offset,4,i)',
                       'layout::prior_word_index(offset,K,i)', 'layout::word_byte_index(offset,i)'):
        aes.require(expression in portable, 'wide proof/production index binding changed')
    aes.require('letmutword=Scratch::<4>::new();' in portable, 'wide expansion scratch guard changed')
    aes.require('elseifK==32&&position==16' in portable, 'AES-256 SubWord branch changed')
    checks = tomllib.loads((root / 'verification/checks.toml').read_text())['checks']
    for check_id, script in (('owner-dispatch', 'owner'), ('wide-operation-cleanup', 'wide-operation')):
        selected = [c for c in checks if c['component'] == 'aes' and c['id'] == check_id]
        aes.require(len(selected) == 1 and selected[0]['command'] ==
                    ['python3', f'scripts/aes/check-aes-{script}-cleanup.py'] and
                    selected[0]['category'] == 'compiler' and selected[0]['platform'] == 'linux-x86_64',
                    'wide owner compiler binding missing or replaced')
