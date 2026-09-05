#!/usr/bin/env python3
"""Exact legacy SHA-1 secret-owner contract, separate from protocol admission."""
OWNER = 'crates/brynja-legacy-sha1/src/owner.rs#brynja_legacy_sha1::owner::Sha1Owner'
DROP = OWNER + '::drop'
WIPE = 'crates/brynja-legacy-sha1/src/owner.rs#brynja_legacy_sha1::Sha1Owner::wipe'
RECORD = {
    'capability': 'algorithm.sha1', 'symbol': OWNER,
    'fields': ['chaining_state:secret-derived', 'block:secret-copy', 'schedule:secret-derived',
               'message_length:secret-derived', 'buffered:secret-derived', 'output_staging:secret-derived'],
    'temporaries': ['round-scalars:register-copy-risk', 'length-encoding:compiler-copy-risk',
                   'borrowed-input:caller-owned-copy-risk', 'typed-output:caller-owned'],
    'sanitization_symbol': WIPE, 'cleanup_callers': [DROP],
    'evidence': ['crates/brynja-legacy-sha1/tests/api.rs', 'assurance/sha1-public-api/src/lib.rs',
                 'scripts/sha1/check-sha1.py', 'scripts/sha1/check-sha1-codegen.sh'],
    'storage': 'crate-owned-fixed', 'output_classification': 'typed-secret-owned',
    'partial_failure_policy': 'clear-complete-secret-destination',
}


def register(contracts, tests, headers, sanitizers, paths):
    contracts['registered.algorithm.sha1'] = {'record': RECORD}
    tests[OWNER] = {'package': 'brynja-legacy-sha1', 'contract_test':
                    'owner::assurance_contract::registered_algorithm_sha1_owner_contract_is_compiler_checked'}
    headers[DROP] = ['fn owner::<impl at crates/brynja-legacy-sha1/src/owner.rs:55:1: 55:24>::drop(_1: &mut Sha1Owner) -> () {']
    sanitizers[WIPE] = 'Sha1Owner::wipe('
    paths.add('scripts/cryptography/legacy_sha1_owner_contract.py')
    paths.update('crates/brynja-legacy-sha1/src/' + name + '.rs'
                 for name in ('lib', 'ordinary', 'hardened', 'owner', 'output', 'compress', 'engine'))
    paths.update(RECORD['evidence'])
