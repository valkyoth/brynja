#!/usr/bin/env python3
"""Exact legacy MD5 secret-owner contract, separate from protocol admission."""
OWNER = 'crates/brynja-legacy-md5/src/owner.rs#brynja_legacy_md5::owner::Md5Owner'
DROP = OWNER + '::drop'
WIPE = 'crates/brynja-legacy-md5/src/owner.rs#brynja_legacy_md5::Md5Owner::wipe'
RECORD = {
    'capability': 'algorithm.md5', 'symbol': OWNER,
    'fields': ['chaining_state:secret-derived', 'block:secret-copy',
               'message_length:secret-derived', 'buffered:secret-derived', 'output_staging:secret-derived'],
    'temporaries': ['round-scalars:register-copy-risk', 'length-encoding:compiler-copy-risk',
                   'borrowed-input:caller-owned-copy-risk', 'typed-output:caller-owned'],
    'sanitization_symbol': WIPE, 'cleanup_callers': [DROP],
    'evidence': ['crates/brynja-legacy-md5/tests/api.rs', 'assurance/md5-public-api/src/lib.rs',
                 'scripts/md5/check-md5.py', 'scripts/md5/check-md5-codegen.sh'],
    'storage': 'crate-owned-fixed', 'output_classification': 'typed-secret-owned',
    'partial_failure_policy': 'clear-complete-secret-destination',
}


def register(contracts, tests, headers, sanitizers, paths):
    contracts['registered.algorithm.md5'] = {'record': RECORD}
    tests[OWNER] = {'package': 'brynja-legacy-md5', 'contract_test':
                    'owner::assurance_contract::registered_algorithm_md5_owner_contract_is_compiler_checked'}
    headers[DROP] = ['fn owner::<impl at crates/brynja-legacy-md5/src/owner.rs:51:1: 51:23>::drop(_1: &mut Md5Owner) -> () {']
    sanitizers[WIPE] = 'Md5Owner::wipe('
    paths.add('scripts/cryptography/legacy_md5_owner_contract.py')
    paths.update('crates/brynja-legacy-md5/src/' + name + '.rs'
                 for name in ('lib', 'ordinary', 'hardened', 'owner', 'output', 'compress', 'engine'))
    paths.update(RECORD['evidence'])
