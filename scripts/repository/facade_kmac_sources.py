"""Exact adaptations from test-conformance fixtures to production KMAC APIs."""
import re

COUNTS = {
    'main.rs': {}, 'selection.rs': {},
    'dispatch.rs': {'conformance::execution': 1, 'new_bits_conformance': 4,
                    'finalize_tag_bits_conformance': 2, 'finalize_bits_xof_conformance': 2},
    'lifecycle.rs': {'conformance::execution': 1, 'new_bits_conformance': 4,
                     'finalize_secret_bits_conformance': 1, 'verify_bits_conformance': 2,
                     'finalize_bits_xof_conformance': 1, 'finalize_xof_conformance': 1},
    'scoped.rs': {'conformance::execution': 1, 'with_bits_and_scratch_conformance': 1,
                  'with_bits_conformance': 2, 'finalize_tag_bits_conformance': 1,
                  'finalize_secret_bits_conformance': 1, 'verify_bits_conformance': 1},
    'scoped_xof.rs': {'conformance::execution': 1, 'with_bits_and_scratch_conformance': 1,
                      'with_bits_conformance': 2, 'finalize_bits_xof_conformance': 3},
}


def require(value, message):
    if not value:
        raise ValueError('facade KMAC source: ' + message)


def once(text, before, after):
    require(text.count(before) == 1, 'adaptation anchor')
    return text.replace(before, after)


def production(name, text):
    require(name in COUNTS, 'unknown fixture module')
    for before, count in COUNTS[name].items():
        require(text.count(before) == count, 'conformance adaptation count: ' + before)
        after = 'execution' if before == 'conformance::execution' else before.removesuffix('_conformance')
        text = text.replace(before, after)
    require('conformance' not in text, 'remaining conformance path')
    return text


def execution_tests(text):
    text = once(text, '#![cfg(feature = "hardened-execution")]', '#![forbid(unsafe_code)]')
    start = '#[test]\n#[cfg(feature = "conformance-testing")]\n'
    end = '#[test]\nfn portable_execution_tags_match_and_outputs_are_transactional'
    require(text.count(start) == text.count(end) == 1, 'conformance-only test boundary')
    prefix, rest = text.split(start)
    omitted, suffix = rest.split(end)
    require(omitted.startswith('fn separate_test_owners_do_not_weaken_production_transitions()') and
            omitted.count('#[test]') == 0, 'only omit the separate test-owner test')
    text = prefix + end + suffix
    require('conformance' not in text and text.count('#[test]') == 7, 'production test inventory')
    return text


def scoped_tests(name, text):
    if name == 'scoped/xof.rs':
        # The facade deliberately cannot create the separate conformance owner.
        # Keep the weak-key rejection using the production constructor instead.
        text = once(text, 'brynja_mac_kmac::conformance::execution::in_place',
                    'brynja_mac_kmac::execution::in_place')
        text = once(text, '.with_conformance(&[1],', '.with(&[1],')
        text = once(text, 'Ok(Err(KmacError::KeyTooShort))', 'Err(KmacError::KeyTooShort)')
    require('conformance' not in text, 'scoped conformance leak')
    return '#![forbid(unsafe_code)]\n' + text


def rewrite(text, package):
    require(package in ('brynja', 'brynja-crypto'), 'unknown facade')
    namespace = 'facade::crypto' if package == 'brynja' else 'facade'
    text = text.replace('brynja_crypto_cpu_std', 'host').replace('brynja_crypto_cpu', namespace + '::cpu')
    text = text.replace('brynja_mac_kmac', namespace + '::kmac')
    require(not re.search(r'\bbrynja_[a-z_]+\b', text), 'unexpected leaf import')
    return text
