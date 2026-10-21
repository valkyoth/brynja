"""Actual mapping-access/clear definitions used by hosted HMAC Output loans."""
import itertools
import re

import hmac_engine_codegen as common
import hmac_engine_final as syntax
import hmac_hosted_lifecycle as lifecycle
import hmac_hosted_loan_flow as flow

require = common.require


def names_for(target):
    _, resource = lifecycle.profile(target)
    mapping = '<' + resource + '::Mapping>'
    clear = (mapping if target == 'aarch64-apple-darwin' else
             '<brynja_crypto_cpu_std::protected_memory::ProtectedBytes>') + '::clear'
    return clear, mapping + '::bytes'


def fields(apple, present=1, admitted=1, same_pid=1, used=17, payload=4096, pid=91):
    return {('storage', 0): ('bytes', 0), ('storage', 8): ('base', 0) if present else None,
            ('storage', 24 if apple else 16): payload, ('storage', 40): used,
            ('storage', 52 if apple else 48): admitted,
            **({('storage', 48): pid if same_pid else pid + 1} if apple else {})}


def field_types(apple):
    return {('storage', 0): 'ptr', ('storage', 8): 'ptr', ('storage', 40): 'i64',
            ('storage', 24 if apple else 16): 'i64', ('storage', 52 if apple else 48): 'i8',
            **({('storage', 48): 'i32'} if apple else {})}


def check(arguments, body, names, target, method):
    apple = target == 'aarch64-apple-darwin'
    formals = syntax.parameters(arguments)
    require(len(formals) == 1 and re.fullmatch(r'ptr [^%]*%self', formals[0])
            and 'dereferenceable(56)' in formals[0], 'loan resource formal changed')
    require(method == 'clear' or apple and method == 'bytes', 'unknown loan resource method')
    visited = set()
    for present, admitted, same_pid, used, payload, pid in itertools.product(
            (0, 1), (0, 1), (0, 1) if apple else (1,), (17, 63), (4096, 16384), (91, 31337) if apple else (91,)):
        events = []
        live = bool(present and admitted and same_pid)

        def call(symbol, args, value):
            name = names.get(symbol, symbol)
            if name == 'getpid':
                require(apple and args == [''], 'unexpected loan PID query')
                return 'return', pid
            if name == 'std::process::abort':
                require(apple and method == 'bytes' and not live and not events,
                        'valid mapping aborts or invalid mapping escaped before abort')
                return 'abort', None
            require(name == 'brynja_core::secret_memory::clear_owned_region' and method == 'clear'
                    and len(args) == 2, 'unknown loan resource callee')
            require(live and not events and value(args[0]) == ('bytes', 0)
                    and value(args[1]) == payload, 'loan resource clearing identity/extent/admission')
            events.append('clear')
            return 'return', flow.expressions.Unknown()

        def load(address, kind):
            require(field_types(apple).get(address) == kind, 'loan resource field type changed')
            if method == 'bytes' and address in (('storage', 0), ('storage', 40)):
                require(live, 'invalid mapping payload read')

        outcome, result, reached = flow.run(body, {'%self': ('storage', 0)},
            fields(apple, present, admitted, same_pid, used, payload, pid), call, load=load)
        if method == 'bytes':
            require((outcome == 'return' and result == (('bytes', 0), used)) if live
                    else outcome == 'abort', 'loan resource access admission/result')
        else:
            require(outcome == 'return' and result is None and events == (['clear'] if live else []),
                    'loan resource clearing missing or unexpected exit')
        visited |= reached
    require(visited == set(common.blocks(body)), 'unreviewed loan resource path')


def validate(llvm, target):
    definitions, aliases = common.definitions_and_aliases(llvm)
    names = lifecycle.demangle({s.strip('"') for s in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
    clear, access = names_for(target)
    selected = []
    helpers = [(clear, 'clear')] + ([(access, 'bytes')] if target == 'aarch64-apple-darwin' else [])
    for expected, method in helpers:
        matches = [symbol for symbol in (*definitions, *aliases) if names[symbol] == expected]
        require(len(matches) == 1, 'missing/ambiguous loan resource helper')
        arguments, body = common.resolve(matches[0], definitions, aliases)
        check(arguments, body, names, target, method)
        selected.append((arguments, body, names, method))
    return selected
