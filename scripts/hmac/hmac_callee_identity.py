"""Exact reviewed monomorphization contexts, not a substitute for callee checks.

The same generic HMAC implementation is emitted in the execution-only fixture
and in the hosted fixture. Only the instantiating crate suffix differs. Callers
must still resolve and inspect the actual definition and bind its arguments,
storage, ownership and typed algorithm; never rewrite an emitted symbol/IR.
"""

CONTEXT = r"(?:29brynja_hmac_execution_cleanup|34brynja_hmac_hosted_cleanup_fixture)"
