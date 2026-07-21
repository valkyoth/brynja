# Modularity Policy

Status: enforced policy

Rust source files must remain at or below 500 lines, including tests and module
documentation. New code should split around 450 lines. Splits follow security
and ownership boundaries, not arbitrary line counts.

The modern facade may depend only on modern production crates. Historical
packages may reuse reviewed primitive crates but may not be dependencies,
features, modules, or fallback paths of `brynja`. Repository-only packages
must remain unpublished. Scripts check the dependency graph, manifest policy,
README synchronization, and source-file lengths.

