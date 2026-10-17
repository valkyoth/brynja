"""Compiled consumer ownership probes; no execution or evidence-only features."""
from facade_tuplehash_probes import diagnostic

OWNERS = ('batch::Workspace', 'Collector', 'Reader', 'Stream', 'batch::Stream')


def negatives(api, consumer, package, cargo, env):
    path = consumer / 'src/lib.rs'
    original = path.read_text()
    count = 0
    try:
        for owner in OWNERS:
            typename = 'api::parallelhash::execution::' + owner
            api.source(consumer, package, f'pub fn present(_: Option<{typename}>) {{}}\n')
            api.run(cargo + ['check', '--offline', '--lib'], consumer, env)
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                api.source(consumer, package, f'fn require<T:{bound}>() {{}}\n'
                           f'pub fn probe() {{ require::<{typename}>(); }}\n')
                result = api.run(cargo + ['check', '--offline', '--lib', '--message-format=json'],
                                 consumer, env, success=False)
                api.require(diagnostic(result, 'E0277'), 'ParallelHash ownership diagnostic: ' + owner)
                count += 1
    finally:
        path.write_text(original)
    api.require(count == 25, 'ParallelHash ownership population')
    print(f'PASS: {package}: 25 ParallelHash owner trait rejections', flush=True)
