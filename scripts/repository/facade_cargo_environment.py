"""Private, config-free Cargo working directories for facade acceptance only."""
import os
from pathlib import Path
import tempfile


def reject_ancestor_config(directory):
    path = Path(directory).absolute()
    for start in (path, path.resolve()):
        for parent in (start, *start.parents):
            for name in ('config', 'config.toml'):
                config = parent / '.cargo' / name
                if config.exists() or config.is_symlink():
                    raise ValueError('ambient Cargo config is forbidden: ' + str(config))


def check(directory, environment):
    reject_ancestor_config(directory)
    home = Path(environment['CARGO_HOME'])
    for name in ('config', 'config.toml'):
        config = home / name
        if config.exists() or config.is_symlink():
            raise ValueError('ambient Cargo home config is forbidden: ' + str(config))


def private_directory(root):
    base = root / 'target'
    reject_ancestor_config(base)
    base.mkdir(exist_ok=True)
    if base.stat().st_uid != os.getuid():
        raise ValueError('Cargo temporary base is not owned by the current user')
    # Do not trust TMPDIR or a shared /tmp parent for executable Cargo inputs.
    for parent in (base.resolve(), *base.resolve().parents):
        status = parent.stat()
        if status.st_mode & 0o022:
            raise ValueError('untrusted Cargo working-directory ancestor: ' + str(parent))
    return tempfile.TemporaryDirectory(prefix='facade-acceptance-', dir=base)
