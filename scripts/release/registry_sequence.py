"""Reconcile the signed plan against registry state before attempting uploads."""
import registry_ownership as registry
import registry_transport as transport


def reconcile(plan, all_steps, steps):
    trusted = registry.owners('brynja')
    active = {}
    for name in all_steps:
        row = registry.inspect(name, plan['crates'][name], trusted)
        if row is not None:
            active[name] = row
        elif name not in steps:
            raise ValueError(f'--start-at would skip missing {name}; rerun without --start-at')
    return trusted, active


def sequence(plan, all_steps, steps, publish, *, status=False):
    trusted, active = reconcile(plan, all_steps, steps)
    pace = transport.Pace()
    for name in all_steps:
        entry = plan['crates'][name]
        print(f"{name} {entry['version']}: {'published' if name in active else 'pending'}")
        if name in active:
            pace.recorded(entry['change'] == 'initial', timestamp(name, active[name]))
    if status:
        return
    for name in all_steps:
        entry = plan['crates'][name]
        initial, version = entry['change'] == 'initial', entry['version']
        uploaded = False
        if name not in active:
            pace.wait(initial)
            for attempt in range(4):
                # Also reconcile after waiting: a prior ambiguous upload or
                # another operator may now be visible. Never retry it blindly.
                row = registry.inspect(name, entry, trusted)
                if row is not None:
                    pace.recorded(initial, timestamp(name, row))
                    break
                try:
                    publish(name)
                except transport.UploadLimited as exc:
                    if attempt == 3:
                        raise RuntimeError(f'{name}: repeated upload limits; rerun later to resume') from exc
                    seconds = transport.retry_seconds(exc.hint, transport.INITIAL if initial else transport.UPDATE)
                    transport.delay(seconds, f'{name}: crates.io rejected upload (429)')
                    continue
                pace.recorded(initial)
                uploaded = True
                break
        # A resumed prerequisite may be in the API before the sparse index.
        transport.wait_index(name, version)
        if initial and uploaded:
            registry.indexed(name, version, trusted, just_uploaded=True)


def timestamp(name, row):
    created = row.get('created_at')
    if not isinstance(created, str):
        raise ValueError(f'missing registry publication date for {name}')
    return created
