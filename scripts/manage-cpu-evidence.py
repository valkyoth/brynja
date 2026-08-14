#!/usr/bin/env python3
"""Persistent detached local and SSH runner for Brynja CPU candidate evidence."""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath

import cpu_evidence_run


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE = ROOT / "target/cpu-evidence-manager/state.sqlite3"
KNOWN_HOSTS = ROOT / "target/cpu-evidence-manager/known_hosts"
DEFAULT_REPOSITORY = "https://github.com/valkyoth/brynja.git"
LANES = tuple(cpu_evidence_run.LANES)
VALID_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
VALID_HOST = re.compile(r"^[A-Za-z0-9.-]+$")
VALID_REMOTE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")


class ManagerError(RuntimeError):
    """Detached evidence orchestration failed closed."""


REMOTE_BOOTSTRAP = r'''set -eu
lane="$1"
commit="$2"
session="$3"
repository="$4"
bootstrap="$5"
attempt="$6"
case "$lane$commit$session$attempt" in *[!A-Za-z0-9._-]*) exit 64;; esac
export PATH="$HOME/.cargo/bin:$PATH"
for command in bash git python3 sed grep awk find wc; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "remote CPU evidence worker is missing $command" >&2
        exit 69
    }
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    echo "remote CPU evidence worker needs sha256sum or shasum" >&2
    exit 69
fi
if ! command -v rustup >/dev/null 2>&1; then
    if [ "$bootstrap" != yes ]; then
        echo "remote CPU evidence worker is missing rustup" >&2
        exit 69
    fi
    command -v curl >/dev/null 2>&1 || exit 69
    installer="$(mktemp)"
    trap 'rm -f "$installer"' EXIT
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$installer"
    sh "$installer" -y --profile minimal
    rm -f "$installer"
    trap - EXIT
fi
work="$HOME/brynja-cpu-$session-$lane-$attempt"
if [ -e "$work" ]; then
    echo "remote CPU evidence worker refuses existing directory: $work" >&2
    exit 73
fi
git clone --filter=blob:none --no-checkout "$repository" "$work"
cd "$work"
git checkout --detach "$commit"
test "$(git rev-parse HEAD)" = "$commit"
test -z "$(git status --porcelain --untracked-files=all)"
toolchain="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml | sed -n '1p')"
test -n "$toolchain"
rustup toolchain install "$toolchain" --profile minimal
mkdir -p target/cpu-evidence-manager
runner=target/cpu-evidence-manager/run.sh
status=target/cpu-evidence-manager/exit-status
cat >"$runner" <<'RUNNER'
#!/usr/bin/env sh
set +e
scripts/capture-sha256-cpu-native.sh "$1" "target/cpu-evidence-native/$1"
code=$?
printf '%s\n' "$code" >"$2.tmp"
mv "$2.tmp" "$2"
exit "$code"
RUNNER
chmod 700 "$runner"
nohup "$runner" "$lane" "$status" >target/cpu-evidence-manager/job.log 2>&1 </dev/null &
pid=$!
printf 'MANAGER_PID=%s\nREMOTE_DIR=%s\n' "$pid" "$work"
'''


REMOTE_STATUS = r'''set -eu
work="$1"
pid="$2"
status="$work/target/cpu-evidence-manager/exit-status"
if [ -s "$status" ]; then
    printf 'MANAGER_STATE=finished\nMANAGER_EXIT='
    cat "$status"
elif kill -0 "$pid" 2>/dev/null; then
    printf 'MANAGER_STATE=running\n'
else
    printf 'MANAGER_STATE=unknown\n'
fi
'''


def git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=ROOT, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def validate_source(connection: sqlite3.Connection) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM session WHERE singleton=1").fetchone()
    if row is None:
        raise ManagerError("CPU evidence session is not initialized")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ManagerError("CPU evidence orchestration requires a clean worktree")
    if git("rev-parse", "HEAD") != row["source_commit"]:
        raise ManagerError("current commit differs from the evidence session")
    if git("rev-parse", "HEAD^{tree}") != row["source_tree"]:
        raise ManagerError("current source tree differs from the evidence session")
    return row


def open_store(path: Path) -> sqlite3.Connection:
    if path.is_symlink():
        raise ManagerError("refusing a symlinked CPU evidence state database")
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    path.chmod(0o600)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS session (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            identifier TEXT NOT NULL, source_commit TEXT NOT NULL,
            source_tree TEXT NOT NULL, repository TEXT NOT NULL,
            bundle_root TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS jobs (
            lane TEXT PRIMARY KEY, status TEXT NOT NULL,
            mode TEXT, host TEXT, port INTEGER, remote_user TEXT,
            key_path TEXT, work_dir TEXT, pid INTEGER, message TEXT NOT NULL
        );
        """
    )
    return connection


def archive_existing_state(path: Path) -> None:
    if not path.exists():
        return
    connection = open_store(path)
    try:
        running = connection.execute(
            "SELECT lane FROM jobs WHERE status='running' LIMIT 1"
        ).fetchone()
        if running is not None:
            raise ManagerError(
                f"cannot archive state while {running['lane']} is marked running"
            )
    finally:
        connection.close()
    archive = path.parent / "archive" / f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
    archive.mkdir(parents=True, exist_ok=False)
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{path}{suffix}")
        if candidate.exists():
            shutil.move(str(candidate), archive / candidate.name)
    print(f"archived_previous_state={archive}")


def initialize(connection: sqlite3.Connection, repository: str, state: Path) -> None:
    if connection.execute("SELECT 1 FROM session").fetchone() is not None:
        raise ManagerError("CPU evidence session already exists")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ManagerError("CPU evidence session requires a clean worktree")
    commit = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    identifier = f"{commit[:12]}-{uuid.uuid4().hex[:8]}"
    root = (state.parent / "sessions" / identifier / "bundles").resolve()
    root.mkdir(parents=True)
    with connection:
        connection.execute(
            "INSERT INTO session VALUES(1,?,?,?,?,?)",
            (identifier, commit, tree, repository, str(root)),
        )
        connection.executemany(
            "INSERT INTO jobs VALUES(?, 'pending', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '')",
            ((lane,) for lane in LANES),
        )
    print(f"session={identifier}")
    print(f"source_commit={commit}")


def job(connection: sqlite3.Connection, lane: str) -> sqlite3.Row:
    if lane not in LANES:
        raise ManagerError("unknown v0.22.2 CPU evidence lane")
    row = connection.execute("SELECT * FROM jobs WHERE lane=?", (lane,)).fetchone()
    if row is None:
        raise ManagerError("CPU evidence session has no matching lane")
    return row


def update(connection: sqlite3.Connection, lane: str, **values: object) -> None:
    allowed = {"status", "mode", "host", "port", "remote_user", "key_path", "work_dir", "pid", "message"}
    if not values or not set(values).issubset(allowed):
        raise ManagerError("invalid CPU evidence job update")
    assignments = ", ".join(f"{key}=?" for key in values)
    with connection:
        connection.execute(
            f"UPDATE jobs SET {assignments} WHERE lane=?",  # noqa: S608
            (*values.values(), lane),
        )


def ssh_options(user: str, host: str, port: int, key: Path, scp: bool = False) -> list[str]:
    if VALID_USER.fullmatch(user) is None or VALID_HOST.fullmatch(host) is None or ".." in host:
        raise ManagerError("SSH user or host contains unsupported characters")
    if not 1 <= port <= 65535 or not key.is_file():
        raise ManagerError("SSH port or private-key path is invalid")
    KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
    if KNOWN_HOSTS.is_symlink():
        raise ManagerError("refusing a symlinked managed known_hosts file")
    KNOWN_HOSTS.touch(mode=0o600, exist_ok=True)
    KNOWN_HOSTS.chmod(0o600)
    command = ["scp" if scp else "ssh", "-F", "/dev/null"]
    command += ["-P" if scp else "-p", str(port), "-i", str(key)]
    command += [
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={KNOWN_HOSTS}", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=15",
    ]
    if not scp:
        command += ["-o", "ServerAliveInterval=30"]
    return command


def start_local(connection: sqlite3.Connection, lane: str) -> None:
    session = validate_source(connection)
    if job(connection, lane)["status"] != "pending":
        raise ManagerError("CPU evidence lane is not pending")
    attempt = f"{int(time.time())}-{os.getpid()}"
    directory = Path(session["bundle_root"]).parent / "logs" / f"{lane}-{attempt}"
    directory.mkdir(parents=True, exist_ok=False)
    status = directory / "exit-status"
    runner = directory / "run.sh"
    candidate = directory / "bundle"
    runner.write_text(
        "#!/usr/bin/env sh\nset +e\n"
        "scripts/capture-sha256-cpu-native.sh "
        f"{shlex.quote(lane)} {shlex.quote(str(candidate))}\n"
        "code=$?\nprintf '%s\\n' \"$code\" >\"$1.tmp\"\nmv \"$1.tmp\" \"$1\"\n",
        encoding="utf-8",
    )
    runner.chmod(0o700)
    with (directory / "job.log").open("wb") as log:
        process = subprocess.Popen(
            [str(runner), str(status)], cwd=ROOT, stdout=log,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
    update(connection, lane, status="running", mode="local", work_dir=str(directory), pid=process.pid, message="detached local worker")
    print(f"{lane}: started local pid {process.pid}")


def start_remote(connection: sqlite3.Connection, arguments: argparse.Namespace) -> None:
    session = validate_source(connection)
    lane = arguments.lane
    if job(connection, lane)["status"] != "pending":
        raise ManagerError("CPU evidence lane is not pending")
    key = arguments.key.expanduser().resolve()
    command = ssh_options(arguments.user, arguments.host, arguments.port, key) + [
        f"{arguments.user}@{arguments.host}", "bash", "-s", "--", lane,
        session["source_commit"], session["identifier"], session["repository"],
        "yes" if arguments.bootstrap_rustup else "no", f"{int(time.time())}-{os.getpid()}",
    ]
    result = subprocess.run(command, input=REMOTE_BOOTSTRAP, text=True, capture_output=True)
    if result.returncode != 0:
        raise ManagerError(f"remote setup failed: {result.stderr.strip()}")
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if line.startswith("MANAGER_") or line.startswith("REMOTE_DIR="))
    if set(values) != {"MANAGER_PID", "REMOTE_DIR"} or not values["MANAGER_PID"].isdigit():
        raise ManagerError("remote setup returned an invalid worker identity")
    remote = PurePosixPath(values["REMOTE_DIR"])
    if not remote.is_absolute() or ".." in remote.parts or VALID_REMOTE_PATH.fullmatch(str(remote)) is None:
        raise ManagerError("remote setup returned an invalid work directory")
    expected = f"brynja-cpu-{session['identifier']}-{lane}-"
    if not remote.name.startswith(expected):
        raise ManagerError("remote work directory does not match this session")
    update(
        connection, lane, status="running", mode="remote", host=arguments.host,
        port=arguments.port, remote_user=arguments.user, key_path=str(key),
        work_dir=str(remote), pid=int(values["MANAGER_PID"]), message="detached SSH worker",
    )
    print(f"{lane}: detached on {arguments.host} as pid {values['MANAGER_PID']}")


def finish_bundle(connection: sqlite3.Connection, lane: str, bundle: Path) -> None:
    session = validate_source(connection)
    manifest = cpu_evidence_run.validate_bundle(bundle)
    if manifest["lane"] != lane or manifest["source_commit"] != session["source_commit"] or manifest["source_tree"] != session["source_tree"]:
        raise ManagerError("candidate bundle differs from the pinned session source")
    update(connection, lane, status="complete", message="bundle verified locally")


def check(connection: sqlite3.Connection, lane: str) -> None:
    row = job(connection, lane)
    session = validate_source(connection)
    if row["status"] != "running":
        print(f"{lane}: {row['status']}")
        return
    if row["mode"] == "local":
        status = Path(row["work_dir"]) / "exit-status"
        if not status.is_file():
            try:
                os.kill(row["pid"], 0)
            except (OSError, TypeError):
                update(connection, lane, status="unknown", message="local worker disappeared")
                print(f"{lane}: unknown")
                return
            print(f"{lane}: running")
            return
        code = status.read_text(encoding="ascii").strip()
        if code != "0":
            update(connection, lane, status="failed", message=f"local exit {code}")
            print(f"{lane}: failed")
            return
        candidate = Path(row["work_dir"]) / "bundle"
        cpu_evidence_run.validate_bundle(candidate)
        destination = Path(session["bundle_root"]) / lane
        shutil.move(str(candidate), destination)
        finish_bundle(connection, lane, destination)
        print(f"{lane}: complete")
        return
    key = Path(row["key_path"])
    query = ssh_options(row["remote_user"], row["host"], row["port"], key) + [
        f"{row['remote_user']}@{row['host']}", "bash", "-s", "--", row["work_dir"], str(row["pid"]),
    ]
    result = subprocess.run(query, input=REMOTE_STATUS, text=True, capture_output=True, check=True)
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if line.startswith("MANAGER_"))
    if values.get("MANAGER_STATE") == "running":
        print(f"{lane}: running")
        return
    if values.get("MANAGER_STATE") != "finished" or values.get("MANAGER_EXIT") != "0":
        update(connection, lane, status="failed", message="remote worker failed or disappeared")
        print(f"{lane}: failed")
        return
    destination = Path(session["bundle_root"]) / lane
    with tempfile.TemporaryDirectory(prefix=f".{lane}-", dir=destination.parent) as temporary:
        source = f"{row['remote_user']}@{row['host']}:{row['work_dir']}/target/cpu-evidence-native/{lane}"
        command = ssh_options(row["remote_user"], row["host"], row["port"], key, scp=True) + ["-r", source, temporary]
        subprocess.run(command, check=True)
        downloaded = Path(temporary) / lane
        cpu_evidence_run.validate_bundle(downloaded)
        shutil.move(str(downloaded), destination)
    finish_bundle(connection, lane, destination)
    print(f"{lane}: complete")


def import_bundle(connection: sqlite3.Connection, lane: str, source: Path) -> None:
    session = validate_source(connection)
    if job(connection, lane)["status"] not in {"pending", "failed"}:
        raise ManagerError("CPU evidence lane cannot accept an imported bundle")
    destination = Path(session["bundle_root"]) / lane
    if destination.exists() or destination.is_symlink():
        raise ManagerError("CPU evidence destination already exists")
    cpu_evidence_run.validate_bundle(source)
    shutil.copytree(source, destination, symlinks=False)
    finish_bundle(connection, lane, destination)
    print(f"{lane}: imported and verified")


def reset_job(connection: sqlite3.Connection, lane: str) -> None:
    validate_source(connection)
    row = job(connection, lane)
    if row["status"] not in {"failed", "unknown"}:
        raise ManagerError("only a failed or unknown CPU evidence job can be reset")
    update(
        connection,
        lane,
        status="pending",
        mode=None,
        host=None,
        port=None,
        remote_user=None,
        key_path=None,
        work_dir=None,
        pid=None,
        message="",
    )
    print(f"{lane}: reset to pending; prior logs and remote work are retained")


def show_status(connection: sqlite3.Connection) -> None:
    session = validate_source(connection)
    print(f"session={session['identifier']}")
    print(f"source_commit={session['source_commit']}")
    for row in connection.execute("SELECT lane,status,message FROM jobs ORDER BY lane"):
        print(f"{row['lane']}={row['status']} {row['message']}".rstrip())


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--state", type=Path, default=DEFAULT_STATE)
    commands = result.add_subparsers(dest="command", required=True)
    initialize_parser = commands.add_parser("init")
    initialize_parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    initialize_parser.add_argument(
        "--new", action="store_true", help="archive completed/failed state and start again"
    )
    for name in ("start-local", "check", "reset"):
        child = commands.add_parser(name)
        child.add_argument("lane", choices=LANES)
    remote = commands.add_parser("start-remote")
    remote.add_argument("lane", choices=LANES)
    remote.add_argument("--host", required=True)
    remote.add_argument("--user", default="ubuntu")
    remote.add_argument("--port", type=int, default=22)
    remote.add_argument("--key", type=Path, required=True)
    remote.add_argument("--bootstrap-rustup", action="store_true")
    imported = commands.add_parser("import")
    imported.add_argument("lane", choices=LANES)
    imported.add_argument("bundle", type=Path)
    commands.add_parser("status")
    return result


def main() -> int:
    arguments = parser().parse_args()
    state = arguments.state.expanduser().resolve()
    try:
        if arguments.command == "init" and arguments.new:
            archive_existing_state(state)
        connection = open_store(state)
        try:
            if arguments.command == "init":
                initialize(connection, arguments.repository, state)
            elif arguments.command == "start-local":
                start_local(connection, arguments.lane)
            elif arguments.command == "start-remote":
                start_remote(connection, arguments)
            elif arguments.command == "check":
                check(connection, arguments.lane)
            elif arguments.command == "import":
                import_bundle(connection, arguments.lane, arguments.bundle.resolve())
            elif arguments.command == "reset":
                reset_job(connection, arguments.lane)
            else:
                show_status(connection)
        finally:
            connection.close()
    except (ManagerError, cpu_evidence_run.CandidateRunError, OSError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(f"CPU evidence manager: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
