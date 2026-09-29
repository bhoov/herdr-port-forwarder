#!/usr/bin/env python3
"""Forward loopback ports that panes on saved Herdr machines print to this computer.

For each enabled saved machine, the daemon keeps one multiplexed SSH connection. Every few
seconds it reads the recent output of each remote pane and finds loopback addresses such as
`http://localhost:5173/`. It probes each announced port through the connection. When the port
accepts connections, it adds a local forward (`ssh -O forward -L`) on the same local port, or
on a nearby one when a local program already uses it. It closes the forward when the port stops
accepting connections. The remote workspace that printed the address gets a `$ports` token for
Space sidebar rows, for example `⇄ 5173 8000→8001`.

Commands:
  start       start the daemon in the background unless one already runs
  run         run the daemon in the foreground
  stop        stop the daemon, close its forwards, and clear its tokens
  restart     stop, then start
  show        list the forwards until q or Esc is pressed (the popup pane)
  open-popup  open the popup pane
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import secrets
import select
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

PLUGIN_ID = "bhoov.port-forwarder"
TOKEN_NAME = "ports"
TOKEN_SOURCE = PLUGIN_ID
TOKEN_PREFIX = "⇄ "
TOKEN_MAX_CHARS = 80
# Ports below this number are system services, not development servers.
MIN_PORT = 1024
# How many following port numbers are tried when the preferred local port is in use.
NEARBY_PORTS = 20
# At most this many announced ports are probed per machine.
MAX_CANDIDATES = 32
READ_LINES = 200
PROBE_OPEN_AFTER = 2.0
MACHINE_REFRESH_SECONDS = 30
RECONNECT_SECONDS = 30
CONNECT_TIMEOUT_SECONDS = 30

HERDR = os.environ.get("HERDR_BIN_PATH") or "herdr"
STATE_DIR = os.environ.get("HERDR_PLUGIN_STATE_DIR") or os.path.expanduser("~/.local/state/herdr-port-forwarder")
CONFIG_DIR = os.environ.get("HERDR_PLUGIN_CONFIG_DIR") or os.path.expanduser("~/.config/herdr-port-forwarder")
LOCK_PATH = os.path.join(STATE_DIR, "daemon.lock")
PID_PATH = os.path.join(STATE_DIR, "daemon.pid")
LOG_PATH = os.path.join(STATE_DIR, "daemon.log")
STATUS_PATH = os.path.join(STATE_DIR, "status.json")
REGISTRY_PATH = os.path.join(STATE_DIR, "registry.json")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
# Unix socket paths are limited to about 104 bytes, so control sockets live in a short directory.
CONTROL_DIR = os.path.join("/tmp", f"hpf-{os.getuid()}")

DEFAULT_CONFIG = {
    "scan_interval_seconds": 3,  # pause between two scans of one machine
    "notify": True,  # show a toast when a forward opens or fails
    "machines": None,  # labels or ids to forward from; null means every enabled machine
}

_LOOPBACK = re.compile(
    r"(?:(?<![A-Za-z0-9._-])(?:localhost|127\.0\.0\.1|0\.0\.0\.0)|\[::1?\]):(\d{1,5})(?![A-Za-z0-9])",
    re.IGNORECASE,
)


def log(message: str) -> None:
    print(time.strftime("%Y-%m-%d %H:%M:%S"), message, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------------------------
# Pure helpers


def announced_ports(text: str) -> List[int]:
    """Return the loopback ports in `text` in order of first appearance."""
    ports: List[int] = []
    for match in _LOOPBACK.finditer(text):
        port = int(match.group(1))
        if MIN_PORT <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def choose_local_port(remote_port: int, remembered: Optional[int], is_free: Callable[[int], bool]) -> Optional[int]:
    """Return the remembered port, else the remote port number, else a nearby free port."""
    if remembered is not None and is_free(remembered):
        return remembered
    for port in range(remote_port, min(remote_port + NEARBY_PORTS, 65535) + 1):
        if is_free(port):
            return port
    return None


def format_token(forwards: List[Tuple[int, int]]) -> str:
    """Format (remote, local) pairs as `⇄ 5173 8000→8001`, capped at the token length limit."""
    text = TOKEN_PREFIX.rstrip()
    for remote, local in sorted(forwards):
        item = str(remote) if remote == local else f"{remote}→{local}"
        if len(text) + 1 + len(item) > TOKEN_MAX_CHARS:
            break
        text += " " + item
    return text if forwards else ""


def split_sections(output: str, nonce: str) -> Dict[str, str]:
    """Split scan output at `@@<nonce> <name>` marker lines into named sections."""
    sections: Dict[str, List[str]] = {}
    current: Optional[List[str]] = None
    marker = f"@@{nonce} "
    for line in output.split("\n"):
        if line.startswith(marker):
            current = sections.setdefault(line[len(marker):].strip(), [])
        elif current is not None:
            current.append(line)
    return {name: "\n".join(lines) for name, lines in sections.items()}


def local_port_is_free(port: int) -> bool:
    """Return whether both loopback addresses can bind `port`."""
    for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.bind((address, port))
        except OSError as error:
            if family == socket.AF_INET6 and error.errno in (errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT):
                continue
            return False
    return True


def load_json(path: str, default):
    try:
        with open(path, encoding="utf-8") as file:
            return json.load(file)
    except (OSError, ValueError):
        return default


def write_json(path: str, value) -> None:
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(value, file, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def load_config() -> dict:
    config = dict(DEFAULT_CONFIG)
    loaded = load_json(CONFIG_PATH, {})
    if isinstance(loaded, dict):
        config.update({key: value for key, value in loaded.items() if key in DEFAULT_CONFIG})
    return config


def notify(title: str, body: str) -> None:
    try:
        subprocess.run([HERDR, "notification", "show", title, "--body", body], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.SubprocessError) as error:
        log(f"notification failed: {error}")


# ---------------------------------------------------------------------------------------------
# Shared daemon state


class Registry:
    """Remembered local ports, so a restarted daemon reuses them. Keyed by machine id."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        data = load_json(REGISTRY_PATH, {})
        self._data: Dict[str, Dict[str, int]] = data if isinstance(data, dict) else {}

    def get(self, machine_id: str, remote_port: int) -> Optional[int]:
        with self._lock:
            return self._data.get(machine_id, {}).get(str(remote_port))

    def set(self, machine_id: str, remote_port: int, local_port: Optional[int]) -> None:
        with self._lock:
            ports = self._data.setdefault(machine_id, {})
            if local_port is None:
                ports.pop(str(remote_port), None)
            else:
                ports[str(remote_port)] = local_port
            write_json(REGISTRY_PATH, self._data)


class Status:
    """What each machine forwards, for the popup."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._machines: Dict[str, dict] = {}

    def update(self, machine_id: str, value: Optional[dict]) -> None:
        with self._lock:
            if value is None:
                self._machines.pop(machine_id, None)
            else:
                self._machines[machine_id] = value
            write_json(STATUS_PATH, {"pid": os.getpid(), "updated": time.time(), "machines": self._machines})


# ---------------------------------------------------------------------------------------------
# One saved machine


@dataclass
class Forward:
    local_port: int
    workspace_id: Optional[str]
    closed_probes: int = 0


@dataclass
class Machine:
    id: str
    label: str
    target: str
    session: str


@dataclass
class ScanResult:
    workspaces: Dict[str, str] = field(default_factory=dict)  # workspace id → label
    ports: Dict[int, str] = field(default_factory=dict)  # announced port → workspace id


REMOTE_HERDR = r"""
H=$(command -v herdr 2>/dev/null) || H=
if [ -z "$H" ]; then
    for c in "$HOME/.local/bin/herdr" /opt/homebrew/bin/herdr /usr/local/bin/herdr /home/linuxbrew/.linuxbrew/bin/herdr "$HOME/.nix-profile/bin/herdr"; do
        if [ -x "$c" ]; then H=$c; break; fi
    done
fi
if [ -z "$H" ]; then echo "herdr is not installed on this machine" >&2; exit 127; fi
"""


class MachineWorker(threading.Thread):
    def __init__(self, machine: Machine, registry: Registry, status: Status, config: dict) -> None:
        super().__init__(name=f"machine-{machine.label}", daemon=True)
        self.machine = machine
        self.registry = registry
        self.status = status
        self.config = config
        self.stop_event = threading.Event()
        self.control_path = os.path.join(CONTROL_DIR, machine.id[:16])
        self.master: Optional[subprocess.Popen] = None
        self.forwards: Dict[int, Forward] = {}
        self.workspace_labels: Dict[str, str] = {}
        self.last_seen: Dict[int, str] = {}  # announced port → workspace id of the last pane that printed it
        self.reported: Dict[str, str] = {}  # workspace id → token value reported to the remote server
        self.error: Optional[str] = None
        self.notified_error: Optional[str] = None

    # -- ssh -------------------------------------------------------------------------------

    def ssh(self, *options: str, command: Tuple[str, ...] = ()) -> List[str]:
        return ["ssh", "-S", self.control_path, "-o", "ControlMaster=no", "-o", "BatchMode=yes", *options, self.machine.target, *command]

    def master_alive(self) -> bool:
        result = subprocess.run(self.ssh("-O", "check"), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0

    def connect(self) -> bool:
        os.makedirs(CONTROL_DIR, mode=0o700, exist_ok=True)
        if os.path.exists(self.control_path):
            # A master left by an earlier daemon holds forwards this daemon does not know.
            subprocess.run(self.ssh("-O", "exit"), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                os.unlink(self.control_path)
            except FileNotFoundError:
                pass
        command = [
            "ssh", "-M", "-N", "-S", self.control_path,
            "-o", "ControlPersist=no",
            # The user's ssh config may declare LocalForward lines; this connection must not bind them.
            "-o", "ClearAllForwardings=yes",
            "-o", "ExitOnForwardFailure=no",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={CONNECT_TIMEOUT_SECONDS}",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            self.machine.target,
        ]
        self.master = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + CONNECT_TIMEOUT_SECONDS + 5
        while time.monotonic() < deadline and not self.stop_event.is_set():
            if self.master.poll() is not None:
                stderr = (self.master.stderr.read() if self.master.stderr else "").strip()
                self.set_error(f"ssh failed: {stderr.splitlines()[-1] if stderr else f'exit {self.master.returncode}'}")
                return False
            if os.path.exists(self.control_path) and self.master_alive():
                threading.Thread(target=self._drain_master_stderr, daemon=True).start()
                log(f"{self.machine.label}: connected")
                return True
            time.sleep(0.3)
        self.set_error("ssh connection timed out")
        self.master.kill()
        return False

    def _drain_master_stderr(self) -> None:
        master = self.master
        if master is None or master.stderr is None:
            return
        for line in master.stderr:
            # Probes of printed ports whose server has stopped fail this way on every scan.
            if "open failed: connect failed" not in line:
                log(f"{self.machine.label}: ssh: {line.rstrip()}")

    def disconnect(self) -> None:
        subprocess.run(self.ssh("-O", "exit"), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.master is not None:
            try:
                self.master.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.master.kill()
        self.master = None

    def remote_script(self, body: str) -> subprocess.CompletedProcess:
        """Run a POSIX sh script on the machine with `$H` set to its herdr binary."""
        prefix = REMOTE_HERDR
        if self.machine.session and self.machine.session != "default":
            prefix += f"export HERDR_SESSION={shlex.quote(self.machine.session)}\n"
        return subprocess.run(self.ssh(command=("sh", "-s")), input=prefix + body, capture_output=True, text=True, timeout=60)

    # -- scanning --------------------------------------------------------------------------

    def token_commands(self, desired: Dict[str, str], refresh: bool) -> str:
        """Commands that report `desired` workspace tokens; unchanged ones only when `refresh`."""
        ttl_ms = int(max(30, 10 * self.config["scan_interval_seconds"]) * 1000)
        lines = []
        for workspace_id in sorted(set(desired) | set(self.reported)):
            value = desired.get(workspace_id, "")
            if not value and workspace_id not in self.reported:
                continue
            if not refresh and self.reported.get(workspace_id) == value:
                continue
            patch = f"--token {shlex.quote(f'{TOKEN_NAME}={value}')} --ttl-ms {ttl_ms}" if value else f"--clear-token {TOKEN_NAME}"
            lines.append(f'"$H" workspace report-metadata {shlex.quote(workspace_id)} --source {TOKEN_SOURCE} {patch} >/dev/null 2>&1')
        return "\n".join(lines) + "\n"

    def scan(self, token_refresh: str) -> Optional[ScanResult]:
        nonce = secrets.token_hex(6)
        body = token_refresh + f"""
printf '@@{nonce} workspaces\\n'; "$H" workspace list
L=$("$H" pane list) || exit $?
printf '\\n@@{nonce} panes\\n%s\\n' "$L"
for p in $(printf '%s' "$L" | tr ',{{' '\\n\\n' | sed -n 's/^"pane_id":"\\([A-Za-z0-9:_.-]*\\)"$/\\1/p'); do
    printf '\\n@@{nonce} read %s\\n' "$p"
    "$H" pane read "$p" --source recent-unwrapped --lines {READ_LINES} 2>/dev/null
done
"""
        try:
            result = self.remote_script(body)
        except subprocess.TimeoutExpired:
            self.set_error("scan timed out")
            return None
        if result.returncode != 0:
            stderr = result.stderr.strip()
            self.set_error(stderr.splitlines()[-1] if stderr else f"scan failed with exit {result.returncode}")
            return None
        sections = split_sections(result.stdout, nonce)
        scan = ScanResult()
        try:
            workspaces = json.loads(sections.get("workspaces", "{}"))["result"]["workspaces"]
            scan.workspaces = {item["workspace_id"]: item.get("label", item["workspace_id"]) for item in workspaces}
            panes = json.loads(sections.get("panes", "{}"))["result"]["panes"]
        except (ValueError, KeyError, TypeError) as error:
            self.set_error(f"unexpected herdr output: {error}")
            return None
        pane_workspace = {pane["pane_id"]: pane.get("workspace_id") for pane in panes}
        for name, text in sections.items():
            if not name.startswith("read "):
                continue
            workspace_id = pane_workspace.get(name[len("read "):])
            for port in announced_ports(text):
                scan.ports[port] = workspace_id
        return scan

    def probe(self, ports: List[int]) -> Dict[int, bool]:
        """Return whether each remote port accepts connections, using one channel per port."""
        processes = {port: subprocess.Popen(self.ssh("-W", f"localhost:{port}"), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for port in ports}
        deadline = time.monotonic() + PROBE_OPEN_AFTER
        results: Dict[int, bool] = {}
        while processes and time.monotonic() < deadline:
            for port, process in list(processes.items()):
                code = process.poll()
                if code is not None:
                    # Exit 0 means the channel opened and the server closed it after our EOF.
                    results[port] = code == 0
                    del processes[port]
            time.sleep(0.05)
        for port, process in processes.items():
            # Still connected: the server accepted and keeps the connection open.
            results[port] = True
            process.kill()
            process.wait()
        return results

    # -- forwards --------------------------------------------------------------------------

    def forward_spec(self, local_port: int, remote_port: int) -> str:
        return f"localhost:{local_port}:localhost:{remote_port}"

    def open_forward(self, remote_port: int, workspace_id: Optional[str]) -> None:
        local_port = choose_local_port(remote_port, self.registry.get(self.machine.id, remote_port), local_port_is_free)
        if local_port is None:
            log(f"{self.machine.label}: no free local port near {remote_port}")
            return
        result = subprocess.run(self.ssh("-O", "forward", "-L", self.forward_spec(local_port, remote_port)), stdin=subprocess.DEVNULL, capture_output=True, text=True)
        if result.returncode != 0:
            message = result.stderr.strip() or f"exit {result.returncode}"
            log(f"{self.machine.label}: forward {remote_port} failed: {message}")
            if self.config["notify"]:
                notify(f"Port forward failed: {self.machine.label}:{remote_port}", message)
            return
        self.forwards[remote_port] = Forward(local_port, workspace_id)
        self.registry.set(self.machine.id, remote_port, local_port)
        source = self.machine.label if local_port == remote_port else f"{self.machine.label}:{remote_port}"
        log(f"{self.machine.label}: forwarding local {local_port} to remote {remote_port}")
        if self.config["notify"]:
            notify(f"Forwarded :{local_port} ← {source}", f"http://localhost:{local_port}/")

    def close_forward(self, remote_port: int, forget: bool) -> None:
        forward = self.forwards.pop(remote_port, None)
        if forward is None:
            return
        subprocess.run(self.ssh("-O", "cancel", "-L", self.forward_spec(forward.local_port, remote_port)), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if forget:
            self.registry.set(self.machine.id, remote_port, None)
        log(f"{self.machine.label}: closed forward of remote {remote_port}")

    def desired_tokens(self) -> Dict[str, str]:
        by_workspace: Dict[str, List[Tuple[int, int]]] = {}
        for remote, forward in self.forwards.items():
            if forward.workspace_id:
                by_workspace.setdefault(forward.workspace_id, []).append((remote, forward.local_port))
        return {workspace_id: format_token(pairs) for workspace_id, pairs in by_workspace.items()}

    def publish_status(self) -> None:
        self.status.update(self.machine.id, {
            "label": self.machine.label,
            "error": self.error,
            "forwards": [
                {"remote_port": remote, "local_port": forward.local_port, "workspace": self.workspace_labels.get(forward.workspace_id or "", forward.workspace_id)}
                for remote, forward in sorted(self.forwards.items())
            ],
        })

    def set_error(self, message: Optional[str]) -> None:
        self.error = message
        if message is None:
            self.notified_error = None
            return
        log(f"{self.machine.label}: {message}")
        if self.config["notify"] and message != self.notified_error:
            self.notified_error = message
            notify(f"Port forwarding stopped: {self.machine.label}", message)

    # -- loop ------------------------------------------------------------------------------

    def cycle(self, refresh_tokens: bool) -> bool:
        desired_before = self.desired_tokens()
        scan = self.scan(self.token_commands(desired_before, refresh_tokens))
        if scan is None:
            return False
        # The scan script reported every changed token, and every token when refreshing.
        self.reported = {key: value for key, value in desired_before.items() if value}
        self.set_error(None)
        self.workspace_labels = scan.workspaces
        for port, workspace_id in scan.ports.items():
            # Reinsert so the dict order is the order of the most recent sighting.
            self.last_seen.pop(port, None)
            self.last_seen[port] = workspace_id
        while len(self.last_seen) > MAX_CANDIDATES:
            self.last_seen.pop(next(iter(self.last_seen)))
        candidates = [port for port in self.last_seen if port not in self.forwards]
        probed = self.probe(candidates + list(self.forwards))
        for remote_port, forward in list(self.forwards.items()):
            if remote_port in scan.ports:
                forward.workspace_id = scan.ports[remote_port]
            forward.closed_probes = 0 if probed.get(remote_port) else forward.closed_probes + 1
            if forward.closed_probes >= 2:
                self.close_forward(remote_port, forget=True)
                self.last_seen.pop(remote_port, None)
        for port in candidates:
            if probed.get(port):
                self.open_forward(port, self.last_seen.get(port))
            elif port not in scan.ports:
                # Closed and no longer on screen: stop probing it.
                self.last_seen.pop(port, None)
        desired = self.desired_tokens()
        commands = self.token_commands(desired, refresh=False)
        if commands.strip() and self.remote_script(commands).returncode == 0:
            self.reported = {key: value for key, value in desired.items() if value}
        self.publish_status()
        return True

    def run(self) -> None:
        interval = float(self.config["scan_interval_seconds"])
        refresh_every = max(1, int(max(30, 10 * interval) / 2 / interval))
        count = 0
        while not self.stop_event.is_set():
            if self.master is None or self.master.poll() is not None:
                self.forwards.clear()  # a dead master closed its listeners
                self.reported.clear()
                if not self.connect():
                    self.publish_status()
                    self.stop_event.wait(RECONNECT_SECONDS)
                    continue
            try:
                ok = self.cycle(refresh_tokens=count % refresh_every == 0)
            except Exception as error:  # a failed cycle must not end the worker
                self.set_error(f"{type(error).__name__}: {error}")
                ok = False
            if not ok:
                self.publish_status()
                if self.master is not None and not self.master_alive():
                    self.master.kill()
            count += 1
            self.stop_event.wait(interval)
        self.shutdown()

    def shutdown(self) -> None:
        """Close forwards and clear tokens, but keep remembered ports for the next daemon."""
        if self.master is not None and self.master.poll() is None:
            for remote_port in list(self.forwards):
                self.close_forward(remote_port, forget=False)
            if self.reported:
                try:
                    self.remote_script(self.token_commands({}, refresh=False))
                except (OSError, subprocess.SubprocessError):
                    pass
            self.disconnect()
        self.status.update(self.machine.id, None)


# ---------------------------------------------------------------------------------------------
# Daemon


def enabled_machines(config: dict) -> List[Machine]:
    result = subprocess.run([HERDR, "machine", "list", "--json"], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "herdr machine list failed")
    selected = config["machines"]
    machines = []
    for item in json.loads(result.stdout):
        if not item.get("enabled"):
            continue
        if selected is not None and item["id"] not in selected and item["label"] not in selected:
            continue
        machines.append(Machine(item["id"], item["label"], item["target"], item.get("session") or "default"))
    return machines


def acquire_lock():
    os.makedirs(STATE_DIR, exist_ok=True)
    handle = open(LOCK_PATH, "a+")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    return handle


def run_daemon() -> int:
    lock = acquire_lock()
    if lock is None:
        log("another daemon already runs")
        return 0
    with open(PID_PATH, "w") as file:
        file.write(str(os.getpid()))
    config = load_config()
    registry = Registry()
    status = Status()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGHUP, lambda *_: stop.set())
    server_socket = os.environ.get("HERDR_SOCKET_PATH")
    workers: Dict[str, MachineWorker] = {}
    missing_server_checks = 0
    log(f"daemon started, pid {os.getpid()}")
    while not stop.is_set():
        if server_socket and not os.path.exists(server_socket):
            missing_server_checks += 1
            if missing_server_checks >= 3:
                log("local herdr server is gone")
                break
        else:
            missing_server_checks = 0
        try:
            machines = {machine.id: machine for machine in enabled_machines(config)}
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            log(f"cannot list machines: {error}")
            machines = {machine_id: worker.machine for machine_id, worker in workers.items()}
        for machine_id, worker in list(workers.items()):
            if machine_id not in machines or machines[machine_id] != worker.machine or not worker.is_alive():
                worker.stop_event.set()
                worker.join(timeout=30)
                del workers[machine_id]
        for machine_id, machine in machines.items():
            if machine_id not in workers:
                worker = MachineWorker(machine, registry, status, config)
                workers[machine_id] = worker
                worker.start()
        stop.wait(MACHINE_REFRESH_SECONDS if missing_server_checks == 0 else 10)
    for worker in workers.values():
        worker.stop_event.set()
    for worker in workers.values():
        worker.join(timeout=30)
    write_json(STATUS_PATH, {"pid": None, "updated": time.time(), "machines": {}})
    try:
        os.unlink(PID_PATH)
    except FileNotFoundError:
        pass
    log("daemon stopped")
    return 0


def daemon_pid() -> Optional[int]:
    handle = acquire_lock()
    if handle is not None:
        handle.close()
        return None
    try:
        with open(PID_PATH) as file:
            return int(file.read().strip())
    except (OSError, ValueError):
        return None


def start_daemon() -> int:
    if acquire_lock_probe():
        print("port forwarder already runs")
        return 0
    os.makedirs(STATE_DIR, exist_ok=True)
    if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 1_000_000:
        os.replace(LOG_PATH, LOG_PATH + ".1")
    with open(LOG_PATH, "a") as log_file:
        subprocess.Popen([sys.executable, os.path.abspath(__file__), "run"], stdin=subprocess.DEVNULL, stdout=log_file, stderr=log_file, start_new_session=True, cwd=os.path.dirname(os.path.abspath(__file__)))
    print(f"port forwarder started; log: {LOG_PATH}")
    return 0


def acquire_lock_probe() -> bool:
    """Return whether a daemon holds the lock."""
    handle = acquire_lock()
    if handle is None:
        return True
    handle.close()
    return False


def stop_daemon() -> int:
    pid = daemon_pid()
    if pid is None:
        print("port forwarder does not run")
        return 0
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline and acquire_lock_probe():
        time.sleep(0.2)
    print("port forwarder stopped" if not acquire_lock_probe() else f"port forwarder (pid {pid}) did not stop")
    return 0


# ---------------------------------------------------------------------------------------------
# Popup


def render_status() -> str:
    status = load_json(STATUS_PATH, {})
    running = acquire_lock_probe()
    lines = [" Forwarded ports", ""]
    if not running:
        lines.append("  The port forwarder does not run.")
        lines.append("  Run the action 'Port forwards: restart' to start it.")
        return "\n".join(lines)
    machines = sorted((status.get("machines") or {}).values(), key=lambda item: item.get("label", ""))
    rows = 0
    for machine in machines:
        for forward in machine.get("forwards", []):
            remote, local = forward["remote_port"], forward["local_port"]
            source = f"{machine['label']}:{remote}"
            note = "  (local port differs)" if remote != local else ""
            workspace = f"  [{forward['workspace']}]" if forward.get("workspace") else ""
            lines.append(f"  http://localhost:{local}/".ljust(30) + f"← {source}{workspace}{note}")
            rows += 1
        if machine.get("error"):
            lines.append(f"  ! {machine['label']}: {machine['error']}")
    if rows == 0:
        lines.append("  No ports are forwarded.")
        if not machines:
            lines.append("  No saved machine is enabled.")
    lines += ["", "  Click a URL to open it. Press q or Esc to close."]
    return "\n".join(lines)


def show_popup() -> int:
    import termios
    import tty

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        sys.stdout.write("\x1b[?25l")
        while True:
            sys.stdout.write("\x1b[H\x1b[2J" + render_status().replace("\n", "\r\n"))
            sys.stdout.flush()
            ready, _, _ = select.select([sys.stdin], [], [], 1.0)
            if ready:
                key = os.read(fd, 16)
                if key[:1] in (b"q", b"Q", b"\x1b", b"\x03"):
                    return 0
    finally:
        sys.stdout.write("\x1b[?25h")
        sys.stdout.flush()
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def open_popup() -> int:
    return subprocess.run([HERDR, "plugin", "pane", "open", "--plugin", PLUGIN_ID, "--entrypoint", "ports"]).returncode


def main(argv: List[str]) -> int:
    commands = {
        "start": start_daemon,
        "run": run_daemon,
        "stop": stop_daemon,
        "restart": lambda: stop_daemon() or start_daemon(),
        "show": show_popup,
        "open-popup": open_popup,
        "status": lambda: print(render_status()) or 0,
    }
    if len(argv) != 2 or argv[1] not in commands:
        print(__doc__, file=sys.stderr)
        return 2
    return commands[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
