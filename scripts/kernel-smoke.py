#!/usr/bin/python3 -I
"""Opt-in real-daemon enforcement check, confined to a fresh network namespace."""
import argparse
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target/debug/snitchgate"


def wait_for(predicate, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(0.1)
    raise RuntimeError("isolated smoke check deadline expired")


def control(path, message):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(3)
        stream.connect(str(path))
        stream.sendall(json.dumps(message).encode() + b"\n")
        response = b""
        while not response.endswith(b"\n"):
            chunk = stream.recv(65536)
            if not chunk:
                raise RuntimeError("isolated broker closed control connection")
            response += chunk
        result = json.loads(response)
        if result.get("error"):
            raise RuntimeError("isolated broker rejected operation")
        return result


def namespace(root, uid, gid):
    if os.geteuid() != 0:
        raise RuntimeError("namespace worker needs root")
    os.umask(0o077)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    rules = root / "rules"
    rules.mkdir(mode=0o700)
    abstract_name = f"snitchgate-kernel-{os.getpid()}"
    config = {
        "Server": {"Address": "unix:@snitchgate-unavailable-" + str(os.getpid()),
                   "Authentication": {"Type": "simple"}, "LogFile": str(root / "daemon.log")},
        "DefaultAction": "deny", "DefaultDuration": "once", "InterceptUnknown": True,
        "ProcMonitorMethod": "proc", "Firewall": "nftables", "LogLevel": 2,
        "FwOptions": {"ConfigPath": str(root / "system-fw.json"), "QueueNum": 11347,
                      "QueueBypass": False, "MonitorInterval": "15s"},
        "Rules": {"Path": str(rules), "EnableChecksums": False},
        "Internal": {"GCPercent": 100, "FlushConnsOnStart": False},
        "Stats": {"MaxEvents": 20, "MaxStats": 10, "Workers": 2},
    }
    path = root / "daemon-config.json"
    path.write_text(json.dumps(config))
    original_config = path.read_bytes()
    # System-wide rules are disabled; only the isolated daemon's queueing rules
    # are needed. Never open or copy the live host's rules/configuration.
    (root / "system-fw.json").write_text(json.dumps({"Enabled": False, "Version": 1, "SystemRules": []}))

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"snitchgate-kernel-fixture")

        def log_message(self, *args):
            pass

    fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 18081), Handler)
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    with (root / "daemon-output.log").open("w") as output:
        broker = subprocess.Popen([str(BIN), "serve", "--config", str(root / "broker.toml"),
                                   "--runtime-dir", str(root / "runtime"), "--state-dir", str(root / "state"),
                                   "--manual", "--abstract-name", abstract_name],
                                  user=uid, group=gid, stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        wait_for((root / "runtime/control.sock").exists)
        daemon = subprocess.Popen(["/usr/bin/opensnitchd", "-config-file", str(path),
                                   "-rules-path", str(rules), "-workers", "2"],
                                  stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        wait_for((root / "daemon.log").exists)
        time.sleep(2)
        # sudo keeps the invoking user's home in SUDO_USER, while root's HOME is
        # /root. Resolve the tested helper through the owner's passwd record.
        import pwd
        helper = Path(pwd.getpwuid(uid).pw_dir) / "noelarchy/bin/opensnitch-snitchgate-trial"
        handover = subprocess.Popen([sys.executable, "-I", str(helper), "trial", "--config-file", str(path),
                                    "--runtime-dir", str(root / "trial"), "--abstract-name", abstract_name,
                                    "--owner-uid", str(uid), "--seconds", "60"], stdout=output, stderr=output)
        try:
            (root / "namespace.json").write_text(json.dumps({"pid": os.getpid()}))
            os.chown(root / "namespace.json", uid, gid)
            while not stopped.wait(0.25):
                if daemon.poll() is not None:
                    raise RuntimeError("isolated daemon exited; inspect private smoke logs")
        finally:
            try:
                handover.terminate()
                handover.wait(timeout=10)
                mounted = any(line.split()[4] == str(path) for line in Path('/proc/self/mountinfo').read_text().splitlines())
                assert path.read_bytes() == original_config and not mounted, "hot trial did not restore original config"
                assert daemon.poll() is None, "daemon exited during hot handover"
            finally:
                daemon.terminate()
                try:
                    daemon.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()
                fixture.shutdown()
                broker.terminate()
                broker.wait(timeout=5)
                for directory, folders, files in os.walk(root):
                    for name in [*folders, *files]:
                        os.chown(Path(directory) / name, uid, gid, follow_symlinks=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", type=Path)
    parser.add_argument("--uid", type=int)
    parser.add_argument("--gid", type=int)
    args = parser.parse_args()
    if args.namespace:
        namespace(args.namespace, args.uid, args.gid)
        return
    if os.geteuid() == 0:
        raise RuntimeError("run the controller as your ordinary user, with sudo available")
    os.umask(0o077)
    runtime = Path(os.environ["XDG_RUNTIME_DIR"])
    root = Path(tempfile.mkdtemp(prefix="snitchgate-kernel-", dir=runtime))
    (root / "broker.toml").write_text("request_timeout_seconds=3\n")
    with (root / "broker.log").open("w") as log:
        worker = None
        child = None
        try:
            path = root / "runtime/control.sock"
            worker = subprocess.Popen(["sudo", "-n", "unshare", "--net", "--mount", "--propagation", "private",
                                       sys.executable, "-I", str(Path(__file__).resolve()), "--namespace", str(root),
                                       "--uid", str(os.getuid()), "--gid", str(os.getgid())],
                                      stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            wait_for((root / "namespace.json").exists)
            child = json.loads((root / "namespace.json").read_text())["pid"]
            wait_for(lambda: control(path, {"command": "snapshot"})["snapshot"]["health"]["daemon"])
            for action in ["allow", "deny", "timeout"]:
                curl = subprocess.Popen(["sudo", "-n", "nsenter", "-t", str(child), "-n", "/usr/bin/curl",
                                         "--silent", "--show-error", "--noproxy", "*", "--max-time", "8",
                                         "http://127.0.0.1:18081/"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                entries = wait_for(lambda: control(path, {"command": "snapshot"})["snapshot"]["pending"])
                entry = entries[0]
                if action != "timeout":
                    control(path, {"command": "decide", "id": entry["id"], "action": action, "duration": "once"})
                stdout, _ = curl.communicate(timeout=12)
                if action == "allow":
                    assert curl.returncode == 0 and stdout == b"snitchgate-kernel-fixture", "allow did not reach fixture"
                else:
                    assert curl.returncode != 0 and not stdout, "denied traffic reached fixture"
                print(f"isolated kernel enforcement: {action} passed", flush=True)
            assert not list((root / "rules").glob("*.json")), "temporary decisions persisted"
        except BaseException:
            print(f"Private smoke evidence retained at {root}", file=sys.stderr)
            raise
        finally:
            if child:
                subprocess.run(["sudo", "-n", "kill", "-TERM", str(child)], check=False)
            if worker:
                try:
                    status = worker.wait(timeout=15)
                    if status:
                        raise RuntimeError("isolated namespace cleanup or rollback failed")
                except subprocess.TimeoutExpired:
                    worker.terminate()
    print("PASS: real daemon allow/deny/timeout, hot handover/rollback, original config unchanged, no permanent rules; host network unchanged.")


if __name__ == "__main__":
    main()
