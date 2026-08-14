#!/usr/bin/env python3
"""Loopback strict-v0.2 live-app interoperability evidence."""
import argparse
import importlib.util
import json
import queue
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "rust"
REFERENCE = ROOT / "reference" / "r8ref.py"
VECTORS = ROOT / "tests" / "vectors" / "wire-v0.2.json"
R8D = RUST / "target" / "debug" / "r8d"
R8PING = RUST / "target" / "debug" / "r8ping"


def reference_codec():
    spec = importlib.util.spec_from_file_location("r8ref_codec", REFERENCE)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


REF = reference_codec()


class Child:
    def __init__(self, name, command):
        self.name, self.lines, self.events = name, [], queue.Queue()
        self.process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        assert self.process.stdout
        for line in self.process.stdout:
            self.lines.append(line.rstrip())
            self.events.put(line)

    def wait_for(self, text, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"{self.name} exited")
            if any(text in line for line in self.lines):
                return
            try:
                self.events.get(timeout=.1)
            except queue.Empty:
                pass
        raise AssertionError(f"{self.name} did not emit {text}")

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.reader.join(timeout=1)


class ScriptedEchoPeer:
    """Independent reference-codec peer emitting hostile replies before the answer."""
    def __init__(self):
        self.expected = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.expected.bind(("127.0.0.1", 0))
        self.wrong = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.wrong.bind(("127.0.0.1", 0))
        self.port = self.expected.getsockname()[1]
        self.done = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            packet, client = self.expected.recvfrom(65535)
            header, payload = REF.Header.unpack(packet)
            kind, code, body = REF.parse_ctl(header, payload)
            if kind != REF.CTL_ECHO_REQUEST or code != 0:
                raise AssertionError("unexpected request")
            reply_header = REF.Header(REF.NH_CTL, header.dst, header.src)
            exact = REF.build_ctl(reply_header, REF.CTL_ECHO_REPLY, 0, body)
            stale = bytearray(body)
            stale[-1] ^= 1
            stale_reply = REF.build_ctl(reply_header, REF.CTL_ECHO_REPLY, 0, stale)
            self.expected.sendto(b"\x80", client)
            self.expected.sendto(stale_reply, client)
            self.wrong.sendto(exact, client)
            time.sleep(.05)
            self.expected.sendto(exact, client)
        except Exception as error:  # recorded and surfaced by wait(), never masked
            self.error = error
        finally:
            self.done.set()

    def wait(self):
        if not self.done.wait(3):
            raise AssertionError("scripted peer did not complete")
        if self.error:
            raise AssertionError("scripted peer failed") from self.error

    def stop(self):
        self.expected.close()
        self.wrong.close()
        self.thread.join(timeout=1)


def run(command, cwd=ROOT):
    return subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def checked(command, cwd=ROOT):
    result = run(command, cwd)
    if result.returncode:
        raise AssertionError("command failed")
    return result.stdout


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def malformed_packets():
    return [bytes.fromhex(case["packet_hex"])
            for case in json.loads(VECTORS.read_text())["negative_cases"]]


def inject(packets, *ports):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for packet in packets:
            for port in ports:
                sock.sendto(packet, ("127.0.0.1", port))


def action(actions, selector, started, evidence, exit_code=0):
    actions.append({"type": "custom", "selector": selector, "target": selector,
                    "startedAt": started, "endedAt": time.monotonic(), "exitCode": exit_code,
                    "stdout": f"captured_bytes={len(evidence.encode())}"})


def assertion(assertions, selector, evidence):
    now = time.monotonic()
    assertions.append({"selector": selector, "status": "passed", "startedAt": now,
                       "endedAt": now, "evidence": evidence})


def report(path, source_id, started, actions, assertions):
    for ordinal, entry in enumerate(actions + assertions, 1):
        entry["timestamp"] = ordinal
    body = {"schemaVersion": 1, "surface": "cli", "tool": "tests/interop.py",
            "sourceId": source_id, "toolchain": {"python": sys.version.split()[0]},
            "environment": {"platform": sys.platform}, "startedAt": started,
            "endedAt": time.monotonic(), "actions": actions, "assertions": assertions}
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps(body, indent=2) + "\n")
    temporary.replace(destination)


def client_command(kind, peer, target, timeout="200", budget=None, payload=None):
    if kind == "rust":
        command = [str(R8PING), "--address", "8:1::10", "--peer", f"{target}={peer}",
                   "--bind", "127.0.0.1:0", "--timeout-ms", timeout]
        if payload is None:
            command += ["--count", "1", target]
        else:
            command += ["--dgram", payload, target]
    else:
        command = [sys.executable, "-u", str(REFERENCE), "ping", "--address", "8:1::20",
                   "--peer", f"{target}={peer}", "--bind", "127.0.0.1", "--count", "1",
                   "--timeout", str(float(timeout) / 1000), target]
    if budget is not None:
        command += ["--binding-budget", str(budget)]
    return command


def scripted_client_case(kind, actions, assertions):
    peer = ScriptedEchoPeer()
    try:
        target = "8:1::20" if kind == "rust" else "8:1::10"
        point = time.monotonic()
        result = run(client_command(kind, f"127.0.0.1:{peer.port}", target, "1000"))
        peer.wait()
        if result.returncode == 0:
            raise AssertionError("hostile replies must produce a nonzero exit")
        if kind == "rust" and "received=1" not in result.stdout:
            raise AssertionError("rust did not recover to the final reply")
        if kind == "python" and "1 sent, 1 received, 0% loss" not in result.stdout:
            raise AssertionError("python did not recover to the final reply")
        action(actions, f"cli:{kind}-hostile-reply-recovery", point, result.stdout, result.returncode)
        assertion(assertions, f"{kind}.hostile-reply-recovery",
                  "final expected-endpoint reply received; invalid replies caused required nonzero exit")
    finally:
        peer.stop()


def expect_nonzero(command, label, actions, assertions):
    point = time.monotonic()
    result = run(command)
    if result.returncode == 0:
        raise AssertionError(f"{label} unexpectedly succeeded")
    action(actions, label, point, result.stdout, result.returncode)
    assertion(assertions, label, "nonzero exit")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--report", metavar="PATH")
    parser.add_argument("--source-id")
    args = parser.parse_args()
    if args.report and not args.source_id:
        parser.error("--source-id is required with --report")
    if args.build:
        checked(["cargo", "build", "-p", "r8d", "-p", "r8ping"], RUST)
    if not R8D.is_file() or not R8PING.is_file():
        raise AssertionError("Rust binaries are missing")
    started, actions, assertions = time.monotonic(), [], []
    rust_port, python_port = free_port(), free_port()
    rust_loc, python_loc = "8:1::10", "8:1::20"
    rustd = Child("r8d", [str(R8D), "--address", rust_loc, "--bind", f"127.0.0.1:{rust_port}"])
    reference = Child("r8ref", [sys.executable, "-u", str(REFERENCE), "listen", "--address", python_loc, "--bind", "127.0.0.1", "--port", str(python_port)])
    try:
        rustd.wait_for("ready")
        reference.wait_for("listen")
        point = time.monotonic()
        inject(malformed_packets(), rust_port, python_port)
        rustd.wait_for("[drop]")
        reference.wait_for("[drop]")
        if rustd.process.poll() is not None or reference.process.poll() is not None:
            raise AssertionError("daemon survival")
        action(actions, "udp:malformed-corpus", point, "both daemons categorized malformed input")
        assertion(assertions, "daemon.malformed-recovery", "both daemons live after malformed input")
        command = [sys.executable, "-u", str(REFERENCE), "ping", "--address", python_loc, "--peer", f"{rust_loc}=127.0.0.1:{rust_port}", "--bind", "127.0.0.1", "--count", "1", "--timeout", "1", rust_loc]
        point = time.monotonic(); output = checked(command)
        if "1 sent, 1 received, 0% loss" not in output: raise AssertionError("python echo")
        action(actions, "cli:python-daemon-echo", point, output); assertion(assertions, "python.echo", "reply received")
        command = client_command("rust", f"127.0.0.1:{python_port}", python_loc, "1000")
        point = time.monotonic(); output = checked(command)
        if "received=1" not in output: raise AssertionError("rust echo")
        action(actions, "cli:rust-daemon-echo", point, output); assertion(assertions, "rust.echo", "reply received")
        command = [sys.executable, "-u", str(REFERENCE), "send", "--address", python_loc, "--peer", f"{rust_loc}=127.0.0.1:{rust_port}", rust_loc, "python-to-rust"]
        point = time.monotonic(); output = checked(command); rustd.wait_for("[dgram]")
        action(actions, "cli:python-dgram", point, output); assertion(assertions, "r8d.dgram", "dgram received")
        command = [str(R8PING), "--address", rust_loc, "--peer", f"{python_loc}=127.0.0.1:{python_port}", "--bind", "127.0.0.1:0", "--dgram", "rust-to-python", python_loc]
        point = time.monotonic(); output = checked(command); reference.wait_for("[dgram]")
        action(actions, "cli:rust-dgram", point, output); assertion(assertions, "r8ref.dgram", "dgram received")
    finally:
        rustd.stop(); reference.stop()
    scripted_client_case("python", actions, assertions)
    scripted_client_case("rust", actions, assertions)
    no_reply = free_port()
    expect_nonzero(client_command("python", f"127.0.0.1:{no_reply}", "8:1::10", "50"), "cli:python-timeout", actions, assertions)
    expect_nonzero(client_command("rust", f"127.0.0.1:{no_reply}", "8:1::20", "50"), "cli:rust-timeout", actions, assertions)
    sink_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink_socket.bind(("127.0.0.1", 0))
    sink = sink_socket.getsockname()[1]
    try:
        payload = "x" * 1200
        for budget in (1232, 1252):
            expect_nonzero(client_command("rust", f"127.0.0.1:{sink}", "8:1::20", budget=budget, payload=payload), f"cli:budget-reject-{budget}", actions, assertions)
        point = time.monotonic()
        checked(client_command("rust", f"127.0.0.1:{sink}", "8:1::20", budget=1280, payload=payload))
        action(actions, "cli:budget-accept-1280", point, "oversize-for-lower-budgets packet accepted")
        assertion(assertions, "budget.1280", "send accepted")
    finally:
        sink_socket.close()
    expect_nonzero(client_command("python", "8.8.8.8:9", "8:1::10"), "cli:python-public-underlay-refusal", actions, assertions)
    expect_nonzero([str(R8PING), "--address", rust_loc, "--peer", f"{python_loc}=8.8.8.8:9", python_loc], "cli:rust-public-underlay-refusal", actions, assertions)
    if args.report:
        report(args.report, args.source_id, started, actions, assertions)
    print("interop passed: bidirectional ECHO/DGRAM and malformed recovery")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"interop failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
