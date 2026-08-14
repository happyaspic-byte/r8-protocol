#!/usr/bin/env python3
"""G003 bounded loopback interoperability harness for the real session CLIs."""
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
REFERENCE = ROOT / "reference" / "r8session.py"
TARGET = RUST / "target" / "debug" / "r8session"


def load_reference():
    reference_directory = str(ROOT / "reference")
    if reference_directory not in sys.path:
        sys.path.insert(0, reference_directory)
    spec = importlib.util.spec_from_file_location("r8session_reference", REFERENCE)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


REF = load_reference()
SEED_CLIENT = bytes(range(1, 33))
SEED_SERVER = bytes(range(33, 65))
CLIENT_KEY = REF.Identity.from_seed(SEED_CLIENT).public.hex()
SERVER_KEY = REF.Identity.from_seed(SEED_SERVER).public.hex()
SERVICE = "7"
CONTEXT = "11"
CLIENT_LOC = "8:1::1"
SERVER_LOC = "8:1::2"


class Child:
    def __init__(self, command):
        self.lines = []
        self.events = queue.Queue()
        self.process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        assert self.process.stdout
        for line in self.process.stdout:
            self.lines.append(line.rstrip())
            self.events.put(line)

    def wait(self, timeout):
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise AssertionError("child deadline") from error
        finally:
            self.thread.join(timeout=1)

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.thread.join(timeout=1)


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def command(program, mode, seed, peer_key, address, peer_address, bind, peer=None,
            message=None, timeout="3", budget="1252", max_sessions=None, service=SERVICE):
    result = ([program] if isinstance(program, str) else list(program)) + [mode, "--local-seed-hex", seed.hex(), "--peer-public-key-hex", peer_key,
              "--service-context", service, "--server-context-id", CONTEXT, "--address", address,
              "--peer-address", peer_address, "--bind", bind, "--binding-budget", budget,
              "--timeout", timeout]
    if mode == "serve":
        result += ["--max-sessions", max_sessions or "1"]
    else:
        result += ["--peer", peer, "--message-hex", message.hex()]
    return result


def run(command, timeout=8):
    try:
        return subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise AssertionError("child deadline") from error


def redact(output):
    # Evidence is intentionally only its bounded byte count, never process output.
    return f"captured_bytes={len(output.encode())}"


def action(actions, selector, started, result):
    actions.append({"type": "custom", "selector": selector, "target": selector,
                    "startedAt": started, "endedAt": time.monotonic(),
                    "exitCode": result.returncode, "stdout": redact(result.stdout)})


def assertion(assertions, selector, evidence):
    now = time.monotonic()
    assertions.append({"selector": selector, "status": "passed", "startedAt": now,
                       "endedAt": now, "evidence": evidence})


def bounded_clean(output):
    if len(output) > 4096:
        raise AssertionError("unbounded child output")
    forbidden = (CLIENT_LOC, SERVER_LOC, SEED_CLIENT.hex(), SEED_SERVER.hex(), CLIENT_KEY, SERVER_KEY)
    if any(value in output for value in forbidden):
        raise AssertionError("sensitive child output")


def exchange(server_program, client_program, message, actions, assertions, label):
    server_port = port()
    server = Child(command(server_program, "serve", SEED_SERVER, CLIENT_KEY, SERVER_LOC, CLIENT_LOC,
                           f"127.0.0.1:{server_port}"))
    try:
        started = time.monotonic()
        client = run(command(client_program, "connect", SEED_CLIENT, SERVER_KEY, CLIENT_LOC, SERVER_LOC,
                             "127.0.0.1:0", f"127.0.0.1:{server_port}", message))
        server_code = server.wait(6)
        server_output = "\n".join(server.lines)
        bounded_clean(client.stdout); bounded_clean(server_output)
        if client.returncode or server_code:
            raise AssertionError("session exchange failed")
        synthetic = subprocess.CompletedProcess([], 0, client.stdout)
        action(actions, label, started, synthetic)
        assertion(assertions, label + ".completion", f"message_length={len(message)}")
    finally:
        server.stop()


def expected_failure(command_line, label, actions, assertions):
    started = time.monotonic()
    result = run(command_line)
    bounded_clean(result.stdout)
    if result.returncode == 0:
        raise AssertionError("expected nonzero")
    action(actions, label, started, result)
    assertion(assertions, label, "nonzero exit")


def malformed_recovery(server_program, client_program, actions, assertions):
    server_port = port()
    server = Child(command(server_program, "serve", SEED_SERVER, CLIENT_KEY, SERVER_LOC, CLIENT_LOC,
                           f"127.0.0.1:{server_port}"))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as hostile:
            for packet in (b"", b"\x80", bytes(range(31)), b"\x80" * 80):
                hostile.sendto(packet, ("127.0.0.1", server_port))
        started = time.monotonic()
        result = run(command(client_program, "connect", SEED_CLIENT, SERVER_KEY, CLIENT_LOC, SERVER_LOC,
                             "127.0.0.1:0", f"127.0.0.1:{server_port}", b"\x01"))
        server_code = server.wait(6)
        bounded_clean(result.stdout); bounded_clean("\n".join(server.lines))
        if result.returncode or server_code:
            raise AssertionError("malformed recovery failed")
        action(actions, "udp:malformed-before-valid-recovery", started, result)
        assertion(assertions, "session.malformed-recovery", "valid session completed after malformed datagrams")
    finally:
        server.stop()


def receive_verify_with_retries(sock, opened, peer):
    deadline = time.monotonic() + 1
    for timeout in (.1, .2, .35):
        sock.sendto(opened, peer)
        attempt_deadline = min(deadline, time.monotonic() + timeout)
        while time.monotonic() < attempt_deadline:
            sock.settimeout(attempt_deadline - time.monotonic())
            try:
                verify, source = sock.recvfrom(1253)
            except socket.timeout:
                break
            if source == peer:
                return verify
    raise AssertionError("verify deadline")


def scripted_adversarial_server(server_program, actions, assertions, label):
    server_port = port()
    server = Child(command(server_program, "serve", SEED_SERVER, CLIENT_KEY, SERVER_LOC, CLIENT_LOC,
                           f"127.0.0.1:{server_port}", timeout="4", max_sessions="1"))
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    alternate_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.bind(("127.0.0.1", 0))
    alternate_socket.bind(("127.0.0.1", 0))
    client_socket.settimeout(.35)
    alternate_socket.settimeout(.2)
    try:
        identity = REF.Identity.from_seed(SEED_CLIENT)
        pin = REF.PeerPin(2, REF.eid(bytes.fromhex(SERVER_KEY)), bytes.fromhex(SERVER_KEY))
        machine = REF.ClientMachine(identity, pin, int(SERVICE), 0, REF.ipaddress.IPv6Address(CLIENT_LOC),
                                    REF.ipaddress.IPv6Address(SERVER_LOC), time.monotonic, 1252)
        peer = ("127.0.0.1", server_port)
        opened = machine.start(1, b"\x01" * 32, b"\x02" * 32)
        started = time.monotonic()
        verify = receive_verify_with_retries(client_socket, opened, peer)
        auth = machine.receive_verify(verify)
        auth_header, auth_payload = REF.parse_packet(auth)
        parsed = REF.OpenAuth.parse(auth_payload)
        bad_cookie = REF.OpenAuth(parsed.sender_role, parsed.receiver_role, parsed.service_context,
                                  parsed.sender_eid, parsed.sender_public_key, parsed.sender_ephemeral,
                                  parsed.sender_nonce, parsed.boot_instance,
                                  bytes([parsed.cookie_value[0] ^ 1]) + parsed.cookie_value[1:],
                                  parsed.signature)
        client_socket.sendto(REF.build_packet(auth_header, bad_cookie.build()), peer)
        try:
            client_socket.recvfrom(1253)
            raise AssertionError("invalid cookie was not silent")
        except socket.timeout:
            pass
        client_socket.sendto(auth, peer)
        ack, source = client_socket.recvfrom(1253)
        if source != peer:
            raise AssertionError("ack source")
        accept = machine.receive_ack(ack)
        data = machine.send_data(b"\x01")
        alternate_socket.sendto(accept, peer)
        alternate_socket.sendto(data, peer)
        try:
            alternate_socket.recvfrom(1253)
            raise AssertionError("alternate binding promoted")
        except socket.timeout:
            pass
        client_socket.sendto(accept, peer)
        tampered = bytearray(data)
        tampered[-1] ^= 1
        client_socket.sendto(tampered, peer)
        client_socket.sendto(data, peer)
        echo, source = client_socket.recvfrom(1253)
        if source != peer or machine.receive_protected(echo) != b"\x01":
            raise AssertionError("valid data was not delivered")
        client_socket.sendto(data, peer)
        try:
            client_socket.recvfrom(1253)
            raise AssertionError("duplicate data echoed")
        except socket.timeout:
            pass
        client_socket.sendto(machine.close(0), peer)
        action(actions, label, started, subprocess.CompletedProcess([], 0, ""))
        assertion(assertions, label + ".invalid-cookie-silent", "silent_count=1")
        assertion(assertions, label + ".binding-replay", "alternate_echo_count=0")
        assertion(assertions, label + ".tamper-recovery", "echo_count=1 duplicate_echo_count=0")
    finally:
        client_socket.close()
        alternate_socket.close()
        server.stop()


def rejection_then_valid(server_program, client_program, actions, assertions, label):
    server_port = port()
    server = Child(command(server_program, "serve", SEED_SERVER, CLIENT_KEY, SERVER_LOC, CLIENT_LOC,
                           f"127.0.0.1:{server_port}", timeout="4"))
    try:
        wrong_pin = run(command(client_program, "connect", SEED_CLIENT, "00" * 32, CLIENT_LOC, SERVER_LOC,
                                "127.0.0.1:0", f"127.0.0.1:{server_port}", b"\x01", timeout="1"))
        wrong_service = run(command(client_program, "connect", SEED_CLIENT, SERVER_KEY, CLIENT_LOC, SERVER_LOC,
                                    "127.0.0.1:0", f"127.0.0.1:{server_port}", b"\x01", timeout="1", service="8"))
        if wrong_pin.returncode == 0 or wrong_service.returncode == 0 or server.process.poll() is not None:
            raise AssertionError("rejection continuity")
        action(actions, label + ".wrong-pin", time.monotonic(), wrong_pin)
        action(actions, label + ".wrong-service", time.monotonic(), wrong_service)
        assertion(assertions, label + ".rejection-continuity", "rejections=2 server_live=1")
        valid = run(command(client_program, "connect", SEED_CLIENT, SERVER_KEY, CLIENT_LOC, SERVER_LOC,
                            "127.0.0.1:0", f"127.0.0.1:{server_port}", b"\x01"))
        code = server.wait(6)
        if valid.returncode or code:
            raise AssertionError("post-rejection valid session")
        action(actions, label + ".valid-after-rejection", time.monotonic(),
               subprocess.CompletedProcess([], 0, valid.stdout))
        assertion(assertions, label + ".valid-after-rejection", "completion_count=1")
    finally:
        server.stop()

def write_report(path, source_id, started, actions, assertions):
    for ordinal, entry in enumerate(actions + assertions, 1):
        entry["timestamp"] = ordinal
    body = {"schemaVersion": 1, "surface": "cli", "tool": "tests/session_interop.py",
            "kind": "G003", "id": "G003-session", "sourceId": source_id,
            "toolchain": {"python": sys.version.split()[0]}, "environment": {"platform": sys.platform},
            "startedAt": started, "endedAt": time.monotonic(), "actions": actions, "assertions": assertions}
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps(body, indent=2) + "\n")
    temporary.replace(destination)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--report")
    parser.add_argument("--source-id")
    args = parser.parse_args()
    if args.report and not args.source_id:
        parser.error("--source-id is required with --report")
    if args.build:
        built = run(["cargo", "build", "--manifest-path", "rust/Cargo.toml", "--locked", "-p", "r8-session"], timeout=120)
        if built.returncode:
            raise AssertionError("r8session build failed")
    if not TARGET.is_file():
        raise AssertionError("expected r8session binary missing")
    started, actions, assertions = time.monotonic(), [], []
    python = sys.executable
    py = [python, "-u", str(REFERENCE)]
    exchange(py, [str(TARGET)], b"\x01", actions, assertions, "cli:python-client-rust-server-byte")
    exchange([str(TARGET)], py, bytes(range(256)) * 4, actions, assertions, "cli:rust-client-python-server-sample")
    malformed_recovery([str(TARGET)], py, actions, assertions)
    malformed_recovery(py, [str(TARGET)], actions, assertions)
    scripted_adversarial_server([str(TARGET)], actions, assertions, "udp:python-client-rust-server-adversarial")
    scripted_adversarial_server(py, actions, assertions, "udp:python-client-python-server-adversarial")
    rejection_then_valid([str(TARGET)], [str(TARGET)], actions, assertions, "cli:rust-server-rejection")
    rejection_then_valid(py, py, actions, assertions, "cli:python-server-rejection")
    dead = port()
    expected_failure(command([str(TARGET)], "connect", SEED_CLIENT, SERVER_KEY, CLIENT_LOC, SERVER_LOC,
                             "127.0.0.1:0", f"127.0.0.1:{dead}", b"\x01", timeout="1"),
                     "cli:timeout", actions, assertions)
    expected_failure(command([str(TARGET)], "connect", SEED_CLIENT, SERVER_KEY, CLIENT_LOC, SERVER_LOC,
                             "127.0.0.1:0", "8.8.8.8:9", b"\x01"),
                     "cli:public-underlay-refusal", actions, assertions)
    expected_failure(command([str(TARGET)], "connect", SEED_CLIENT, SERVER_KEY, CLIENT_LOC, SERVER_LOC,
                             "127.0.0.1:0", f"127.0.0.1:{dead}", b"\x01", budget="47"),
                     "cli:counter-budget-refusal", actions, assertions)
    if args.report:
        write_report(args.report, args.source_id, started, actions, assertions)
    print("session interop passed: bidirectional sessions and malformed recovery")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"session interop failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
