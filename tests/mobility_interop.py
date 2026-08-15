#!/usr/bin/env python3
"""Bounded closed-loopback Python/Rust r8move mobility matrix."""
import copy
import ipaddress
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time
from unittest import mock
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RS = (str(ROOT / "rust" / "target" / "debug" / "r8move"),)
PY = (sys.executable, str(ROOT / "reference" / "r8move.py"))
BUILD = "--build" in sys.argv
if BUILD:
    sys.argv.remove("--build")
    subprocess.run(
        ("cargo", "build", "--locked", "-p", "r8-mobility"),
        cwd=ROOT / "rust",
        check=True,
    )
sys.path.insert(0, str(ROOT / "reference"))
from r8session import Identity, PeerPin, UdpBinding, eid
from r8mobility import MobilityManager, MobilityError
import r8mobility
import r8move

SEED_A = "01" * 32
SEED_B = "02" * 32


def public(seed):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ).hex()


def pipe():
    reader, writer = os.pipe()
    return reader, writer


def read_pipe(fd):
    result = b""
    while True:
        chunk = os.read(fd, 4096)
        if not chunk:
            return result
        result += chunk
def read_exact(fd, length, timeout):
    result = b""
    deadline = time.monotonic() + timeout
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("pipe")
        readable, _, _ = select.select((fd,), (), (), remaining)
        if not readable:
            raise TimeoutError("pipe")
        chunk = os.read(fd, length - len(result))
        if not chunk:
            raise OSError("pipe")
        result += chunk
    return result


class Interop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a, cls.b = public(SEED_A), public(SEED_B)
        cls.records = []

    def command(self, side, command, peer, seed, pin, moving_role, mode, message, port, fds=()):
        local, remote, new = (
            ("2001:db8::1", "2001:db8::2", "2001:db8::3")
            if command == "connect"
            else ("2001:db8::2", "2001:db8::1", "2001:db8::3")
        )
        bind = "127.0.0.1:0" if command == "connect" else f"127.0.0.1:{port}"
        base = side + (
            command, "--local-seed-hex", seed, "--peer-public-key-hex", pin,
            "--service-context", "7", "--server-context-id", "9", "--address", local,
            "--peer-address", remote, "--new-address", new, "--bind", bind,
            "--candidate-bind", "127.0.0.1:0", "--timeout", "3",
            "--moving-role", str(moving_role),
            "--mode", mode,
        ) + tuple(fds)
        return base + (
            ("--peer", peer, "--message-hex", message)
            if command == "connect" else ("--max-sessions", "1", "--expected-post-move", "1")
        )

    def _port(self):
        allocator = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        allocator.bind(("127.0.0.1", 0))
        port = allocator.getsockname()[1]
        allocator.close()
        return port

    def _assert_clean(self, output):
        self.assertNotRegex(output, r"(?i)(?:seed|public-key|candidate|127\.0\.0\.1|2001:db8)")

    def scenario(self, mover, server, moving_role, mode, payload, expected=0):
        port = self._port()
        serve = self.command(server, "serve", "", SEED_B, self.a, moving_role, mode, "", port)
        process = subprocess.Popen(serve, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(.1)
            connect = self.command(mover, "connect", f"127.0.0.1:{port}", SEED_A, self.b, moving_role, mode, payload, port)
            client = subprocess.run(connect, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
            if expected:
                if process.poll() is None:
                    process.terminate()
                server_out, server_err = process.communicate(timeout=2)
                diagnostic = (
                    f"client rc={client.returncode} stdout={client.stdout!r} stderr={client.stderr!r}; "
                    f"server rc={process.returncode} stdout={server_out!r} stderr={server_err!r}"
                )
                self.assertNotEqual(client.returncode, 0, diagnostic)
                self.assertIn("CONFIG", client.stderr, diagnostic)
                return
            server_out, server_err = process.communicate(timeout=8)
            diagnostic = (
                f"client rc={client.returncode} stdout={client.stdout!r} stderr={client.stderr!r}; "
                f"server rc={process.returncode} stdout={server_out!r} stderr={server_err!r}"
            )
            self.assertEqual(client.returncode, 0, diagnostic)
            self.assertEqual(process.returncode, 0, diagnostic)
            self.assertIn("[r8move] complete", client.stdout, diagnostic)
            self.assertIn("[r8move] complete", server_out, diagnostic)
            self._assert_clean(client.stdout + client.stderr + server_out + server_err)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def _assert_cpu_window(self, records, start, end):
        for record in records:
            self.assertEqual(len(record), 48)
            pre_ns, user_pre, system_pre, post_ns, user_post, system_post = struct.unpack("!QQQQQQ", record)
            self.assertLessEqual(pre_ns, start)
            self.assertGreaterEqual(post_ns, end)
            self.assertGreaterEqual(post_ns, pre_ns)
            self.assertGreaterEqual(user_post, user_pre)
            self.assertGreaterEqual(system_post, system_pre)
    def test_python_udp_sockets_require_df_and_propagate_setup_failure(self):
        sock = mock.MagicMock()
        with mock.patch.object(r8move, "_socket", return_value=sock):
            self.assertIs(r8move._udp_socket(), sock)
        sock.setsockopt.assert_called_once_with(
            socket.IPPROTO_IP, getattr(socket, "IP_MTU_DISCOVER", 10),
            getattr(socket, "IP_PMTUDISC_DO", 2),
        )
        failed = mock.MagicMock()
        failed.setsockopt.side_effect = OSError("pmtu")
        with mock.patch.object(r8move, "_socket", return_value=failed):
            with self.assertRaises(OSError):
                r8move._udp_socket()
        failed.close.assert_called_once_with()
        source = Path(r8move.__file__).read_text()
        self.assertEqual(source.count("_udp_socket()"), 7)
    def stream_scenario(self, mover, server, moving_role, mode):
        port = self._port()
        start = time.monotonic_ns() + 700_000_000
        cut = start + 300_000_000
        end = cut + 900_000_000
        stream = ("--stream-rate", "20", "--stream-start-ns", str(start),
                  "--stream-cutover-ns", str(cut), "--stream-end-ns", str(end))
        sr, sw = pipe()
        cr, cw = pipe()
        er, ew = pipe()
        rr, rw = pipe()
        ar, aw = pipe()
        tr, tw = pipe()
        spr, spw = pipe()
        cpr, cpw = pipe()
        server_fds = ("--ready-fd", str(sw), "--cpu-fd", str(spw))
        client_fds = ("--ready-fd", str(cw), "--events-fd", str(ew),
                      "--scheduled-fd", str(rw), "--attempt-fd", str(aw),
                      "--sent-fd", str(tw), "--cpu-fd", str(cpw))
        serve = self.command(server, "serve", "", SEED_B, self.a, moving_role, mode, "", port, server_fds) + stream
        process = subprocess.Popen(
            serve, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            pass_fds=(sw, spw),
        )
        try:
            time.sleep(.1)
            connect = self.command(mover, "connect", f"127.0.0.1:{port}", SEED_A, self.b,
                                   moving_role, mode, "00", port, client_fds) + stream
            client = subprocess.run(
                connect, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                timeout=10, pass_fds=(cw, ew, rw, aw, tw, cpw),
            )
            for fd in (sw, cw, ew, rw, aw, tw, spw, cpw):
                os.close(fd)
            sw = cw = ew = rw = aw = tw = spw = cpw = None
            server_out, server_err = process.communicate(timeout=10)
            ready_server, ready_client = read_pipe(sr), read_pipe(cr)
            events, scheduled = read_pipe(er), read_pipe(rr)
            attempts, sent = read_pipe(ar), read_pipe(tr)
            server_cpu, client_cpu = read_pipe(spr), read_pipe(cpr)
            diagnostic = (
                f"client rc={client.returncode} stdout={client.stdout!r} stderr={client.stderr!r}; "
                f"server rc={process.returncode} stdout={server_out!r} stderr={server_err!r}"
            )
            self.assertEqual(client.returncode, 0, diagnostic)
            self.assertEqual(process.returncode, 0, diagnostic)
            self.assertIn("[r8move] complete", client.stdout, diagnostic)
            self.assertIn("[r8move] complete", server_out, diagnostic)
            self._assert_clean(client.stdout + client.stderr + server_out + server_err)
            self.assertEqual(len(ready_server), 8)
            self.assertEqual(len(ready_client), 8)
            self._assert_cpu_window((server_cpu, client_cpu), start, end)
            self.assertEqual(len(events) % 16, 0)
            self.assertEqual(len(scheduled) % 16, 0)
            self.assertEqual(len(attempts) % 16, 0)
            self.assertEqual(len(sent) % 16, 0)
            records = lambda data: [struct.unpack("!QQ", data[offset:offset + 16]) for offset in range(0, len(data), 16)]
            scheduled_records = records(scheduled)
            attempt_records = records(attempts)
            sent_records = records(sent)
            event_records = records(events)
            scheduled_ids = [sequence for sequence, _ in scheduled_records]
            attempt_ids = [sequence for sequence, _ in attempt_records]
            sent_ids = [sequence for sequence, _ in sent_records]
            event_ids = [sequence for sequence, _ in event_records]
            self.assertEqual(scheduled_ids, sorted(set(scheduled_ids)))
            self.assertTrue(event_ids)
            self.assertTrue(set(event_ids) <= set(sent_ids) <= set(attempt_ids) <= set(scheduled_ids))
            scheduled_by_id = dict(scheduled_records)
            attempts_by_id = dict(attempt_records)
            sent_by_id = dict(sent_records)
            events_by_id = dict(event_records)
            for sequence in event_ids:
                self.assertLessEqual(scheduled_by_id[sequence], attempts_by_id[sequence])
                self.assertLessEqual(attempts_by_id[sequence], sent_by_id[sequence])
                self.assertLessEqual(sent_by_id[sequence], events_by_id[sequence])
            self.assertTrue(any(timestamp < cut for _, timestamp in event_records))
            post = [sequence for sequence, timestamp in event_records if timestamp >= cut]
            self.assertTrue(any(post[index:index + 10] == list(range(post[index], post[index] + 10))
                                for index in range(len(post) - 9)))
            tolerance = 150_000_000
            self.assertTrue(all(
                start - tolerance <= timestamp <= end + tolerance
                for _, timestamp in scheduled_records + attempt_records + sent_records + event_records
            ))
            self.records.append({
                "command": f"<redacted r8move stream role={moving_role} mode={mode}>",
                "exit": client.returncode,
                "assertions": ["completion", "record widths", "ordered stream accounting", "continuity", "cpu"],
            })
        finally:
            for fd in (sw, cw, ew, rw, aw, tw, spw, cpw, sr, cr, er, rr, ar, tr, spr, cpr):
                if fd is not None:
                    os.close(fd)
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def fd_stream_scenario(self, mover, server, moving_role, mode):
        port = self._port()
        sr, sw = pipe(); cr, cw = pipe()
        ssr, ssw = pipe(); sgr, sgw = pipe(); csr, csw = pipe(); cgr, cgw = pipe()
        cutr, cutw = pipe()
        er, ew = pipe(); rr, rw = pipe(); ar, aw = pipe(); tr, tw = pipe()
        spr, spw = pipe(); cpr, cpw = pipe()
        fds = {sr, sw, cr, cw, ssr, ssw, sgr, sgw, csr, csw, cgr, cgw, cutr, cutw,
               er, ew, rr, rw, ar, aw, tr, tw, spr, spw, cpr, cpw}
        process = client_process = None
        try:
            server_fds = ("--stream-rate", "20", "--ready-fd", str(sw), "--schedule-fd", str(ssr),
                          "--gate-fd", str(sgr), "--cpu-fd", str(spw))
            client_fds = ("--stream-rate", "20", "--ready-fd", str(cw), "--schedule-fd", str(csr),
                          "--gate-fd", str(cgr), "--events-fd", str(ew), "--scheduled-fd", str(rw),
                          "--attempt-fd", str(aw), "--sent-fd", str(tw), "--cpu-fd", str(cpw))
            if moving_role == 2: server_fds += ("--cutover-gate-fd", str(cutr))
            else: client_fds += ("--cutover-gate-fd", str(cutr))
            process = subprocess.Popen(
                self.command(server, "serve", "", SEED_B, self.a, moving_role, mode, "", port, server_fds),
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                pass_fds=(sw, ssr, sgr, spw) + ((cutr,) if moving_role == 2 else ()),
            )
            for fd in (sw, ssr, sgr, spw):
                os.close(fd); fds.remove(fd)
            time.sleep(.1)
            client_process = subprocess.Popen(
                self.command(mover, "connect", f"127.0.0.1:{port}", SEED_A, self.b,
                             moving_role, mode, "00", port, client_fds),
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                pass_fds=(cw, csr, cgr, ew, rw, aw, tw, cpw) + ((cutr,) if moving_role == 1 else ()),
            )
            for fd in (cw, csr, cgr, ew, rw, aw, tw, cpw, cutr):
                if fd in fds:
                    os.close(fd); fds.remove(fd)
            try:
                ready_server = read_exact(sr, 8, 5)
                ready_client = read_exact(cr, 8, 5)
                self.assertGreater(struct.unpack("!Q", ready_server)[0], 0)
                self.assertGreater(struct.unpack("!Q", ready_client)[0], 0)
            except (AssertionError, OSError, TimeoutError) as error:
                outputs = []
                for name, child in (("client", client_process), ("server", process)):
                    if child.poll() is not None:
                        stdout, stderr = child.communicate(timeout=1)
                        outputs.append(f"{name} rc={child.returncode} stdout={stdout!r} stderr={stderr!r}")
                self.fail(f"readiness: {error}; {'; '.join(outputs)}")
            start = time.monotonic_ns() + 300_000_000; cut = start + 300_000_000; end = cut + 900_000_000
            schedule = struct.pack("!QQQ", start, cut, end)
            os.write(ssw, schedule); os.write(csw, schedule)
            os.write(sgw, b"x"); os.write(cgw, b"x")
            for fd in (ssw, csw, sgw, cgw):
                os.close(fd); fds.remove(fd)
            time.sleep(max(0, (cut - time.monotonic_ns()) / 1e9))
            self.assertIsNone(process.poll())
            self.assertIsNone(client_process.poll())
            os.write(cutw, b"x"); os.close(cutw); fds.remove(cutw)
            client_out, client_err = client_process.communicate(timeout=10)
            server_out, server_err = process.communicate(timeout=10)
            ready_server, ready_client = read_pipe(sr), read_pipe(cr)
            events, scheduled, attempts, sent = read_pipe(er), read_pipe(rr), read_pipe(ar), read_pipe(tr)
            server_cpu, client_cpu = read_pipe(spr), read_pipe(cpr)
            diagnostic = (
                f"client rc={client_process.returncode} stdout={client_out!r} stderr={client_err!r}; "
                f"server rc={process.returncode} stdout={server_out!r} stderr={server_err!r}"
            )
            self.assertEqual(client_process.returncode, 0, diagnostic)
            self.assertEqual(process.returncode, 0, diagnostic)
            self.assertIn("[r8move] complete", client_out, diagnostic)
            self.assertIn("[r8move] complete", server_out, diagnostic)
            self._assert_clean(client_out + client_err + server_out + server_err)
            self.assertEqual(ready_server, b"")
            self.assertEqual(ready_client, b"")
            self._assert_cpu_window((server_cpu, client_cpu), start, end)
            self.assertEqual(len(events) % 16, 0)
            self.assertEqual(len(scheduled) % 16, 0)
            self.assertEqual(len(attempts) % 16, 0)
            self.assertEqual(len(sent) % 16, 0)
            records = lambda data: [struct.unpack("!QQ", data[index:index + 16]) for index in range(0, len(data), 16)]
            scheduled_records, attempt_records = records(scheduled), records(attempts)
            sent_records, event_records = records(sent), records(events)
            self.assertTrue(event_records)
            scheduled_by_id, attempts_by_id = dict(scheduled_records), dict(attempt_records)
            sent_by_id, events_by_id = dict(sent_records), dict(event_records)
            self.assertTrue(set(events_by_id) <= set(sent_by_id) <= set(attempts_by_id) <= set(scheduled_by_id))
            for sequence in events_by_id:
                self.assertLessEqual(scheduled_by_id[sequence], attempts_by_id[sequence])
                self.assertLessEqual(attempts_by_id[sequence], sent_by_id[sequence])
                self.assertLessEqual(sent_by_id[sequence], events_by_id[sequence])
            post = [sequence for sequence, stamp in event_records if stamp >= cut]
            self.assertTrue(any(post[index:index + 10] == list(range(post[index], post[index] + 10))
                                for index in range(len(post) - 9)))
            self.assertTrue(all(start - 150_000_000 <= stamp <= end + 150_000_000
                                for _, stamp in scheduled_records + attempt_records + sent_records + event_records))
            self._assert_cpu_window((server_cpu, client_cpu), start, end)
        finally:
            for fd in tuple(fds):
                try: os.close(fd)
                except OSError: pass
            for child in (client_process, process):
                if child is not None and child.poll() is None:
                    child.terminate()
                    try: child.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        child.kill(); child.wait()
    @unittest.skipUnless(Path(RS[0]).exists(), "r8move binary not built; use --build")
    def test_native_role_language_matrix(self):
        for mover, server in ((PY, PY), (PY, RS), (RS, PY), (RS, RS)):
            for moving_role in (1, 2):
                for mode in ("abrupt", "mbb"):
                    with self.subTest(mover=mover[0], server=server[0], role=moving_role, mode=mode):
                        self.stream_scenario(mover, server, moving_role, mode)

    @unittest.skipUnless(Path(RS[0]).exists(), "r8move binary not built; use --build")
    def test_cross_language_payload_boundaries(self):
        for mover, server in ((PY, PY), (PY, RS), (RS, PY), (RS, RS)):
            for moving_role in (1, 2):
                for mode in ("abrupt", "mbb"):
                    with self.subTest(role=moving_role, mode=mode, length=1):
                        self.scenario(mover, server, moving_role, mode, "00")
                    with self.subTest(role=moving_role, mode=mode, length=1176):
                        self.scenario(mover, server, moving_role, mode, "aa" * 1176)
                    with self.subTest(role=moving_role, mode=mode, length=1177):
                        self.scenario(mover, server, moving_role, mode, "aa" * 1177, expected=1)
    def test_python_rejects_strict_argument_errors(self):
        for arguments in (
            ("connect", "--unknown"),
            ("connect", "--stream-rate", "20", "--stream-rate", "20"),
            ("serve", "--peer", "127.0.0.1:1"),
        ):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    PY + arguments, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=2,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("CONFIG", result.stderr)
                self._assert_clean(result.stdout + result.stderr)
    @unittest.skipUnless(Path(RS[0]).exists(), "r8move binary not built; use --build")
    def test_fd_schedule_gate_role_language_matrix(self):
        for mover, server in ((PY, PY), (PY, RS), (RS, PY), (RS, RS)):
            for moving_role in (1, 2):
                for mode in ("abrupt", "mbb"):
                    with self.subTest(mover=mover[0], server=server[0], role=moving_role, mode=mode):
                        self.fd_stream_scenario(mover, server, moving_role, mode)

    def _hostile_direction(self, moving_role):
        clock = [0]
        now = lambda: clock[0]
        role1, role2 = Identity.from_seed(bytes.fromhex(SEED_A)), Identity.from_seed(bytes.fromhex(SEED_B))
        old = UdpBinding.from_endpoint("127.0.0.1", 50001, 1, b"a" * 16)
        candidate = UdpBinding.from_endpoint("127.0.0.1", 50002, 1, b"b" * 16)
        wrong = UdpBinding.from_endpoint("127.0.0.1", 50003, 1, b"c" * 16)
        if moving_role == 1:
            sender = MobilityManager(role1, PeerPin(2, eid(role2.public), role2.public), 1, 0, 17, 1, "2001:db8::1", "2001:db8::2", old, b"c" * 32, now)
            receiver = MobilityManager(role2, PeerPin(1, eid(role1.public), role1.public), 2, 0, 17, 1, "2001:db8::2", "2001:db8::1", old, b"d" * 32, now)
        else:
            sender = MobilityManager(role2, PeerPin(1, eid(role1.public), role1.public), 2, 0, 17, 1, "2001:db8::2", "2001:db8::1", old, b"c" * 32, now)
            receiver = MobilityManager(role1, PeerPin(2, eid(role2.public), role2.public), 1, 0, 17, 1, "2001:db8::1", "2001:db8::2", old, b"d" * 32, now)
        r8mobility._MOBILITY_CORES[receiver].peer_epoch = 1
        candidate_id = b"e" * 16
        update = sender.propose_local("2001:db8::3", 2, candidate_id)
        state = lambda: copy.deepcopy((
            receiver.peer_loc, receiver.binding, receiver.local_epoch, receiver.peer_epoch, receiver.generation,
            receiver.proposals, receiver.candidates, receiver.results, receiver.emitted,
        ))
        before = state()
        stale = sender._sign_update(b"g" * 16, ipaddress.IPv6Address("2001:db8::4"), 1, 0).build()
        for hostile, binding, token in (
            (update[:-1] + bytes([update[-1] ^ 1]), old, 1),
            (stale, old, 2),
        ):
            with self.assertRaises(MobilityError):
                receiver.preview(hostile, binding, token)
            self.assertEqual(before, state())
        receiver.commit(receiver.preview(update, old, 4))
        probe = sender.make_probe(candidate_id, candidate, b"f" * 16)
        challenge = receiver.commit(receiver.preview(probe, candidate, 5))
        response = sender.commit(sender.preview(challenge, candidate, 6))
        before_response = state()
        with self.assertRaises(MobilityError):
            receiver.preview(response, wrong, 7)
        self.assertEqual(before_response, state())
        self.assertEqual(receiver.peer_loc, ipaddress.IPv6Address("2001:db8::1" if moving_role == 1 else "2001:db8::2"))
        self.assertEqual(receiver.binding, old)
        receiver.commit(receiver.preview(response, candidate, 8))
        self.assertEqual(receiver.peer_loc, ipaddress.IPv6Address("2001:db8::3"))
        self.assertEqual(receiver.binding, candidate)
        self.assertGreater(receiver.generation, 0)

    def test_hostile_mobility_api_continues_both_roles(self):
        for moving_role in (1, 2):
            with self.subTest(moving_role=moving_role):
                self._hostile_direction(moving_role)

    @classmethod
    def tearDownClass(cls):
        print(json.dumps({"source": "mobility_interop.py", "records": cls.records}, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
