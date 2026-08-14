#!/usr/bin/env python3
"""Bounded closed-loopback r8move integration and mobility API checks."""
import ipaddress, json, os, socket, struct, subprocess, sys, time, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"reference"))
from r8session import Identity, PeerPin, UdpBinding, eid
from r8mobility import MobilityManager, MobilityError
PY=(sys.executable,str(ROOT/'reference'/'r8move.py'))
RS=(str(ROOT/'rust'/'target'/'debug'/'r8move'),)
SEED_A='01'*32; SEED_B='02'*32

def public(seed):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
class Interop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a,cls.b=public(SEED_A),public(SEED_B); cls.records=[]
    def command(self, side, command, peer, seed, pin, mode, message, port):
        local,remote,new=("2001:db8::1","2001:db8::2","2001:db8::3") if command=="connect" else ("2001:db8::2","2001:db8::1","2001:db8::3")
        bind="127.0.0.1:0" if command=="connect" else f"127.0.0.1:{port}"
        base=side+(command,'--local-seed-hex',seed,'--peer-public-key-hex',pin,'--service-context','7','--server-context-id','9','--address',local,'--peer-address',remote,'--new-address',new,'--bind',bind,'--timeout','3','--deterministic-scid','17','--deterministic-candidate-hex','03'*16,'--deterministic-secret-hex','04'*32)
        return base+(('--peer',peer,'--mode',mode,'--message-hex',message) if command=='connect' else ('--max-sessions','1'))
    def scenario(self, mover, server, mode, payload):
        allocator=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); allocator.bind(("127.0.0.1",0)); port=allocator.getsockname()[1]; allocator.close()
        serve=self.command(server,'serve','',SEED_B,self.a,mode,'',port)
        p=subprocess.Popen(serve,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            time.sleep(.1)
            connect=self.command(mover,'connect',f'127.0.0.1:{port}',SEED_A,self.b,mode,payload,port)
            c=subprocess.run(connect,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=8)
            server_out,server_err=p.communicate(timeout=8)
            self.records.append({'command':'<redacted r8move '+mode+'>','exit':c.returncode,'assertions':['protected initial echo','signed move','protected post-move echo']})
            self.assertEqual(c.returncode,0,f"client={c.stderr!r} server={server_err!r}"); self.assertIn('[r8move] complete',c.stdout); self.assertIn('[r8move] complete',server_out)
        finally:
            if p.poll() is None:
                p.terminate()
                try: p.wait(timeout=1)
                except subprocess.TimeoutExpired: p.kill(); p.wait()
    def stream_scenario(self, mover, server, mode):
        allocator=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); allocator.bind(("127.0.0.1",0)); port=allocator.getsockname()[1]; allocator.close()
        start=time.monotonic_ns()+500_000_000; cut=start+300_000_000; end=cut+400_000_000
        stream=('--stream-rate','100','--stream-start-ns',str(start),'--stream-cutover-ns',str(cut),'--stream-end-ns',str(end))
        serve=self.command(server,'serve','',SEED_B,self.a,mode,'',port)+stream
        reader,writer=os.pipe(); p=subprocess.Popen(serve,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            connect=self.command(mover,'connect',f'127.0.0.1:{port}',SEED_A,self.b,mode,'00',port)+stream+('--events-fd',str(writer))
            c=subprocess.run(connect,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=8,pass_fds=(writer,))
            os.close(writer); writer=None
            server_out,server_error=p.communicate(timeout=8)
            records=b""
            while True:
                chunk=os.read(reader,4096)
                if not chunk: break
                records+=chunk
            self.assertEqual(c.returncode,0,f"client stderr: {c.stderr}; server stderr: {server_error}"); self.assertEqual(p.returncode,0,f"client stderr: {c.stderr}; server stderr: {server_error}"); self.assertIn('[r8move] complete',c.stdout); self.assertIn('[r8move] complete',server_out)
            self.assertEqual(len(records)%16,0)
            echoes=[struct.unpack("!QQ",records[offset:offset+16]) for offset in range(0,len(records),16)]
            self.assertTrue(echoes)
            sequences=[sequence for sequence,_ in echoes]
            self.assertEqual(sequences,sorted(set(sequences)))
            self.assertTrue(any(received < cut for _,received in echoes))
            after=[sequence for sequence,received in echoes if received >= cut]
            self.assertTrue(any(after[index:index+10]==list(range(after[index],after[index]+10)) for index in range(max(0,len(after)-9))))
            tolerance=100_000_000
            self.assertTrue(all(start-tolerance <= received <= end+tolerance for _,received in echoes))
            self.records.append({'command':'<redacted r8move stream '+mode+'>','exit':c.returncode,'assertions':['16-byte echo records','pre-cut echo','post-cut consecutive echo run','completion markers']})
        finally:
            if writer is not None: os.close(writer)
            os.close(reader)
            if p.poll() is None:
                p.terminate()
                try: p.wait(timeout=1)
                except subprocess.TimeoutExpired: p.kill(); p.wait()
    def test_python_stream_loopback(self):
        for mode in ("abrupt","mbb"):
            with self.subTest(mode=mode): self.stream_scenario(PY,PY,mode)
    @unittest.skipUnless(Path(RS[0]).exists(),"r8move binary not built")
    def test_python_stream_to_rust_server(self):
        for mode in ("abrupt","mbb"):
            with self.subTest(mode=mode): self.stream_scenario(PY,RS,mode)
    @unittest.skipUnless(Path(RS[0]).exists(),"r8move binary not built")
    def test_rust_stream_to_python_server(self):
        for mode in ("abrupt","mbb"):
            with self.subTest(mode=mode): self.stream_scenario(RS,PY,mode)
    def test_python_loopback(self):
        for mode in ("abrupt","mbb"):
            self.scenario(PY,PY,mode,"00")
    def test_hostile_mobility_api_continues(self):
        clock=[0]
        now=lambda:clock[0]
        client,server=Identity.from_seed(bytes.fromhex(SEED_A)),Identity.from_seed(bytes.fromhex(SEED_B))
        client_pin=PeerPin(2,eid(server.public),server.public)
        server_pin=PeerPin(1,eid(client.public),client.public)
        old_binding=UdpBinding.from_endpoint("127.0.0.1",50001,1,b"a"*16)
        candidate_binding=UdpBinding.from_endpoint("127.0.0.1",50002,1,b"b"*16)
        wrong=UdpBinding.from_endpoint("127.0.0.1",50003,1,b"c"*16)
        sender=MobilityManager(client,client_pin,1,0,17,1,"2001:db8::1","2001:db8::2",old_binding,b"c"*32,now)
        receiver=MobilityManager(server,server_pin,2,0,17,1,"2001:db8::2","2001:db8::1",old_binding,b"d"*32,now)
        cid=b"e"*16
        update=sender.propose_local("2001:db8::3",1,cid)
        with self.assertRaises(MobilityError): receiver.preview(update[:-1]+bytes([update[-1]^1]),old_binding,1)
        receiver.commit(receiver.preview(update,old_binding,2))
        # Current old binding remains application-eligible while the proposal is unproven;
        # a candidate/unknown binding is not.
        self.assertEqual(receiver.peer_loc,ipaddress.IPv6Address("2001:db8::1"))
        self.assertTrue(receiver.binding_allowed_inbound(old_binding))
        self.assertFalse(receiver.binding_allowed_inbound(candidate_binding))
        probe=sender.make_probe(cid,candidate_binding,b"f"*16)
        challenge=receiver.commit(receiver.preview(probe,candidate_binding,3))
        response=sender.commit(sender.preview(challenge,candidate_binding,4))
        with self.assertRaises(MobilityError): receiver.preview(response,wrong,5)
        receiver.commit(receiver.preview(response,candidate_binding,6))
        self.assertEqual(receiver.peer_loc,ipaddress.IPv6Address("2001:db8::3"))
        self.assertEqual(receiver.binding,candidate_binding)
        # Exact duplicate is cached after promotion on the current carrier.
        receiver.commit(receiver.preview(response,candidate_binding,7))
        self.assertIsNotNone(receiver.grace)
        # The old carrier remains accepted exactly through, but not at, expiry.
        clock[0]=9999; self.assertTrue(receiver.binding_allowed_inbound(old_binding))
        self.assertTrue(receiver.binding_allowed_inbound(candidate_binding))
        clock[0]=10000; self.assertFalse(receiver.binding_allowed_inbound(old_binding))
        self.assertIsNone(receiver.grace)
        # Same-epoch candidates settle deterministically by lexical candidate ID.
        tie_sender=MobilityManager(client,client_pin,1,0,19,1,"2001:db8::1","2001:db8::2",old_binding,b"g"*32,now)
        tie_receiver=MobilityManager(server,server_pin,2,0,19,1,"2001:db8::2","2001:db8::1",old_binding,b"h"*32,now)
        pairs=((b"z"*16,"2001:db8::4"),(b"y"*16,"2001:db8::5"))
        for candidate,loc in pairs: tie_receiver.commit(tie_receiver.preview(tie_sender.propose_local(loc,1,candidate),old_binding,20))
        for candidate,_ in pairs:
            challenge=tie_receiver.commit(tie_receiver.preview(tie_sender.make_probe(candidate,old_binding,b"i"*16),old_binding,21))
            tie_receiver.commit(tie_receiver.preview(tie_sender.commit(tie_sender.preview(challenge,old_binding,22)),old_binding,23))
        self.assertEqual(tie_receiver.peer_loc,ipaddress.IPv6Address("2001:db8::5"))
        # A rejection does not poison later valid traffic.
        self.assertEqual(sender.make_probe(cid,candidate_binding,b"f"*16),probe)
    @unittest.skipUnless(Path(RS[0]).exists(),"r8move binary not built")
    def test_python_mover_rust_server(self):
        for mode in ('abrupt','mbb'):
            for payload in ('00','aa'*(1252-76)): self.scenario(PY,RS,mode,payload)
    @unittest.skipUnless(Path(RS[0]).exists(),"r8move binary not built")
    def test_rust_mover_python_server(self):
        for mode in ('abrupt','mbb'):
            for payload in ('00','aa'*(1252-76)): self.scenario(RS,PY,mode,payload)
    @classmethod
    def tearDownClass(cls):
        print(json.dumps({'source':'mobility_interop.py','records':cls.records},sort_keys=True))
if __name__=='__main__': unittest.main()
