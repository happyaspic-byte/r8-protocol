"""Deterministic bounded decoder smoke fuzz."""
import pathlib, random, sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'reference'))
import r8session as s
def _auth_wait(r):
 client=s.Identity.from_seed(r.randbytes(32))
 server=s.Identity.from_seed(r.randbytes(32))
 source=s.ipaddress.IPv6Address(r.randbytes(16))
 destination=s.ipaddress.IPv6Address(r.randbytes(16))
 machine=s.ClientMachine(client,s.PeerPin(2,server.eid,server.public),r.randrange(1<<32),r.randrange(4),
                         source,destination,lambda: 0)
 machine.start(r.randrange(1,1<<64),r.randbytes(32),r.randbytes(32),
               _authority=s._HANDSHAKE_MATERIAL_AUTHORITY)
 verify=s.VerifyCookie(2,1,machine.service_context,client.public,s.hashlib.sha256(machine.ephemeral).digest(),
                       r.randbytes(16),r.randbytes(32))
 packet=s.build_packet(s.Header(s.NH_SES,destination,source,profile=machine.profile,scid=machine.scid),
                       verify.build(machine.profile),machine.binding_budget)
 return machine,packet,verify
def run(seed=0x52385345):
 r=random.Random(seed)
 for size in range(1282):
  try: s.decode(r.randbytes(size))
  except s.SessionError as e: assert e.category in s.ERRORS
  except Exception as e: raise AssertionError(f'uncategorized {e!r}') from e
 for _ in range(128):
  machine,packet,verify=_auth_wait(r)
  auth=machine.receive_verify(packet)
  snapshot=dict(machine.__dict__)
  assert machine.receive_verify(packet)==auth
  assert machine.__dict__==snapshot
  competing=s.VerifyCookie(2,1,machine.service_context,machine.identity.public,
                           s.hashlib.sha256(machine.ephemeral).digest(),verify.boot_instance,r.randbytes(32))
  competing_packet=s.build_packet(s.Header(s.NH_SES,machine.destination,machine.source,
                                           profile=machine.profile,scid=machine.scid),
                                  competing.build(machine.profile),machine.binding_budget)
  malformed=bytearray(packet); malformed[-1]^=1
  for candidate in (bytes(malformed),competing_packet):
   try: machine.receive_verify(candidate)
   except s.SessionError as e: assert e.category=="AUTH_FAILED"
   else: raise AssertionError("accepted a competing VerifyCookie")
   assert machine.__dict__==snapshot
  machine.deadline=0
  try: machine.receive_verify(packet)
  except s.SessionError as e: assert e.category=="AUTH_FAILED"
  else: raise AssertionError("accepted VerifyCookie at its deadline")
  assert machine.state==machine.RELEASED
  assert not hasattr(machine,"ephemeral_secret") and machine.auth_payload is None
  secrets=s._client_secrets(machine)
  assert all(value is None for value in (
      secrets.ephemeral_secret,secrets.transcript_hash,secrets.prk,secrets.c2s,secrets.s2c))
if __name__=='__main__': run()
