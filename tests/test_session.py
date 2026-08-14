import json
import pathlib
import sys
import unittest
import threading
from unittest import mock
from types import SimpleNamespace
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'reference'))
import r8session as s
V=json.loads((ROOT/'tests'/'vectors'/'session-v0.1.json').read_text())
class SessionVectors(unittest.TestCase):
 def test_positive_payloads_are_exact(self):
  for case in V['positive_cases'][:4]:
   payload=bytes.fromhex(case['payload_hex']); typ,ver,profile,body=s.decode(payload)
   self.assertEqual(s.encode(typ,profile,body),payload)
 def test_identity_and_transcript_vectors(self):
  i=V['identities']; c=s.Identity.from_seed(bytes.fromhex(i['client_ed25519_seed_hex']))
  self.assertEqual(c.public.hex(),i['client_public_key_hex']); self.assertEqual(c.eid.hex(),i['client_eid_hex'])
  x=V['context']; t=V['transcript']
  p=s.placeholder_t0(x['scid'],x['client_role'],x['server_role'],x['service_context'],bytes.fromhex(i['client_eid_hex']),bytes.fromhex(i['client_public_key_hex']),bytes.fromhex(i['server_eid_hex']),bytes.fromhex(i['client_ephemeral_hex']),bytes.fromhex(x['client_nonce_hex']),bytes.fromhex(x['server_boot_instance_hex']))
  self.assertEqual(p.hex(),t['placeholder_t0_hex'])
 def test_crypto_vectors(self):
  i=V['identities']; x=V['context']; t=V['transcript']; k=V['key_schedule']
  shared=s.x25519(bytes.fromhex(i['client_x25519_secret_hex']),bytes.fromhex(i['server_ephemeral_hex']))
  self.assertEqual(shared.hex(),i['shared_secret_hex'])
  self.assertEqual(s.key_prk(shared,bytes.fromhex(t['transcript_hash_hex'])).hex(),k['hkdf_prk_hex'])
  self.assertEqual(s.key_schedule(shared,bytes.fromhex(t['transcript_hash_hex']),1,2).hex(),k['c2s_slot0_key_hex'])
  self.assertEqual(s.key_schedule(shared,bytes.fromhex(t['transcript_hash_hex']),2,1).hex(),k['s2c_slot0_key_hex'])
  for case in V['positive_cases'][4:]:
   p=case['protected']; key=bytes.fromhex(k['c2s_slot0_key_hex'])
   self.assertEqual(s.nonce(p['counter']).hex(),p['nonce_hex'])
   self.assertEqual(s.seal(key,bytes.fromhex(p['header_hex']),bytes.fromhex(p['prefix_hex']),p['counter'],bytes.fromhex(p['plaintext_hex'])).hex(),p['ciphertext_and_tag_hex'])
   self.assertEqual(s.open_sealed(key,bytes.fromhex(p['header_hex']),bytes.fromhex(p['prefix_hex']),p['counter'],bytes.fromhex(p['ciphertext_and_tag_hex'])),bytes.fromhex(p['plaintext_hex']))
 def test_client_machine_ack_and_accept_vectors(self):
  i=V['identities']; x=V['context']; t=V['transcript']
  client=s.Identity.from_seed(bytes.fromhex(i['client_ed25519_seed_hex']))
  server=s.Identity.from_seed(bytes.fromhex(i['server_ed25519_seed_hex']))
  source=s.ipaddress.IPv6Address("11:2233:4455:6677:8899:aabb:ccdd:eeff")
  destination=s.ipaddress.IPv6Address("ffee:ddcc:bbaa:9988:7766:5544:3322:1100")
  pin=s.PeerPin(2,server.eid,server.public)
  now=[0]
  machine=s.ClientMachine(client,pin,x['service_context'],0,source,destination,lambda: now[0])
  opening=machine.start(x['scid'],bytes.fromhex(i['client_x25519_secret_hex']),bytes.fromhex(x['client_nonce_hex']))
  self.assertEqual(opening[48:].hex(),V['positive_cases'][0]['payload_hex'])
  verify=s.VerifyCookie(2,1,x['service_context'],client.public,
                        s.hashlib.sha256(bytes.fromhex(i['client_ephemeral_hex'])).digest(),
                        bytes.fromhex(x['server_boot_instance_hex']),bytes.fromhex(x['cookie_hmac_hex']))
  verify_packet=s.build_packet(s.Header(s.NH_SES,destination,source,scid=x['scid']),verify.build())
  auth=machine.receive_verify(verify_packet)
  self.assertEqual(auth[48:].hex(),V['positive_cases'][2]['payload_hex'])
  actual=bytes.fromhex(t['actual_t0_hex'])
  ack=s.OpenAck(2,1,x['service_context'],server.eid,server.public,bytes.fromhex(i['server_ephemeral_hex']),
                bytes.fromhex(x['server_nonce_hex']),s.sign_open_ack(server,actual))
  ack_packet=s.build_packet(s.Header(s.NH_SES,destination,source,scid=x['scid']),ack.build())
  accept=machine.receive_ack(ack_packet)
  self.assertEqual(accept.hex(),V['positive_cases'][4]['protected']['packet_hex'])
  self.assertEqual(machine.transcript_hash.hex(),t['transcript_hash_hex'])
  self.assertEqual(machine.state,machine.ESTABLISHED)
  self.assertEqual(machine.c2s_session.send_counter,2)
  self.assertEqual(machine.receive_ack(ack_packet),accept)

 def test_client_ack_fatal_header_and_signature(self):
  i=V['identities']; x=V['context']
  client=s.Identity.from_seed(bytes.fromhex(i['client_ed25519_seed_hex']))
  server=s.Identity.from_seed(bytes.fromhex(i['server_ed25519_seed_hex']))
  source=s.ipaddress.IPv6Address("11:2233:4455:6677:8899:aabb:ccdd:eeff")
  destination=s.ipaddress.IPv6Address("ffee:ddcc:bbaa:9988:7766:5544:3322:1100")
  machine=s.ClientMachine(client,s.PeerPin(2,server.eid,server.public),x['service_context'],0,source,destination,lambda: 0)
  machine.start(x['scid'],bytes.fromhex(i['client_x25519_secret_hex']),bytes.fromhex(x['client_nonce_hex']))
  verify=s.VerifyCookie(2,1,x['service_context'],client.public,s.hashlib.sha256(bytes.fromhex(i['client_ephemeral_hex'])).digest(),bytes.fromhex(x['server_boot_instance_hex']),bytes.fromhex(x['cookie_hmac_hex']))
  machine.receive_verify(s.build_packet(s.Header(s.NH_SES,destination,source,scid=x['scid']),verify.build()))
  bad=s.build_packet(s.Header(s.NH_SES,destination,source,scid=x['scid']+1),s.OpenAck(2,1,x['service_context'],server.eid,server.public,bytes.fromhex(i['server_ephemeral_hex']),bytes.fromhex(x['server_nonce_hex']),b"\0"*64).build())
  with self.assertRaises(s.SessionError): machine.receive_ack(bad)
  self.assertEqual(machine.state,machine.RELEASED)
 def test_open_ack_record_rejects_wrong_eid_signature_and_ephemeral(self):
  i=V['identities']; x=V['context']
  server=s.Identity.from_seed(bytes.fromhex(i['server_ed25519_seed_hex']))
  valid=s.OpenAck(2,1,x['service_context'],server.eid,server.public,
                  bytes.fromhex(i['server_ephemeral_hex']),bytes.fromhex(x['server_nonce_hex']),b"\0"*64).build()
  with self.assertRaises(s.SessionError) as caught:
   s.OpenAck.parse(valid[:10])
  self.assertEqual(caught.exception.category,"TRUNCATED")
  malformed=bytearray(valid); malformed[10]^=1
  with self.assertRaises(s.SessionError) as caught:
   s.OpenAck.parse(bytes(malformed))
  self.assertEqual(caught.exception.category,"EID_KEY_MISMATCH")
  with self.assertRaises(s.SessionError) as caught:
   s.verify_signature(server.public,b"R8 OPEN_ACK v1",b"x",b"\0"*64)
  self.assertEqual(caught.exception.category,"AUTH_FAILED")
  with self.assertRaises(s.SessionError) as caught:
   s.x25519(bytes.fromhex(i['client_x25519_secret_hex']),b"\0"*32)
  self.assertEqual(caught.exception.category,"AUTH_FAILED")
 def test_server_cookie_first_auth_and_accept_promotion(self):
  i=V['identities']; x=V['context']
  client=s.Identity.from_seed(bytes.fromhex(i['client_ed25519_seed_hex']))
  server=s.Identity.from_seed(bytes.fromhex(i['server_ed25519_seed_hex']))
  source=s.ipaddress.IPv6Address("11:2233:4455:6677:8899:aabb:ccdd:eeff")
  destination=s.ipaddress.IPv6Address("ffee:ddcc:bbaa:9988:7766:5544:3322:1100")
  binding=s.UdpBinding.from_endpoint("192.0.2.10",52808,1,b"\x90"*16)
  clock=lambda: x["cookie_bucket"]*10
  machine=s.ClientMachine(client,s.PeerPin(2,server.eid,server.public),x['service_context'],0,source,destination,clock)
  opening=machine.start(x['scid'],bytes.fromhex(i['client_x25519_secret_hex']),bytes.fromhex(x['client_nonce_hex']))
  config=s.ServerConfig(server,s.PeerPin(1,client.eid,client.public),x['service_context'],x['server_context_id'],
                        0,destination,source,1280,256,1024)
  server_machine=s.ServerMachine(config,bytes.fromhex(x['server_boot_instance_hex']),
                                 bytes.fromhex(x['cookie_key_hex']),None,0,clock,
                                 s.PrevalidationLimiter(clock,b"\xa0"*32))
  verify_packet=server_machine.receive_open_packet(opening,binding,x["cookie_bucket"])
  auth=machine.receive_verify(verify_packet)
  ack=server_machine.receive_open_auth(auth,binding,x["cookie_bucket"],bytes.fromhex(i['server_x25519_secret_hex']),bytes.fromhex(x['server_nonce_hex']))
  self.assertEqual(len(server_machine.pending),1)
  accept=machine.receive_ack(ack)
  self.assertEqual(server_machine.receive_protected(accept),b"")
  self.assertEqual(len(server_machine.established),1)
  data=machine.send_data(b"synthetic session data")
  self.assertEqual(data.hex(),V["positive_cases"][5]["protected"]["packet_hex"])
  plaintext,_,_,preview=server_machine.preview_data(data); self.assertEqual(plaintext,b"synthetic session data")
  before=server_machine.established[x["scid"]]["last"]; server_machine.abort_data_preview(preview)
  self.assertEqual(server_machine.established[x["scid"]]["last"],before)
  with self.assertRaises(s.SessionError): server_machine.abort_data_preview(preview)
  plaintext,_,_,preview=server_machine.preview_data(data); server_machine.commit_data(preview)
  self.assertEqual(plaintext,b"synthetic session data")
  tampered=bytearray(data); tampered[-1]^=1
  with self.assertRaises(s.SessionError): server_machine.receive_protected(bytes(tampered))
  reply=server_machine.send_data(x["scid"],b"reply")
  self.assertEqual(machine.receive_protected(reply),b"reply")
  with self.assertRaises(s.SessionError): machine.receive_protected(reply)
  closing=machine.close(7)
  self.assertEqual(server_machine.receive_protected(closing),b"\0\x07")
 def test_binding_cookie_and_prevalidation_limiter(self):
  x=V["context"]; i=V["identities"]
  binding=s.UdpBinding.from_endpoint("192.0.2.10",52808,1,b"\x90"*16)
  self.assertEqual(binding.encode().hex(),x["udp_binding_ipv4_hex"])
  raw=s.cookie_input(binding,1,2,x["service_context"],x["scid"],bytes.fromhex(i["client_eid_hex"]),
                     bytes.fromhex(i["client_public_key_hex"]),bytes.fromhex(i["client_ephemeral_hex"]),
                     bytes.fromhex(x["server_boot_instance_hex"]),x["cookie_bucket"],x["server_context_id"])
  self.assertEqual(raw.hex(),x["cookie_input_hex"])
  self.assertEqual(s.cookie(bytes.fromhex(x["cookie_key_hex"]),binding,1,2,x["service_context"],x["scid"],
                    bytes.fromhex(i["client_eid_hex"]),bytes.fromhex(i["client_public_key_hex"]),
                    bytes.fromhex(i["client_ephemeral_hex"]),bytes.fromhex(x["server_boot_instance_hex"]),
                    x["cookie_bucket"],x["server_context_id"]).hex(),x["cookie_hmac_hex"])
  now=[0]; limiter=s.PrevalidationLimiter(lambda:now[0],b"\xa0"*32,max_sources=1,burst=2,refill=0)
  limiter.admit("a",170,170)
  limiter.admit("a",170,170)
  with self.assertRaises(s.SessionError): limiter.admit("b",170,170)
 def test_server_config_cookie_order_and_header_limits(self):
  i=V["identities"]; x=V["context"]; client=s.Identity.from_seed(bytes.fromhex(i["client_ed25519_seed_hex"]))
  server=s.Identity.from_seed(bytes.fromhex(i["server_ed25519_seed_hex"]))
  local=s.ipaddress.IPv6Address("ffee:ddcc:bbaa:9988:7766:5544:3322:1100"); peer=s.ipaddress.IPv6Address("11:2233:4455:6677:8899:aabb:ccdd:eeff")
  now=[100]; clock=lambda:now[0]; binding=s.UdpBinding.from_endpoint("192.0.2.10",52808,1,b"\x90"*16)
  config=s.ServerConfig(server,s.PeerPin(1,client.eid,client.public),x["service_context"],x["server_context_id"],0,local,peer,1280,1,1)
  machine=s.ServerMachine(config,bytes.fromhex(x["server_boot_instance_hex"]),bytes.fromhex(x["cookie_key_hex"]),b"\x81"*32,110,clock,s.PrevalidationLimiter(clock,b"\xa0"*32))
  c=s.ClientMachine(client,s.PeerPin(2,server.eid,server.public),x["service_context"],0,peer,local,clock)
  opening=c.start(x["scid"],bytes.fromhex(i["client_x25519_secret_hex"]),bytes.fromhex(x["client_nonce_hex"]))
  verify=machine.receive_open_packet(opening,binding,10)
  auth=bytearray(c.receive_verify(verify)); auth[48 + 4 + 134]^=1
  with mock.patch.object(s,"verify_signature") as signature, mock.patch.object(s,"x25519") as shared:
   with self.assertRaises(s.SessionError) as caught:
    machine.receive_open_auth(bytes(auth),binding,10,bytes.fromhex(i["server_x25519_secret_hex"]),bytes.fromhex(x["server_nonce_hex"]))
   self.assertEqual(caught.exception.category,"COOKIE_INVALID"); signature.assert_not_called(); shared.assert_not_called()
  wrong=bytearray(opening); wrong[16]^=1
  with self.assertRaises(s.SessionError): machine.receive_open_packet(bytes(wrong),binding,10)
 def test_limiter_response_tokens_refill_and_keyed_slots(self):
  now=[0]; limiter=s.PrevalidationLimiter(lambda:now[0],b"\xaa"*32,max_sources=2,burst=2,refill=1)
  binding=s.UdpBinding.from_endpoint("192.0.2.10",52808,1,b"\x90"*16)
  limiter.admit(binding,170,170); limiter.admit(binding,170,170)
  with self.assertRaises(s.SessionError): limiter.admit(binding,170,170)
  now[0]=1; limiter.admit(binding,170,170)
  self.assertTrue(all(isinstance(key,bytes) and b"192.0.2.10" not in key for key in limiter.sources))
  now[0]=2; limiter.admit("older",170,170)
  now[0]=3; limiter.admit("newest",170,170)
  self.assertLessEqual(len(limiter.sources),2)
 def test_cli_underlay_policy_and_bounded_socket(self):
  self.assertEqual(s._endpoint("127.0.0.1:52808"),("127.0.0.1",52808))
  self.assertEqual(s._endpoint("127.0.0.1:0",allow_zero=True),("127.0.0.1",0))
  for endpoint in ("0.0.0.0:1","224.0.0.1:1","240.0.0.1:1","8.8.8.8:1"):
   with self.subTest(endpoint=endpoint):
    with self.assertRaises(ValueError): s._endpoint(endpoint)
  self.assertEqual(s._endpoint("10.0.0.1:1",True),("10.0.0.1",1))
 def test_udp_send_requires_full_completion(self):
  class FakeSocket:
   def __init__(self, result): self.result=result
   def sendto(self, packet, endpoint): return self.result
  s._udp_send(FakeSocket(2),b"ok",("127.0.0.1",1))
  for result in (0,1):
   with self.subTest(result=result):
    with self.assertRaises(OSError): s._udp_send(FakeSocket(result),b"ok",("127.0.0.1",1))
 def test_updated_finite_categories_and_rng_failure(self):
  for category in ("TIMEOUT","BUDGET","BINDING_INVALID","CONFIG_ERROR","RNG_FAILURE"):
   self.assertIn(category,s.ERRORS)
   self.assertEqual(s.SessionError(category).category,category)
  with mock.patch.object(s.os,"urandom",side_effect=OSError("unavailable")):
   with self.assertRaises(s.SessionError) as caught:
    s._random(32)
  self.assertEqual(caught.exception.category,"RNG_FAILURE")
  identity=s.Identity.from_seed(b"\x10"*32)
  peer=s.Identity.from_seed(b"\x20"*32)
  client=s.ClientMachine(identity,s.PeerPin(2,peer.eid,peer.public),1,0,
                         s.ipaddress.IPv6Address("8::1"),s.ipaddress.IPv6Address("8::2"),lambda:0)
  self.assertEqual(client.state,client.IDLE)
  with self.assertRaises(s.SessionError) as caught:
   s.UdpBinding(b"\x01\x02",0,0,b"").encode()
  self.assertEqual(caught.exception.category,"BINDING_INVALID")
 def test_cookie_key_rotation_window_and_session_preservation(self):
  client=s.Identity.from_seed(b"\x10"*32); server=s.Identity.from_seed(b"\x20"*32)
  local=s.ipaddress.IPv6Address("8::2"); peer=s.ipaddress.IPv6Address("8::1")
  now=[599.0]; clock=lambda:now[0]
  config=s.ServerConfig(server,s.PeerPin(1,client.eid,client.public),1,1,0,local,peer,1280,1,1)
  old=b"\x31"*32; new=b"\x32"*32
  machine=s.ServerMachine(config,b"\x40"*16,old,None,0,clock,s.PrevalidationLimiter(clock,b"\x41"*32))
  binding=s.UdpBinding.from_endpoint("192.0.2.10",52808,1,b"\x90"*16)
  auth=SimpleNamespace(sender_role=1,receiver_role=2,service_context=1,scid=9,
                       sender_eid=client.eid,sender_public_key=client.public,
                       sender_ephemeral=b"\x50"*32,cookie_value=b"")
  bucket=60
  auth.cookie_value=s.cookie(old,binding,1,2,1,9,client.eid,client.public,b"\x50"*32,
                              b"\x40"*16,bucket,1)
  self.assertTrue(machine._cookies(binding,auth,9,bucket))
  now[0]=600; machine.rotate_cookie_key(new,now[0])
  self.assertEqual(machine.cookie_key,new); self.assertEqual(machine.prior_cookie_key,old)
  self.assertEqual(machine.prior_key_valid_until,620)
  now[0]=619.999; self.assertTrue(machine._cookies(binding,auth,9,bucket))
  now[0]=620; self.assertTrue(machine._cookies(binding,auth,9,bucket))
  now[0]=620.0001; self.assertFalse(machine._cookies(binding,auth,9,bucket))
  auth.cookie_value=s.cookie(new,binding,1,2,1,9,client.eid,client.public,b"\x50"*32,
                              b"\x40"*16,bucket,1)
  self.assertTrue(machine._cookies(binding,auth,9,bucket))
  machine.pending[9]="kept"; machine.established[9]={"last":620}
  machine.rotate_cookie_key(b"\x33"*32,1200)
  self.assertIn(9,machine.pending); self.assertIn(9,machine.established)
 def test_decoder_bounds_and_replay(self):
  with self.assertRaises(s.SessionError): s.decode(b'')
  r=s.ReplayWindow(); r.check_and_mark(1)
  with self.assertRaises(s.SessionError): r.check_and_mark(1)
  with self.assertRaises(s.SessionError): r.check_and_mark(1048578)
 def test_failed_auth_does_not_mutate_replay(self):
  q=s.Session(b'\1'*32); header=b'h'*48; prefix=b'\6\1\0\0'; c,ct=q.encrypt(header,prefix,b'x')
  with self.assertRaises(s.SessionError): q.decrypt(header+b'x',prefix,c,ct)
  self.assertEqual(q.decrypt(header,prefix,c,ct),b'x')
 def test_transactional_decrypt_is_single_use_and_auth_does_not_mark(self):
  sender=s.Session(b'\2'*32); receiver=s.Session(b'\2'*32)
  header=b'h'*48; prefix=b'\6\1\0\0'; counter,ciphertext=sender.encrypt(header,prefix,b'x')
  with self.assertRaises(s.SessionError): receiver.preview_decrypt(header+b'x',prefix,counter,ciphertext)
  plaintext,first=receiver.preview_decrypt(header,prefix,counter,ciphertext)
  self.assertEqual(plaintext,b'x'); self.assertEqual(receiver.replay.highest,0)
  _,second=receiver.preview_decrypt(header,prefix,counter,ciphertext)
  receiver.commit_decrypt(first)
  self.assertEqual(receiver.replay.highest,counter)
  with self.assertRaises(s.SessionError): receiver.commit_decrypt(first)
  with self.assertRaises(s.SessionError): receiver.commit_decrypt(second)
 def test_client_data_preview_defers_idle_and_allows_only_exact_alternate_locs(self):
  now=[1]; local=s.ipaddress.IPv6Address("2001:db8::1"); peer=s.ipaddress.IPv6Address("2001:db8::2")
  alternate=s.ipaddress.IPv6Address("2001:db8::3"); identity=s.Identity.from_seed(b'\3'*32)
  client=s.ClientMachine(identity,s.PeerPin(2,identity.eid,identity.public),1,0,local,peer,lambda:now[0])
  client.state,client.scid,client.deadline,client.s2c_session,client.c2s_session=client.ESTABLISHED,9,0,s.Session(b'\4'*32),s.Session(b'\5'*32)
  header=s.Header(s.NH_SES,alternate,local,profile=0,flags=1,scid=9); prefix=b'\6\1\0\0'
  sender=s.Session(b'\4'*32); counter,ciphertext=sender.encrypt(
   header.pack(prefix+b'\0'*8+b'\0'*17)[:48],prefix,b'x')
  packet=s.build_packet(header,s.ProtectedMessage(6,0,counter,ciphertext).build())
  with self.assertRaises(s.SessionError): client.preview_data(packet)
  self.assertEqual(client.s2c_session.replay.highest,0)
  plaintext,parsed,message,preview=client.preview_data(packet,{alternate},{local})
  self.assertEqual((plaintext,(parsed.profile,parsed.tc,parsed.nh,parsed.hop,parsed.flags,parsed.pslot,parsed.scid,parsed.src,parsed.dst),message.counter),(b'x',(header.profile,header.tc,header.nh,header.hop,header.flags,header.pslot,header.scid,header.src,header.dst),counter)); self.assertEqual(client.deadline,0)
  client.abort_data_preview(preview); self.assertEqual(client.deadline,0)
  with self.assertRaises(s.SessionError): client.abort_data_preview(preview)
  plaintext,parsed,message,preview=client.preview_data(packet,{alternate},{local})
  now[0]=2; client.commit_data(preview); self.assertEqual(client.deadline,2)
  counter,ciphertext=sender.encrypt(header.pack(prefix+b'\0'*8+b'\0'*17)[:48],prefix,b'z')
  packet=s.build_packet(header,s.ProtectedMessage(6,0,counter,ciphertext).build())
  _,_,_,first=client.preview_data(packet,{alternate},{local}); _,_,_,second=client.preview_data(packet,{alternate},{local})
  client.abort_data_preview(first); client.commit_data(second)
  counter,ciphertext=sender.encrypt(header.pack(prefix+b'\0'*8+b'\0'*17)[:48],prefix,b'w')
  packet=s.build_packet(header,s.ProtectedMessage(6,0,counter,ciphertext).build())
  _,_,_,preview=client.preview_data(packet,{alternate},{local})
  outcomes=[]
  def invoke(method, token):
   try: method(token); outcomes.append("ok")
   except s.SessionError: outcomes.append("replay")
  aborter=threading.Thread(target=invoke,args=(client.abort_data_preview,preview))
  committer=threading.Thread(target=invoke,args=(client.commit_data,preview))
  aborter.start(); committer.start(); aborter.join(); committer.join()
  self.assertEqual(sorted(outcomes),["ok","replay"])
  client.promote_local_loc(alternate); client.promote_peer_loc(local)
  sent=client.send_data(b'y'); outgoing,_=s.parse_packet(sent)
  self.assertEqual((outgoing.src,outgoing.dst),(alternate,local))
if __name__=='__main__': unittest.main()
