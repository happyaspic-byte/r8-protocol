#!/usr/bin/env python3
"""Closed-lab R8 protected-mobility UDP CLI; diagnostics contain no identifiers."""
import argparse, ipaddress, os, socket, struct, sys, threading, time
from r8session import (Identity, PeerPin, UdpBinding, ClientMachine, ServerConfig, ServerMachine,
    PrevalidationLimiter, SessionError, _random, _endpoint, _socket, _udp_send, parse_packet, decode, eid)
from r8mobility import MobilityManager, MobilityError, parse_control

BUDGET = 1252
def _ms(): return int(time.monotonic() * 1000)
def _binding(endpoint, selector): return UdpBinding.from_endpoint(endpoint[0], endpoint[1], 1, selector)
def _raw(text, size):
    value = bytes.fromhex(text)
    if len(value) != size: raise ValueError("configuration")
    return value
def _event(fd, sequence):
    if fd is not None: os.write(fd, struct.pack("!QQ", sequence, time.monotonic_ns()))
def _receive(sock, deadline, budget):
    while time.monotonic() < deadline:
        sock.settimeout(max(.001, deadline - time.monotonic()))
        try:
            packet, endpoint = sock.recvfrom(budget + 1)
            if len(packet) <= budget: return packet, endpoint
        except socket.timeout: pass
    raise SessionError("TIMEOUT")
def _send(sock, packet, endpoint): _udp_send(sock, packet, endpoint)
def _arguments():
    parser = argparse.ArgumentParser(prog="r8move"); commands = parser.add_subparsers(dest="command", required=True)
    for name in ("serve", "connect"):
        arg = commands.add_parser(name)
        for flag, kind, default in (("--local-seed-hex",str,None),("--peer-public-key-hex",str,None),("--service-context",int,None),("--server-context-id",int,None),("--address",str,None),("--peer-address",str,None),("--new-address",str,None),("--policy",int,1),("--binding-budget",int,BUDGET),("--timeout",float,5),("--candidate-bind",str,"127.0.0.1:0"),("--deterministic-scid",int,None),("--deterministic-candidate-hex",str,None),("--deterministic-secret-hex",str,None),("--stream-rate",int,0),("--stream-start-ns",int,0),("--stream-cutover-ns",int,0),("--stream-end-ns",int,0),("--events-fd",int,None)):
            arg.add_argument(flag, type=kind, required=default is None and flag in ("--local-seed-hex","--peer-public-key-hex","--service-context","--server-context-id","--address","--peer-address","--new-address"), default=default)
        arg.add_argument("--allow-isolated-underlay", action="store_true")
        arg.add_argument("--bind", default="127.0.0.1:52818" if name == "serve" else "127.0.0.1:0")
        if name == "connect":
            arg.add_argument("--peer", required=True); arg.add_argument("--message-hex", default="00" * 64); arg.add_argument("--mode", choices=("abrupt","mbb"), default="mbb")
        else: arg.add_argument("--max-sessions", type=int, default=1); arg.add_argument("--expected-post-move", type=int, default=1)
    return parser.parse_args()
def _validate(a):
    seed, public = _raw(a.local_seed_hex,32), _raw(a.peer_public_key_hex,32)
    if not (0 < a.service_context <= 0xffffffff and 0 < a.server_context_id <= 0xffffffff and 48 <= a.binding_budget <= BUDGET and a.timeout > 0 and 0 <= a.policy <= 0xffffffff and a.stream_rate >= 0 and (a.command == "connect" or (a.max_sessions > 0 and a.expected_post_move > 0))): raise ValueError("configuration")
    old, peer, new = map(ipaddress.IPv6Address, (a.address,a.peer_address,a.new_address))
    bind = _endpoint(a.bind,a.allow_isolated_underlay,a.command == "connect"); candidate = _endpoint(a.candidate_bind,a.allow_isolated_underlay,True)
    target = _endpoint(a.peer,a.allow_isolated_underlay) if a.command == "connect" else None
    return Identity.from_seed(seed), PeerPin(2 if a.command == "connect" else 1,eid(public),public), old,peer,new,bind,candidate,target
def _handshake(a, identity, pin, old, peer, bind, target):
    client = ClientMachine(identity,pin,a.service_context,0,old,peer,time.monotonic,a.binding_budget)
    sock = _socket(); sock.bind(bind); scid = a.deterministic_scid or int.from_bytes(_random(8),"big")
    if not 0 < scid <= 0xffffffffffffffff: raise ValueError("configuration")
    packet = client.start(scid,_random(32),_random(32)); phase = 0; deadline = time.monotonic() + a.timeout
    while phase < 3 and time.monotonic() < deadline:
        _send(sock,packet,target)
        try: incoming, endpoint = _receive(sock,min(deadline,time.monotonic()+.5),a.binding_budget)
        except SessionError: continue
        if endpoint != target: continue
        try:
            if phase == 0: packet = client.receive_verify(incoming); phase = 1
            elif phase == 1: packet = client.receive_ack(incoming); phase = 2
            if phase == 2: _send(sock,packet,target); phase = 3
        except SessionError: continue
    if phase != 3: raise SessionError("TIMEOUT")
    return client,sock,scid
def _exchange(client,sock,target,payload,budget,deadline,event_fd=None):
    _send(sock,client.send_data(payload),target)
    while time.monotonic() < deadline:
        packet, endpoint = _receive(sock,deadline,budget)
        if endpoint != target: continue
        if client.receive_protected(packet) == payload:
            if len(payload) == 64 and event_fd is not None: _event(event_fd,struct.unpack("!Q",payload[:8])[0])
            return
    raise SessionError("TIMEOUT")
def _move(a,client,old_sock,candidate_sock,target,manager,old,peer,new):
    cid = _raw(a.deterministic_candidate_hex,16) if a.deterministic_candidate_hex else _random(16)
    update = manager.propose_local(new,1,cid)
    # MBB advertises over old carrier. Abrupt abandons it before advertising from candidate with old outer LOC.
    update_sock = old_sock if a.mode == "mbb" else candidate_sock
    if a.mode == "abrupt": old_sock.close()
    _send(update_sock,client.send_data_with_locs(update,old,peer),target)
    carrier = _binding(target,_random(16)); probe = manager.make_probe(cid,carrier,_random(16))
    _send(candidate_sock,client.send_data_with_locs(probe,new,peer),target)
    deadline=time.monotonic()+a.timeout; retry=time.monotonic()+.4
    while time.monotonic() < deadline:
        try: packet, endpoint = _receive(candidate_sock,min(deadline,retry),a.binding_budget)
        except SessionError:
            _send(update_sock,client.send_data_with_locs(update,old,peer),target)
            _send(candidate_sock,client.send_data_with_locs(probe,new,peer),target)
            retry=time.monotonic()+.4
            continue
        if endpoint != target: continue
        try:
            plain,_,_,preview=client.preview_data(packet,[peer],[new]); control=parse_control(plain)
        except SessionError: continue
        try:
            response=manager.preview(plain,carrier,preview); reply=manager.commit(response) # callback commits session preview atomically
        except MobilityError:
            client.abort_data_preview(preview)
            continue
        if reply: _send(candidate_sock,client.send_data_with_locs(reply,new,peer),target)
        for result in manager.take_results(): _send(candidate_sock,client.send_data_with_locs(result,new,peer),target)
        if control.__class__.__name__ == "Result" and control.result == 1:
            client.promote_local_loc(manager.local_loc); return
    raise SessionError("TIMEOUT")
def _connect(a,identity,pin,old,peer,new,bind,candidate_bind,target):
    client,old_sock,scid=_handshake(a,identity,pin,old,peer,bind,target)
    manager=MobilityManager(identity,pin,1,0,scid,a.policy,old,peer,_binding(target,_random(16)),_raw(a.deterministic_secret_hex,32) if a.deterministic_secret_hex else _random(32),_ms,client.commit_data)
    payload=bytes.fromhex(a.message_hex)
    if not payload or len(payload)>a.binding_budget-76: raise ValueError("configuration")
    if not a.stream_rate:
        _exchange(client,old_sock,target,payload,a.binding_budget,time.monotonic()+a.timeout)
        candidate=_socket(); candidate.bind(candidate_bind); _move(a,client,old_sock,candidate,target,manager,old,peer,new)
        _exchange(client,candidate,target,payload,a.binding_budget,time.monotonic()+a.timeout); print("[r8move] complete",flush=True); return
    start=a.stream_start_ns; cut=a.stream_cutover_ns; end=a.stream_end_ns
    if not (start and start <= cut < end): raise ValueError("configuration")
    candidate=None; sequence=0; period=1_000_000_000//a.stream_rate; worker=None; move_errors=[]
    while True:
        due=start+sequence*period
        if due >= end: break
        now_ns=time.monotonic_ns()
        if now_ns < due:
            time.sleep((due-now_ns)/1e9)
            continue
        if worker is None and now_ns >= cut:
            candidate=_socket(); candidate.bind(candidate_bind)
            def run_move():
                try: _move(a,client,old_sock,candidate,target,manager,old,peer,new)
                except (SessionError,MobilityError,OSError) as error: move_errors.append(error)
            worker=threading.Thread(target=run_move,daemon=True)
            worker.start()
        if now_ns >= due + period:
            sequence += (now_ns-due)//period
            continue
        sock=candidate if worker is not None and not worker.is_alive() else old_sock
        data=struct.pack("!Q",sequence)+b"\0"*56
        try: _exchange(client,sock,target,data,a.binding_budget,time.monotonic()+min(.02,period/1e9),a.events_fd)
        except (SessionError,OSError): pass
        sequence+=1
    if worker is not None: worker.join(timeout=a.timeout)
    if worker is not None and (worker.is_alive() or move_errors): raise SessionError("TIMEOUT")
    print("[r8move] complete",flush=True)
def _serve(a,identity,pin,old,peer,new,bind,candidate_bind,unused):
    config=ServerConfig(identity,pin,a.service_context,a.server_context_id,0,old,peer,a.binding_budget,256,a.max_sessions)
    server=ServerMachine(config,_random(16),_random(32),None,0,time.monotonic,PrevalidationLimiter(time.monotonic,_random(32)))
    sock=_socket(); sock.bind(bind); selector=_random(16); sessions={}; completed=0
    stream_end_ns=a.stream_end_ns if a.stream_rate else 0
    deadline=max(time.monotonic()+a.timeout, stream_end_ns/1_000_000_000+a.timeout if stream_end_ns else 0)
    while time.monotonic()<deadline and (completed<a.max_sessions or (stream_end_ns and time.monotonic_ns()<stream_end_ns)):
        try:
            receive_deadline=min(deadline,stream_end_ns/1_000_000_000) if stream_end_ns else deadline
            packet,endpoint=_receive(sock,receive_deadline,a.binding_budget); header,payload=parse_packet(packet,a.binding_budget); typ=decode(payload)[0]; binding=_binding(endpoint,selector); out=None; out_endpoint=endpoint
            if typ==1: out=server.receive_open_packet(packet,binding,int(time.monotonic()//10))
            elif typ==3:
                out=server.receive_open_auth(packet,binding,int(time.monotonic()//10),_random(32),_random(32)); sessions[header.scid]={"endpoint":endpoint,"binding":binding,"old_endpoint":None,"old_binding":None,"manager":None,"promoted":False,"post":0,"established":False}
            elif typ==5:
                record=sessions.get(header.scid)
                if record is None or (endpoint,binding)!=(record["endpoint"],record["binding"]): raise SessionError("AUTH_FAILED")
                if record["manager"] is not None: record["manager"].expire()
                server.receive_protected(packet); record["established"]=True
            else:
                record=sessions.get(header.scid)
                if record is None or not record["established"]: raise SessionError("AUTH_FAILED")
                manager=record["manager"]; initial=manager is None
                if initial:
                    if (endpoint,binding)!=(record["endpoint"],record["binding"]): raise SessionError("AUTH_FAILED")
                    plain,h,_,preview=server.preview_data(packet,None,None)
                    manager=MobilityManager(identity,pin,2,0,header.scid,a.policy,old,peer,record["binding"],_random(32),_ms,server.commit_data); record["manager"]=manager
                    manager.expire()
                else:
                    manager.expire()
                    current=(endpoint,binding)==(record["endpoint"],record["binding"])
                    old_grace=(endpoint,binding)==(record["old_endpoint"],record["old_binding"]) and manager.binding_allowed_inbound(binding)
                    allowed=[manager.peer_loc]+[item[1].new_loc for item in manager.proposals.values()]
                    if old_grace: allowed.append(peer)
                    plain,h,_,preview=server.preview_data(packet,allowed,None)
                if plain.startswith(b"R8M1"):
                    try:
                        reply=manager.commit(manager.preview(plain,binding,preview))
                    except MobilityError:
                        server.abort_data_preview(preview)
                        continue
                    if reply: out=server.send_data_with_locs(header.scid,reply,old,h.src)
                    if manager.peer_loc != peer and not record["promoted"]:
                        record["old_endpoint"],record["old_binding"]=record["endpoint"],record["binding"]
                        server.promote_peer_loc(manager.peer_loc); record["endpoint"]=endpoint; record["binding"]=binding; record["promoted"]=True
                    for result in manager.take_results(): _send(sock,server.send_data_with_locs(header.scid,result,old,manager.peer_loc),endpoint)
                else:
                    if initial:
                        server.commit_data(preview); out=server.send_data(header.scid,plain)
                    else:
                        if not (current or old_grace):
                            server.abort_data_preview(preview)
                            raise SessionError("AUTH_FAILED")
                        server.commit_data(preview)
                        # The old carrier is inbound grace only: its echo uses the current carrier.
                        if current: out=server.send_data(header.scid,plain)
                        elif old_grace: out=server.send_data(header.scid,plain); out_endpoint=record["endpoint"]
                        if record["promoted"] and current:
                            record["post"]+=1
                            if record["post"]>=a.expected_post_move: completed+=1
            if out is not None: _send(sock,out,out_endpoint)
        except (SessionError,MobilityError,ValueError,OSError): continue
    if completed<a.max_sessions: raise SessionError("TIMEOUT")
    print("[r8move] complete",flush=True)
def main():
    try:
        a=_arguments(); values=_validate(a); (_connect if a.command=="connect" else _serve)(a,*values)
    except (ValueError,SessionError,MobilityError,OSError,RuntimeError) as error:
        category=(error.category if isinstance(error,(SessionError,MobilityError)) else "CONFIG" if isinstance(error,ValueError) else "IO")
        print(f"[r8move] error {category}",file=sys.stderr,flush=True)
        return 1
    return 0
if __name__=="__main__": sys.exit(main())
