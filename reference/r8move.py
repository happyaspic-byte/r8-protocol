#!/usr/bin/env python3
"""Closed-lab R8 protected-mobility UDP CLI; diagnostics contain no identifiers."""
import argparse, ipaddress, os, resource, select, socket, struct, sys, time
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
def _nonzero_random(size):
    for _ in range(4):
        value = _random(size)
        if any(value):
            return value
    raise SessionError("RNG_FAILURE")
def _write(fd, value):
    while value:
        written = os.write(fd, value)
        if written <= 0: raise OSError("write")
        value = value[written:]
def _event(fd, sequence):
    if fd is not None: _write(fd, struct.pack("!QQ", sequence, time.monotonic_ns()))
def _record(fd, sequence, stamp=None):
    if fd is not None: _write(fd, struct.pack("!QQ", sequence, time.monotonic_ns() if stamp is None else stamp))
def _ready(fd):
    if fd is not None: _write(fd, struct.pack("!Q", time.monotonic_ns()))
def _cpu_snapshot():
    return time.monotonic_ns(), resource.getrusage(resource.RUSAGE_SELF)
def _cpu_record(fd, before):
    if fd is None or before is None: return
    before_ns, before_usage = before
    after_ns, after_usage = _cpu_snapshot()
    _write(fd, struct.pack("!QQQQQQ", before_ns, int(before_usage.ru_utime*1e9),
        int(before_usage.ru_stime*1e9), after_ns, int(after_usage.ru_utime*1e9),
        int(after_usage.ru_stime*1e9)))
def _wait_until_ns(target):
    while time.monotonic_ns() < target:
        time.sleep(min((target-time.monotonic_ns())/1e9,.02))
def _read_exact(fd, length):
    raw = b""
    while len(raw) < length:
        part = os.read(fd, length-len(raw))
        if not part: raise OSError("read")
        raw += part
    return raw
def _read_schedule(schedule_fd):
    if schedule_fd is None: raise ValueError("configuration")
    return struct.unpack("!QQQ", _read_exact(schedule_fd, 24))
def _wait_gate(gate_fd):
    if gate_fd is None: raise ValueError("configuration")
    _read_exact(gate_fd, 1)
def _udp_socket():
    sock = _socket()
    try:
        sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_MTU_DISCOVER", 10),
                        getattr(socket, "IP_PMTUDISC_DO", 2))
    except OSError:
        sock.close()
        raise
    return sock
def _receive(sock, deadline, budget):
    return _receive_any((sock,), deadline, budget)[1:]
def _receive_any(socks, deadline, budget):
    while True:
        remaining = deadline-time.monotonic()
        if remaining <= 0: break
        readable, _, _ = select.select(socks, [], [], remaining)
        for sock in readable:
            packet, endpoint = sock.recvfrom(budget + 1)
            if len(packet) <= budget: return sock, packet, endpoint
    raise SessionError("TIMEOUT")
def _send(sock, packet, endpoint): _udp_send(sock, packet, endpoint)
class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("configuration")

def _arguments():
    parser = _Parser(prog="r8move", add_help=True); commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    for name in ("serve", "connect"):
        arg = commands.add_parser(name)
        for flag, kind, default in (("--local-seed-hex",str,None),("--peer-public-key-hex",str,None),("--service-context",int,None),("--server-context-id",int,None),("--address",str,None),("--peer-address",str,None),("--new-address",str,None),("--policy",int,1),("--binding-budget",int,BUDGET),("--timeout",float,5),("--candidate-bind",str,"127.0.0.1:0"),("--stream-rate",int,0),("--stream-start-ns",int,0),("--stream-cutover-ns",int,0),("--stream-end-ns",int,0),("--events-fd",int,None),("--ready-fd",int,None),("--schedule-fd",int,None),("--gate-fd",int,None),("--cutover-gate-fd",int,None),("--scheduled-fd",int,None),("--attempt-fd",int,None),("--sent-fd",int,None),("--cpu-fd",int,None)):
            arg.add_argument(flag, type=kind, required=default is None and flag in ("--local-seed-hex","--peer-public-key-hex","--service-context","--server-context-id","--address","--peer-address","--new-address"), default=default)
        arg.add_argument("--moving-role", choices=(1,2), type=int, default=1)
        arg.add_argument("--mode", choices=("abrupt","mbb"), default="mbb")
        arg.add_argument("--allow-isolated-underlay", action="store_true")
        arg.add_argument("--bind", default="127.0.0.1:52818" if name == "serve" else "127.0.0.1:0")
        if name == "connect":
            arg.add_argument("--peer", required=True); arg.add_argument("--message-hex", default="00" * 64)
        else: arg.add_argument("--max-sessions", type=int, default=1); arg.add_argument("--expected-post-move", type=int, default=1)
    argv=sys.argv[1:]
    if argv and argv[0] in ("serve","connect"):
        actions=commands.choices[argv[0]]._option_string_actions
        seen=set(); index=1
        while index < len(argv):
            value=argv[index]
            if not value.startswith("--"): raise ValueError("configuration")
            flag=value.split("=",1)[0]
            if flag in seen: raise ValueError("configuration")
            seen.add(flag)
            action=actions.get(flag)
            if "=" not in value and action is not None and action.nargs != 0: index+=1
            index+=1
    return parser.parse_args(argv)
def _validate(a):
    seed, public = _raw(a.local_seed_hex,32), _raw(a.peer_public_key_hex,32)
    if not (0 < a.service_context <= 0xffffffff and 0 < a.server_context_id <= 0xffffffff and 48 <= a.binding_budget <= BUDGET and a.timeout > 0 and 0 <= a.policy <= 0xffffffff and a.stream_rate >= 0 and (a.command == "connect" or (a.max_sessions > 0 and a.expected_post_move > 0))): raise ValueError("configuration")
    if a.command == "serve" and a.moving_role == 2 and a.max_sessions != 1: raise ValueError("configuration")
    if a.stream_rate and 1_000_000_000 % a.stream_rate: raise ValueError("configuration")
    if bool(a.schedule_fd is not None) != bool(a.gate_fd is not None): raise ValueError("configuration")
    stream_fds=(a.scheduled_fd,a.attempt_fd,a.sent_fd,a.events_fd,a.cpu_fd)
    fd_schedule=a.schedule_fd is not None
    mover=(a.command == "connect" and a.moving_role == 1) or (a.command == "serve" and a.moving_role == 2)
    if a.cutover_gate_fd is not None and (not fd_schedule or not mover): raise ValueError("configuration")
    if fd_schedule and a.command == "serve" and a.max_sessions != 1: raise ValueError("configuration")
    if a.stream_rate:
        if not fd_schedule and not all((a.stream_start_ns,a.stream_cutover_ns,a.stream_end_ns)): raise ValueError("configuration")
    elif any(fd is not None for fd in stream_fds+(a.schedule_fd,a.gate_fd,a.cutover_gate_fd)):
        raise ValueError("configuration")
    old, peer, new = map(ipaddress.IPv6Address, (a.address,a.peer_address,a.new_address))
    bind = _endpoint(a.bind,a.allow_isolated_underlay,a.command == "connect"); candidate = _endpoint(a.candidate_bind,a.allow_isolated_underlay,True)
    target = _endpoint(a.peer,a.allow_isolated_underlay) if a.command == "connect" else None
    return Identity.from_seed(seed), PeerPin(2 if a.command == "connect" else 1,eid(public),public), old,peer,new,bind,candidate,target
def _handshake(a, identity, pin, old, peer, bind, target):
    client = ClientMachine(identity,pin,a.service_context,0,old,peer,time.monotonic,a.binding_budget)
    sock = _udp_socket(); sock.bind(bind); scid = int.from_bytes(_nonzero_random(8), "big")
    packet = client.start(scid, _random(32), _random(32)); phase = 0
    opened_at = time.monotonic(); deadline = opened_at + min(a.timeout, 5)
    retry_waits = (0.5, 1.0, 2.0); retry_index = 0
    retry_deadlines = (opened_at + 0.5, opened_at + 1.5, opened_at + 3.5)
    _send(sock, packet, target); next_retry = min(deadline, retry_deadlines[0])
    while phase < 3 and time.monotonic() < deadline:
        try:
            incoming, endpoint = _receive(sock, min(deadline, next_retry), a.binding_budget)
        except SessionError as error:
            if error.category != "TIMEOUT":
                raise
            if time.monotonic() >= deadline:
                break
            if retry_index < len(retry_waits):
                _send(sock, packet, target)
                retry_index += 1
                next_retry = (min(deadline, retry_deadlines[retry_index])
                              if retry_index < len(retry_deadlines) else deadline)
            continue
        if endpoint != target:
            continue
        try:
            if phase == 0:
                packet = client.receive_verify(incoming); phase = 1
                _send(sock, packet, target)
            elif phase == 1:
                packet = client.receive_ack(incoming); phase = 2
                _send(sock, packet, target); phase = 3
        except SessionError:
            continue
    if phase != 3:
        raise SessionError("TIMEOUT")
    return client,sock,scid
def _exchange(client,sock,target,payload,budget,deadline,event_fd=None,attempt_fd=None,sent_fd=None):
    sequence = struct.unpack("!Q", payload[:8])[0] if len(payload) == 64 else None
    if sequence is not None: _record(attempt_fd, sequence)
    _send(sock,client.send_data(payload),target)
    if sequence is not None: _record(sent_fd, sequence)
    while time.monotonic() < deadline:
        packet, endpoint = _receive(sock,deadline,budget)
        if endpoint != target: continue
        if client.receive_protected(packet) == payload:
            if len(payload) == 64 and event_fd is not None: _event(event_fd,sequence)
            return
    raise SessionError("TIMEOUT")
def _move(a,client,old_sock,candidate_sock,target,manager,old,peer,new):
    cid = _nonzero_random(16)
    update = manager.propose_local(new,1,cid)
    # MBB advertises over old carrier. Abrupt abandons it before advertising from candidate with old outer LOC.
    update_sock = old_sock if a.mode == "mbb" else candidate_sock
    if a.mode == "abrupt": old_sock.close()
    _send(update_sock,client.send_data_with_locs(update,old,peer),target)
    carrier = _binding(target,_random(16)); probe = manager.make_probe(cid,carrier,_random(16))
    _send(candidate_sock,client.send_data_with_locs(probe,new,peer),target)
    deadline=time.monotonic()+3; retry_waits=(0.5,1.0,2.0); retry_index=0
    retry=time.monotonic()+retry_waits[0]
    while time.monotonic() < deadline:
        try: packet, endpoint = _receive(candidate_sock,min(deadline,retry),a.binding_budget)
        except SessionError as error:
            if error.category != "TIMEOUT": raise
            if time.monotonic() >= deadline: break
            if retry_index < len(retry_waits):
                _send(update_sock,client.send_data_with_locs(update,old,peer),target)
                _send(candidate_sock,client.send_data_with_locs(probe,new,peer),target)
                retry_index += 1
                retry=(time.monotonic()+retry_waits[retry_index]
                       if retry_index < len(retry_waits) else deadline)
            continue
        if endpoint != target: continue
        try:
            control, reply, results = _commit_client_control(client, manager, packet, carrier, [peer], [new])
        except (SessionError, MobilityError, ValueError):
            continue
        if reply: _send(candidate_sock,client.send_data_with_locs(reply,new,peer),target)
        for result in results: _send(candidate_sock,client.send_data_with_locs(result,new,peer),target)
        if control.__class__.__name__ == "Result" and control.result == 1:
            client.promote_local_loc(manager.local_loc); return
    raise SessionError("TIMEOUT")
def _commit_client_control(client, manager, packet, observed, allowed_sources, allowed_destinations):
    preview = None
    try:
        plain, _, _, preview = client.preview_data(packet, allowed_sources, allowed_destinations)
        control = parse_control(plain)
        reply = manager.commit(manager.preview(plain, observed, preview))
        return control, reply, tuple(manager.take_results())
    except (SessionError, MobilityError, ValueError):
        if preview is not None: client.abort_data_preview(preview)
        raise
def _commit_server_control(server, manager, packet, observed, allowed_sources, allowed_destinations):
    preview = None
    try:
        plain, header, _, preview = server.preview_data(packet, allowed_sources, allowed_destinations)
        control = parse_control(plain)
        reply = manager.commit(manager.preview(plain, observed, preview))
        return header, control, reply, tuple(manager.take_results())
    except (SessionError, MobilityError, ValueError):
        if preview is not None: server.abort_data_preview(preview)
        raise

def _serve_role2_mover(a, server, old_sock, candidate_sock, target, scid, manager, old, peer, new):
    cid = _nonzero_random(16)
    update = manager.propose_local(new,1,cid)
    carrier = _binding(target,_random(16))
    probe = manager.make_probe(cid,carrier,_random(16))
    update_sock = old_sock if a.mode == "mbb" else candidate_sock
    old_live = a.mode == "mbb"
    if not old_live: old_sock.close()
    _send(update_sock,server.send_data_with_locs(scid,update,old,peer),target)
    _send(candidate_sock,server.send_data_with_locs(scid,probe,new,peer),target)
    deadline=time.monotonic()+3; retry_waits=(0.5,1.0,2.0); retry_index=0
    retry=time.monotonic()+retry_waits[0]
    while time.monotonic() < deadline:
        try: packet, endpoint = _receive(candidate_sock,min(deadline,retry),a.binding_budget)
        except SessionError as error:
            if error.category != "TIMEOUT": raise
            if time.monotonic() >= deadline: break
            if retry_index < len(retry_waits):
                _send(update_sock,server.send_data_with_locs(scid,update,old,peer),target)
                _send(candidate_sock,server.send_data_with_locs(scid,probe,new,peer),target)
                retry_index += 1
                retry=(time.monotonic()+retry_waits[retry_index]
                       if retry_index < len(retry_waits) else deadline)
            continue
        if endpoint != target: continue
        try:
            _, control, reply, results = _commit_server_control(server,manager,packet,carrier,[peer],[new])
        except (SessionError, MobilityError, ValueError): continue
        if reply: _send(candidate_sock,server.send_data_with_locs(scid,reply,new,peer),target)
        for result in results: _send(candidate_sock,server.send_data_with_locs(scid,result,new,peer),target)
        if control.__class__.__name__ == "Result":
            if control.result != 1: raise MobilityError("E-CANDIDATE")
            if not manager.local_loc == old:
                server.promote_local_loc(manager.local_loc)
            return carrier, old_live
    raise SessionError("TIMEOUT")
def _connect_role1_responder(a, client, sock, target, manager, old, peer, new, payload):
    _exchange(client,sock,target,payload,a.binding_budget,time.monotonic()+a.timeout)
    selector=_random(16); deadline=time.monotonic()+a.timeout; promoted=False
    while time.monotonic() < deadline:
        packet, endpoint = _receive(sock,deadline,a.binding_budget)
        observed=_binding(endpoint,selector)
        try:
            control, reply, results = _commit_client_control(client,manager,packet,observed,[peer,new],[old])
        except (SessionError, MobilityError, ValueError):
            continue
        if reply: _send(sock,client.send_data_with_locs(reply,old,new),endpoint)
        for result in results: _send(sock,client.send_data_with_locs(result,old,manager.peer_loc),endpoint)
        if manager.peer_loc == new and not promoted:
            client.promote_peer_loc(manager.peer_loc)
            promoted=True
            break
    if not promoted: raise SessionError("TIMEOUT")
    _exchange(client,sock,endpoint,payload,a.binding_budget,time.monotonic()+a.timeout)
def _connect_role2_stream(a, client, sock, target, manager, old, peer, new, start, cut, end, period):
    selector=_random(16); active_target=target; old_target=target; promoted=False; pending={}; sequence=0
    while time.monotonic_ns() < end:
        now_ns=time.monotonic_ns()
        while start + sequence * period <= now_ns and start + sequence * period < end:
            due=start + sequence * period
            _record(a.scheduled_fd,sequence,due)
            payload=struct.pack("!Q",sequence)+b"\0"*56
            _record(a.attempt_fd,sequence)
            _send(sock,client.send_data(payload),active_target)
            _record(a.sent_fd,sequence)
            pending[payload]=(sequence,due+period)
            sequence+=1
        next_due=min(start + sequence * period,end)
        timeout=max(0,min(next_due,end)-time.monotonic_ns())/1e9
        readable,_,_=select.select([sock],[],[],timeout)
        if not readable: continue
        packet,endpoint=sock.recvfrom(a.binding_budget+1)
        if len(packet)>a.binding_budget: continue
        preview=None
        try:
            plain,_,_,preview=client.preview_data(packet,[peer,new],[old])
            if plain.startswith(b"R8M1"):
                control=parse_control(plain)
                reply=manager.commit(manager.preview(plain,_binding(endpoint,selector),preview))
                preview=None
                if reply: _send(sock,client.send_data_with_locs(reply,old,new),endpoint)
                for result in manager.take_results():
                    _send(sock,client.send_data_with_locs(result,old,manager.peer_loc),endpoint)
                if manager.peer_loc == new and not promoted:
                    client.promote_peer_loc(manager.peer_loc)
                    active_target=endpoint
                    promoted=True
            elif endpoint in (active_target,old_target) and plain in pending and time.monotonic_ns() <= pending[plain][1]:
                client.commit_data(preview); preview=None
                _event(a.events_fd,pending.pop(plain)[0])
            else:
                client.abort_data_preview(preview); preview=None
        except (SessionError,MobilityError,ValueError):
            if preview is not None: client.abort_data_preview(preview)
    if not promoted: raise SessionError("TIMEOUT")
def _connect(a,identity,pin,old,peer,new,bind,candidate_bind,target):
    client,old_sock,scid=_handshake(a,identity,pin,old,peer,bind,target)
    manager=MobilityManager(identity,pin,1,0,scid,a.policy,old,peer,_binding(target,_random(16)),_nonzero_random(32),_ms,client.commit_data)
    payload=bytes.fromhex(a.message_hex)
    if not payload or len(payload)>a.binding_budget-76: raise ValueError("configuration")
    if not a.stream_rate: _ready(a.ready_fd)
    if not a.stream_rate:
        if a.moving_role == 2:
            _connect_role1_responder(a,client,old_sock,target,manager,old,peer,new,payload)
        else:
            candidate=_udp_socket(); candidate.bind(candidate_bind)
            _exchange(client,old_sock,target,payload,a.binding_budget,time.monotonic()+a.timeout)
            _move(a,client,old_sock,candidate,target,manager,old,peer,new)
            _exchange(client,candidate,target,payload,a.binding_budget,time.monotonic()+a.timeout)
        print("[r8move] complete",flush=True); return
    start=a.stream_start_ns; cut=a.stream_cutover_ns; end=a.stream_end_ns
    _ready(a.ready_fd)
    if a.schedule_fd is not None:
        if any((start,cut,end)): raise ValueError("configuration")
        start,cut,end=_read_schedule(a.schedule_fd)
        _wait_gate(a.gate_fd)
    if not (start < cut < end and 1_000_000_000 % a.stream_rate == 0): raise ValueError("configuration")
    period=1_000_000_000//a.stream_rate
    cpu_before=_cpu_snapshot()
    if a.moving_role == 2:
        _connect_role2_stream(a,client,old_sock,target,manager,old,peer,new,start,cut,end,period)
        _cpu_record(a.cpu_fd,cpu_before)
        print("[r8move] complete",flush=True)
        return
    candidate=None; promoted=False; sequence=0; selector=_random(16); active_target=target
    while start + sequence*period < end:
        due=start+sequence*period; now_ns=time.monotonic_ns()
        if not promoted and a.moving_role == 1 and now_ns >= cut:
            candidate=_udp_socket(); candidate.bind(candidate_bind)
            if a.cutover_gate_fd is not None: _wait_gate(a.cutover_gate_fd)
            _move(a,client,old_sock,candidate,target,manager,old,peer,new)
            promoted=True
            continue
        if now_ns >= due:
            _record(a.scheduled_fd, sequence, due)
            if now_ns < due + period:
                data=struct.pack("!Q",sequence)+b"\0"*56
                try:
                    _exchange(client,candidate if promoted and a.moving_role == 1 else old_sock,
                              active_target,data,a.binding_budget,(due+period)/1e9,
                              a.events_fd,a.attempt_fd,a.sent_fd)
                except SessionError as error:
                    if error.category != "TIMEOUT": raise
            sequence+=1
            continue
        time.sleep(min((due-now_ns)/1e9,.02))
        continue
    if a.moving_role == 2 and not promoted: raise SessionError("TIMEOUT")
    _wait_until_ns(end)
    _cpu_record(a.cpu_fd,cpu_before)
    print("[r8move] complete",flush=True)
def _serve_role1(a,identity,pin,old,peer,new,bind,candidate_bind,unused):
    config=ServerConfig(identity,pin,a.service_context,a.server_context_id,0,old,peer,a.binding_budget,256,a.max_sessions)
    server=ServerMachine(config,_random(16),_random(32),None,0,time.monotonic,PrevalidationLimiter(time.monotonic,_random(32)))
    sock=_udp_socket(); sock.bind(bind); selector=_random(16); sessions={}; completed=0
    stream_end_ns=a.stream_end_ns if a.stream_rate else 0
    deadline=max(time.monotonic()+a.timeout,stream_end_ns/1_000_000_000+a.timeout if stream_end_ns else 0); cpu_before=None
    while time.monotonic()<deadline and (not stream_end_ns or time.monotonic_ns()<stream_end_ns):
        try:
            receive_deadline=min(deadline,stream_end_ns/1_000_000_000) if stream_end_ns else deadline
            packet,endpoint=_receive(sock,receive_deadline,a.binding_budget); header,payload=parse_packet(packet,a.binding_budget); typ=decode(payload)[0]; binding=_binding(endpoint,selector); record=None; out=None; out_endpoint=endpoint
            if typ==1: out=server.receive_open_packet(packet,binding,int(time.monotonic()//10))
            elif typ==3:
                out=server.receive_open_auth(packet,binding,int(time.monotonic()//10),_random(32),_random(32))
                sessions[header.scid]={"endpoint":endpoint,"binding":binding,"old_endpoint":None,"old_binding":None,"manager":None,"promoted":False,"post":0,"established":False}
            elif typ==5:
                record=sessions.get(header.scid)
                if record is None or (endpoint,binding)!=(record["endpoint"],record["binding"]): raise SessionError("AUTH_FAILED")
                server.receive_protected(packet)
                if not record["established"]:
                    _ready(a.ready_fd)
                    if a.schedule_fd is not None:
                        start,cut,stream_end_ns=_read_schedule(a.schedule_fd)
                        if not (start < cut < stream_end_ns): raise ValueError("configuration")
                        _wait_gate(a.gate_fd)
                    if stream_end_ns:
                        deadline=stream_end_ns/1_000_000_000+a.timeout
                    if a.stream_rate:
                        cpu_before=_cpu_snapshot()
                record["established"]=True
            else:
                record=sessions.get(header.scid)
                if record is None or not record["established"]: raise SessionError("AUTH_FAILED")
                manager=record["manager"]; initial=manager is None
                if initial:
                    if (endpoint,binding)!=(record["endpoint"],record["binding"]): raise SessionError("AUTH_FAILED")
                    plain,h,_,preview=server.preview_data(packet,None,None)
                    manager=MobilityManager(identity,pin,2,0,header.scid,a.policy,old,peer,record["binding"],_random(32),_ms,server.commit_data); record["manager"]=manager
                else:
                    current=(endpoint,binding)==(record["endpoint"],record["binding"])
                    old_grace=(endpoint,binding)==(record["old_endpoint"],record["old_binding"]) and manager.binding_allowed_inbound(binding)
                    allowed=[manager.peer_loc]+[item[1].new_loc for item in manager.proposals.values()]
                    plain,h,_,preview=server.preview_data(packet,allowed,None)
                if plain.startswith(b"R8M1"):
                    try: reply=manager.commit(manager.preview(plain,binding,preview))
                    except (MobilityError,ValueError):
                        server.abort_data_preview(preview); continue
                    if reply: out=server.send_data_with_locs(header.scid,reply,old,h.src)
                    if manager.peer_loc != peer and not record["promoted"]:
                        record["old_endpoint"],record["old_binding"]=record["endpoint"],record["binding"]
                        server.promote_peer_loc(manager.peer_loc); record["endpoint"]=endpoint; record["binding"]=binding; record["promoted"]=True
                    for result in manager.take_results(): _send(sock,server.send_data_with_locs(header.scid,result,old,manager.peer_loc),endpoint)
                else:
                    if not initial and not (current or old_grace):
                        server.abort_data_preview(preview)
                        raise SessionError("AUTH_FAILED")
                    server.commit_data(preview)
                    if initial: out=server.send_data(header.scid,plain)
                    elif current: out=server.send_data(header.scid,plain)
                    else: out=server.send_data(header.scid,plain); out_endpoint=record["endpoint"]
                    if record["promoted"] and current:
                        record["post"]+=1
                        if record["post"]>=a.expected_post_move: completed+=1
            if out is not None: _send(sock,out,out_endpoint)
        except (SessionError,MobilityError,ValueError):
            continue
    if completed<a.max_sessions: raise SessionError("TIMEOUT")
    _cpu_record(a.cpu_fd,cpu_before)
    print("[r8move] complete",flush=True)
def _serve_role2(a,identity,pin,old,peer,new,bind,candidate_bind,unused):
    config=ServerConfig(identity,pin,a.service_context,a.server_context_id,0,old,peer,a.binding_budget,256,a.max_sessions)
    server=ServerMachine(config,_random(16),_random(32),None,0,time.monotonic,PrevalidationLimiter(time.monotonic,_random(32)))
    sock=_udp_socket(); sock.bind(bind); old_live=True; selector=_random(16); sessions={}; completed=0
    stream_end_ns=a.stream_end_ns if a.stream_rate else 0
    deadline=max(time.monotonic()+a.timeout,stream_end_ns/1_000_000_000+a.timeout if stream_end_ns else 0)
    cut_ns=a.stream_cutover_ns if a.stream_rate else 0; cpu_before=None
    while time.monotonic()<deadline and (not stream_end_ns or time.monotonic_ns()<stream_end_ns):
        for record in tuple(sessions.values()):
            if record["manager"] is not None and record["candidate_sock"] is None and (not stream_end_ns or time.monotonic_ns()>=cut_ns):
                candidate=_udp_socket(); candidate.bind(candidate_bind)
                if a.cutover_gate_fd is not None: _wait_gate(a.cutover_gate_fd)
                record["carrier"],old_live=_serve_role2_mover(a,server,sock,candidate,record["endpoint"],record["scid"],record["manager"],old,peer,new)
                record["candidate_sock"]=candidate; record["local_promoted"]=True
        try:
            receive_deadline=min(deadline,stream_end_ns/1_000_000_000) if stream_end_ns else deadline
            input_sock,packet,endpoint=_receive_any(([sock] if old_live else [])+[r["candidate_sock"] for r in sessions.values() if r["candidate_sock"] is not None],receive_deadline,a.binding_budget)
            header,payload=parse_packet(packet,a.binding_budget); typ=decode(payload)[0]; binding=_binding(endpoint,selector); record=None; out=None; out_endpoint=endpoint
            if typ==1:
                if input_sock is not sock: continue
                out=server.receive_open_packet(packet,binding,int(time.monotonic()//10))
            elif typ==3:
                if input_sock is not sock: continue
                out=server.receive_open_auth(packet,binding,int(time.monotonic()//10),_random(32),_random(32))
                sessions[header.scid]={"scid":header.scid,"endpoint":endpoint,"binding":binding,"manager":None,"established":False,"candidate_sock":None,"carrier":None,"local_promoted":False,"post":0}
            elif typ==5:
                record=sessions.get(header.scid)
                if record is None or input_sock is not sock or (endpoint,binding)!=(record["endpoint"],record["binding"]): raise SessionError("AUTH_FAILED")
                server.receive_protected(packet)
                if not record["established"]:
                    _ready(a.ready_fd)
                    if a.schedule_fd is not None:
                        start,cut_ns,stream_end_ns=_read_schedule(a.schedule_fd)
                        if not (start < cut_ns < stream_end_ns): raise ValueError("configuration")
                        _wait_gate(a.gate_fd)
                    if stream_end_ns:
                        deadline=stream_end_ns/1_000_000_000+a.timeout
                    if a.stream_rate:
                        cpu_before=_cpu_snapshot()
                record["established"]=True
            else:
                record=sessions.get(header.scid)
                if record is None or not record["established"]: raise SessionError("AUTH_FAILED")
                manager=record["manager"]
                if manager is None:
                    if input_sock is not sock or (endpoint,binding)!=(record["endpoint"],record["binding"]): raise SessionError("AUTH_FAILED")
                    plain,h,_,preview=server.preview_data(packet,None,None)
                    manager=MobilityManager(identity,pin,2,0,header.scid,a.policy,old,peer,record["binding"],_random(32),_ms,server.commit_data); record["manager"]=manager
                elif input_sock is record["candidate_sock"]:
                    if endpoint != record["endpoint"]: raise SessionError("AUTH_FAILED")
                    plain,h,_,preview=server.preview_data(packet,[peer],[new])
                    if plain.startswith(b"R8M1"):
                        try: reply=manager.commit(manager.preview(plain,record["carrier"],preview))
                        except (MobilityError,ValueError): server.abort_data_preview(preview); continue
                        if reply: _send(input_sock,server.send_data_with_locs(header.scid,reply,new,peer),endpoint)
                        for result in manager.take_results(): _send(input_sock,server.send_data_with_locs(header.scid,result,new,peer),endpoint)
                    else:
                        server.commit_data(preview); _send(input_sock,server.send_data(header.scid,plain),endpoint)
                        record["post"]+=1
                        if record["post"]>=a.expected_post_move: completed+=1
                    continue
                else:
                    if input_sock is not sock or not manager.binding_allowed_inbound(record["binding"]): raise SessionError("AUTH_FAILED")
                    plain,h,_,preview=server.preview_data(packet,[peer],[old,new])
                    server.commit_data(preview); _send(record["candidate_sock"] if record["candidate_sock"] is not None else sock,server.send_data(header.scid,plain),record["endpoint"])
                    continue
                if plain.startswith(b"R8M1"):
                    try: reply=manager.commit(manager.preview(plain,binding,preview))
                    except (MobilityError,ValueError): server.abort_data_preview(preview); continue
                    if reply: out=server.send_data_with_locs(header.scid,reply,old,h.src)
                else:
                    server.commit_data(preview); out=server.send_data(header.scid,plain)
            if out is not None: _send(sock,out,out_endpoint)
        except (SessionError,MobilityError,ValueError):
            continue
    if completed<a.max_sessions: raise SessionError("TIMEOUT")
    _cpu_record(a.cpu_fd,cpu_before)
    print("[r8move] complete",flush=True)
def _serve(a,*values):
    return (_serve_role2 if a.moving_role == 2 else _serve_role1)(a,*values)
def main():
    try:
        a=_arguments(); values=_validate(a); (_connect if a.command=="connect" else _serve)(a,*values)
    except (ValueError,SessionError,MobilityError,OSError,RuntimeError) as error:
        category=(error.category if isinstance(error,(SessionError,MobilityError)) else "CONFIG" if isinstance(error,ValueError) else "IO")
        print(f"[r8move] error {category}",file=sys.stderr,flush=True)
        return 1
    return 0
if __name__=="__main__": sys.exit(main())
