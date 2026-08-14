#!/usr/bin/env python3
"""Privileged Q1 network-namespace worker and its real TCP endpoint helpers."""
import argparse, hashlib, json, os, resource, selectors, signal, socket, struct, subprocess, sys, tempfile, threading, time, uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / "reference"))
from r8session import Identity
PAYLOAD_SIZE=64; RATE_NS=10_000_000; PORTS={"TCP-reconnect":(53101,53102),"GARP-VIP":(53103,53103),"R8":(53104,53104)}
COUNTERS=("rx_bytes","tx_bytes","rx_packets","tx_packets","rx_dropped","tx_dropped","rx_errors","tx_errors")
MACS={"bridge":"02:00:00:00:01:01","old":"02:00:00:00:01:02","candidate":"02:00:00:00:01:03"}
class StageError(RuntimeError):
 def __init__(self,category): self.category=category
def _stage(category,operation):
 try: return operation()
 except StageError: raise
 except Exception as error: raise StageError(category) from error
def _control(path, phase, **timeline):
 if not path: return
 record={}
 if path and Path(path).exists():
  try: record=json.loads(Path(path).read_text())
  except (OSError,json.JSONDecodeError): record={}
 record.update({"phase":phase,**{key:value for key,value in timeline.items() if (key in {"t_minus_3_ns","activation_ns","activation_start_ns","activation_complete_ns","cutover_ns","observation_end_ns"} and isinstance(value,int)) or (key=="cleanup_complete" and isinstance(value,bool))}})
 temporary=Path(path).with_suffix(".tmp"); temporary.write_text(json.dumps(record,sort_keys=True,separators=(",",":"))); os.chmod(temporary,0o600); os.replace(temporary,path)
class Commands:
 def __init__(self,run=subprocess.run,popen=subprocess.Popen): self.run,self.popen,self.owned,self.transcript=run,popen,[],[]
 def call(self,*a,check=True): self.transcript.append(tuple(a)); return self.run(a,check=check,text=True,capture_output=True)
 def inside(self,ns,*a,check=True): return self.call("ip","netns","exec",ns,*a,check=check)
 def netns(self,n): self.call("ip","netns","add",n); self.owned.append(n)
 def spawn(self,ns,*a,pass_fds=()): self.transcript.append(("ip","netns","exec",ns)+a); return self.popen(("ip","netns","exec",ns)+a,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=pass_fds)
 def cleanup(self):
  failed=False
  for n in reversed(self.owned):
   try:
    result=self.call("ip","netns","del",n,check=False)
    failed=failed or bool(result.returncode)
   except Exception: failed=True
  self.owned.clear()
  if failed: raise StageError("cleanup_delete")
def payload(n): return struct.pack("!Q",n)+b"\0"*56
def _n(x,s): return x+"-"+s
def topology(commands=None,suffix=None):
 c=commands or Commands(); s=suffix or uuid.uuid4().hex[:10]; client,server,router=(_n(x,s) for x in ("r8q1-client","r8q1-server","r8q1-router")); n={"cr0":"qc"+s[:8],"cr1":"qr"+s[:8],"si0":"qso"+s[:7],"rb0":"qbo"+s[:7],"si1":"qsn"+s[:7],"rb1":"qbn"+s[:7]}
 try:
  _stage("namespace_create",lambda:[c.netns(x) for x in (client,server,router)])
  _stage("forwarding_config",lambda:c.inside(router,"sysctl","-w","net.ipv4.ip_forward=1"))
  _stage("veth_create",lambda:[c.call("ip","link","add",a,"type","veth","peer","name",b) for a,b in ((n["cr0"],n["cr1"]),(n["si0"],n["rb0"]),(n["si1"],n["rb1"]))])
  _stage("namespace_move",lambda:([c.call("ip","link","set",n["cr0"],"netns",client),c.call("ip","link","set",n["cr1"],"netns",router)]+[c.call("ip","link","set",n[x],"netns",router) for x in ("rb0","rb1")]+[c.call("ip","link","set",n[x],"netns",server) for x in ("si0","si1")]))
  _stage("forwarding_config",lambda:[c.inside(server,"sysctl","-w",f"net.ipv4.conf.{scope}.{setting}={value}") for scope in ("all","default",n["si0"],n["si1"]) for setting,value in (("rp_filter","0"),("arp_ignore","1"),("arp_announce","2"))])
  _stage("bridge_create",lambda:(c.inside(router,"ip","link","add","brq1","type","bridge"),[c.inside(router,"ip","link","set",n[x],"master","brq1") for x in ("rb0","rb1")]))
  _stage("address_config",lambda:([c.inside(router,"ip","link","set","brq1","address",MACS["bridge"]),c.inside(server,"ip","link","set",n["si0"],"address",MACS["old"]),c.inside(server,"ip","link","set",n["si1"],"address",MACS["candidate"]),c.inside(client,"ip","addr","add","10.88.0.2/24","dev",n["cr0"]),c.inside(router,"ip","addr","add","10.88.0.1/24","dev",n["cr1"]),c.inside(router,"ip","addr","add","10.88.1.1/24","dev","brq1"),c.inside(server,"ip","addr","add","10.88.1.2/24","dev",n["si0"]),c.inside(server,"ip","addr","add","10.88.1.3/24","dev",n["si1"]),c.inside(server,"ip","addr","add","10.88.1.100/32","dev",n["si0"])]))
  _stage("environment_setup",lambda:([c.inside(client,"ip","link","set",n["cr0"],"mtu","1500")]+[c.inside(router,"ip","link","set",d,"mtu","1500") for d in (n["cr1"],n["rb0"],n["rb1"],"brq1")]+[c.inside(server,"ip","link","set",d,"mtu","1500") for d in (n["si0"],n["si1"])]))
  _stage("link_activate",lambda:([c.inside(ns,"ip","link","set","lo","up") for ns in (client,server,router)]+[c.inside(client,"ip","link","set",n["cr0"],"up")]+[c.inside(router,"ip","link","set",d,"up") for d in (n["cr1"],n["rb0"],n["rb1"],"brq1")]+[c.inside(server,"ip","link","set",d,"up") for d in (n["si0"],n["si1"])]))
  _stage("environment_setup",lambda:([c.inside(client,"tc","qdisc","replace","dev",n["cr0"],"root","fq_codel")]+[c.inside(router,"tc","qdisc","replace","dev",d,"root","fq_codel") for d in (n["cr1"],n["rb0"],n["rb1"],"brq1")]+[c.inside(server,"tc","qdisc","replace","dev",d,"root","fq_codel") for d in (n["si0"],n["si1"])]))
  _stage("environment_setup",lambda:([c.inside(client,"ethtool","-K",n["cr0"],"gro","off","gso","off","tso","off")]+[c.inside(router,"ethtool","-K",d,"gro","off","gso","off","tso","off") for d in (n["cr1"],n["rb0"],n["rb1"],"brq1")]+[c.inside(server,"ethtool","-K",d,"gro","off","gso","off","tso","off") for d in (n["si0"],n["si1"])]))
  _stage("route_client_default",lambda:c.inside(client,"ip","route","add","default","via","10.88.0.1","dev",n["cr0"]))
  _stage("route_server_main",lambda:c.inside(server,"ip","route","add","10.88.0.0/24","via","10.88.1.1","dev",n["si0"]))
  _stage("route_old_policy",lambda:([c.inside(server,"ip","route","add","10.88.1.0/24","dev",n["si0"],"scope","link","table","101"),c.inside(server,"ip","route","add","10.88.0.0/24","via","10.88.1.1","dev",n["si0"],"table","101"),c.inside(server,"ip","rule","add","from","10.88.1.2/32","table","101")]))
  _stage("route_candidate_policy",lambda:([c.inside(server,"ip","route","add","10.88.1.0/24","dev",n["si1"],"scope","link","table","102"),c.inside(server,"ip","route","add","10.88.0.0/24","via","10.88.1.1","dev",n["si1"],"onlink","table","102"),c.inside(server,"ip","rule","add","from","10.88.1.3/32","table","102")]))
  _stage("route_vip_policy",lambda:([c.inside(server,"ip","route","add","10.88.1.0/24","dev",n["si0"],"scope","link","table","103"),c.inside(server,"ip","route","add","10.88.0.0/24","via","10.88.1.1","dev",n["si0"],"table","103"),c.inside(server,"ip","rule","add","from","10.88.1.100/32","table","103")]))
  _stage("neighbor_config",lambda:([c.inside(router,"ip","neigh","replace","10.88.1.2","lladdr",MACS["old"],"nud","permanent","dev","brq1"),c.inside(router,"ip","neigh","replace","10.88.1.3","lladdr",MACS["candidate"],"nud","permanent","dev","brq1"),c.inside(server,"ip","neigh","replace","10.88.1.1","lladdr",MACS["bridge"],"nud","permanent","dev",n["si0"]),c.inside(server,"ip","neigh","replace","10.88.1.1","lladdr",MACS["bridge"],"nud","permanent","dev",n["si1"])]))
  _stage("candidate_deactivate",lambda:c.inside(server,"ip","link","set",n["si1"],"down"))
  result={"client":client,"server":server,"router":router,"names":n}; verify_environment(c,result); return c,result
 except Exception: c.cleanup(); raise
def counters(ns,devs,c):
 paths=[f"/sys/class/net/{device}/statistics/{field}" for device in devs for field in COUNTERS]
 try: values=c.inside(ns,"cat",*paths).stdout.splitlines()
 except Exception as error: raise StageError("counter_read") from error
 if len(values)!=len(paths): raise StageError("counter_read")
 try: values=[int(value) for value in values]
 except ValueError as error: raise StageError("counter_read") from error
 return {str(index):dict(zip(COUNTERS,values[index*len(COUNTERS):(index+1)*len(COUNTERS)])) for index in range(len(devs))}
def verify_environment(c,topology):
 checks=((topology["client"],topology["names"]["cr0"]),)+tuple((topology["router"],topology["names"][name]) for name in ("cr1","rb0","rb1"))+((topology["router"],"brq1"),)+tuple((topology["server"],topology["names"][name]) for name in ("si0","si1"))
 for namespace,device in checks:
  link=c.inside(namespace,"ip","-o","link","show","dev",device).stdout
  qdisc=c.inside(namespace,"tc","qdisc","show","dev",device).stdout
  offload=c.inside(namespace,"ethtool","-k",device).stdout
  if not link or "mtu 1500" not in link: raise StageError("environment_verify")
  if not qdisc or "fq_codel" not in qdisc: raise StageError("environment_verify")
  if not offload: raise StageError("environment_verify")
  values={line.split(":",1)[0].strip():line.split(":",1)[1].strip() for line in offload.splitlines() if ":" in line}
  if any(feature not in values or values[feature] not in {"off","off [fixed]"} for feature in ("generic-receive-offload","generic-segmentation-offload","tcp-segmentation-offload")): raise StageError("environment_verify")
BOUNDARY_SKEW_NS=100_000_000
def _cpu_record(before_ns,before,after_ns,after):
 return struct.pack("!QQQQQQ",before_ns,int(before.ru_utime*1e9),int(before.ru_stime*1e9),after_ns,int(after.ru_utime*1e9),int(after.ru_stime*1e9))
def _activation_sampler(c, topology, cut, stop, result, errors):
 delay=max(0,(cut-time.monotonic_ns())/1e9)
 if stop.wait(delay): return
 try: result["activation"]=counters(topology["server"],(topology["names"]["si0"],topology["names"]["si1"]),c); result["activation_timestamp_ns"]=time.monotonic_ns()
 except StageError as error: errors.append(error)
def _recv_exact(s,n):
 b=b""
 while len(b)<n:
  p=s.recv(n-len(b))
  if not p: raise OSError("eof")
  b+=p
 return b
def _queue_frames(incoming,outgoing):
 while len(incoming)>=PAYLOAD_SIZE:
  outgoing.extend(incoming[:PAYLOAD_SIZE]); del incoming[:PAYLOAD_SIZE]
def _fd_write(fd, sequence, stamp=None):
 if fd is not None: os.write(fd,struct.pack("!QQ",sequence,time.monotonic_ns() if stamp is None else stamp))
def _fd_ready(fd):
 if fd is not None: os.write(fd,b"R")
def _read_exact(fd,n):
 value=b""
 while len(value)<n:
  part=os.read(fd,n-len(value))
  if not part: raise StageError("endpoint_ready")
  value+=part
 return value
def _schedule(schedule_fd,gate_fd):
 start,cut,end=struct.unpack("!QQQ",_read_exact(schedule_fd,24)); _read_exact(gate_fd,1)
 if cut-start!=3_000_000_000 or end-cut!=5_000_000_000: raise StageError("timeline")
 return start,cut,end
def _socket():
 s=socket.socket(); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
 s.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,131072); s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,131072)
 if s.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)!=262144 or s.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)!=262144: raise StageError("environment_verify")
 return s
def _deadline_timeout(deadline_ns):
 remaining=deadline_ns-time.monotonic_ns()
 return remaining/1e9 if remaining>0 else None
def endpoint_server(mechanism,ready_fd,schedule_fd,gate_fd,stop,old_dev=None,new_dev=None,cpu_fd=None):
 ports=PORTS[mechanism]; listeners=[]; selector=selectors.DefaultSelector(); before=after=None; before_ns=after_ns=end=None
 def close(conn):
  try: selector.unregister(conn)
  except Exception: pass
  try: conn.close()
  except OSError: pass
 try:
  bind=["0.0.0.0"] if mechanism=="GARP-VIP" else ["10.88.1.2","10.88.1.3"]
  for index,(ip,port) in enumerate(zip(bind,ports)):
   listener=_socket(); listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
   if mechanism=="TCP-reconnect": listener.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,(old_dev,new_dev)[index].encode()+b"\0")
   listener.bind((ip,port)); listener.listen(); listener.setblocking(False); selector.register(listener,selectors.EVENT_READ); listeners.append(listener)
  _fd_ready(ready_fd)
  _,_,end=_schedule(schedule_fd,gate_fd); before_ns=time.monotonic_ns(); before=resource.getrusage(resource.RUSAGE_SELF)
  while not Path(stop).exists() and time.monotonic_ns()<end:
   for key,mask in selector.select(.002):
    conn=key.fileobj
    if conn in listeners:
     try:
      while True:
       accepted,_=conn.accept(); accepted.setblocking(False); selector.register(accepted,selectors.EVENT_READ,bytearray())
     except BlockingIOError: pass
     continue
    incoming=key.data
    try: chunk=conn.recv(4096)
    except (BlockingIOError,InterruptedError): continue
    except OSError: close(conn); continue
    if not chunk: close(conn); continue
    incoming.extend(chunk)
    while len(incoming)>=PAYLOAD_SIZE:
     frame=bytes(incoming[:PAYLOAD_SIZE]); del incoming[:PAYLOAD_SIZE]
     try: conn.sendall(frame)
     except OSError: close(conn); break
 finally:
  if cpu_fd is not None and before is not None:
   after_ns=time.monotonic_ns(); after=resource.getrusage(resource.RUSAGE_SELF)
   os.write(cpu_fd,_cpu_record(before_ns,before,after_ns,after))
  for key in list(selector.get_map().values()): close(key.fileobj)
  selector.close()
def endpoint_client(mechanism,ready_fd,schedule_fd,gate_fd,attempt_fd,sent_fd,received_fd,cpu_fd):
 target="10.88.1.100" if mechanism=="GARP-VIP" else "10.88.1.2"; old,new=PORTS[mechanism]; port=old; sock=None; before=after=None; before_ns=after_ns=end=None
 try:
  sock=_socket(); sock.settimeout(2); sock.connect((target,port)); _fd_ready(ready_fd)
  start,cut,end=_schedule(schedule_fd,gate_fd); before_ns=time.monotonic_ns(); before=resource.getrusage(resource.RUSAGE_SELF)
  sequence=0
  while sequence<800:
   due=start+sequence*RATE_NS; now=time.monotonic_ns()
   if now<due: time.sleep((due-now)/1e9); continue
   if now>=due+RATE_NS:
    sequence+=(now-due)//RATE_NS; continue
   if mechanism=="TCP-reconnect" and now>=cut: target,port="10.88.1.3",new
   if sock is None:
    deadline_ns=due+RATE_NS; timeout=_deadline_timeout(deadline_ns)
    if timeout is None: sequence+=1; continue
    try: sock=_socket(); sock.settimeout(timeout); sock.connect((target,port))
    except OSError: sock=None
   if sock is not None:
    timeout=_deadline_timeout(due+RATE_NS)
    if timeout is None: sequence+=1; continue
    _fd_write(attempt_fd,sequence)
    try:
     sock.settimeout(timeout)
     sock.sendall(payload(sequence))
     timeout=_deadline_timeout(due+RATE_NS)
     if timeout is None: sock.close(); sock=None; sequence+=1; continue
     _fd_write(sent_fd,sequence)
     sock.settimeout(timeout)
     response=_recv_exact(sock,PAYLOAD_SIZE)
     if response != payload(sequence): sock.close(); sock=None
     elif _deadline_timeout(due+RATE_NS) is not None: _fd_write(received_fd,sequence)
    except OSError: sock.close(); sock=None
   sequence+=1
 finally:
  if sock: sock.close()
  if cpu_fd is not None and before is not None:
   while time.monotonic_ns()<end: time.sleep(.0005)
   after_ns=time.monotonic_ns(); after=resource.getrusage(resource.RUSAGE_SELF)
   os.write(cpu_fd,_cpu_record(before_ns,before,after_ns,after))
def metrics(event,t,end):
 scheduled={seq:due for seq,due in event.get("scheduled",())}; attempted=event.get("attempted",()); sent=event.get("sent",()); sent_stamps={seq:stamp for seq,stamp in sent}; received=sorted((item for item in event.get("received",()) if item[1] < end),key=lambda item:item[1])
 if any(seq not in sent_stamps or sent_stamps[seq]>stamp for seq,stamp in received): raise StageError("authenticated_events")
 seen=set(); duplicate=reordered=0; high=-1; streak=[]; readiness=None
 for seq,stamp in received:
  duplicate+=seq in seen
  if seq not in seen: reordered+=seq<high; high=max(high,seq)
  due=scheduled.get(seq); qualifying=due is not None and t<=stamp<end and due<=stamp<due+RATE_NS and seq not in seen
  if not qualifying: streak=[]
  elif streak and seq==streak[-1][0]+1: streak.append((seq,stamp))
  else: streak=[(seq,stamp)]
  if len(streak)==10 and readiness is None: readiness=stamp
  seen.add(seq)
 on_schedule=[(seq,stamp) for seq,stamp in received if seq in scheduled and scheduled[seq]<=stamp<scheduled[seq]+RATE_NS]
 pre=[item for item in on_schedule if item[1]<t]
 failure=not pre or readiness is None
 return {"readiness_ns":readiness,"censored":failure,"failure":failure,"scheduled_payloads":len(scheduled),"attempted_payloads":len(attempted),"sent_payloads":len(sent),"received_payloads":len(received),"lost_payloads":len(set(scheduled)-seen),"duplicate_payloads":duplicate,"reordered_payloads":reordered,"outage_ns":None if failure else readiness-max(stamp for _,stamp in pre)}
def _garp(c,server,device):
 for i in range(3):
  result=c.inside(server,"arping","-U","-c","1","-w","1","-I",device,"10.88.1.100",check=False)
  if result.returncode not in (0,1): raise StageError("garp_announce")
  if i<2: time.sleep(.1)
def _activate_candidate(c,t):
 n=t["names"]; s=t["server"]
 _stage("link_activate",lambda:c.inside(s,"ip","link","set",n["si1"],"up"))
 _stage("route_server_main",lambda:c.inside(s,"ip","route","replace","10.88.0.0/24","via","10.88.1.1","dev",n["si1"],"onlink"))
 _stage("route_candidate_policy",lambda:c.inside(s,"ip","route","get","10.88.0.2","from","10.88.1.3"))
def actions(c,t,mech,arm,cut,control_path=None):
 n=t["names"]; s=t["server"]; activation_start=activation_complete=None
 if arm=="make-before-break":
  while time.monotonic_ns()<cut-2_000_000_000: time.sleep(.001)
  activation_start=time.monotonic_ns(); _control(control_path,"runtime",activation_start_ns=activation_start); _activate_candidate(c,t); activation_complete=time.monotonic_ns(); _control(control_path,"runtime",activation_complete_ns=activation_complete)
 while time.monotonic_ns()<cut: time.sleep(.0005)
 if activation_start is None:
  activation_start=time.monotonic_ns(); _control(control_path,"runtime",activation_start_ns=activation_start)
 if arm=="abrupt-break":
  _activate_candidate(c,t); activation_complete=time.monotonic_ns(); _control(control_path,"runtime",activation_complete_ns=activation_complete)
 if mech=="TCP-reconnect": _stage("link_activate",lambda:c.inside(s,"ip","link","set",n["si0"],"down"))
 elif mech=="GARP-VIP":
  _stage("address_config",lambda:(c.inside(s,"ip","addr","del","10.88.1.100/32","dev",n["si0"]),c.inside(s,"ip","addr","add","10.88.1.100/32","dev",n["si1"])))
  _stage("route_vip_policy",lambda:c.inside(s,"ip","route","replace","10.88.0.0/24","via","10.88.1.1","dev",n["si1"],"onlink","table","103")); _garp(c,s,n["si1"])
 elif arm=="abrupt-break": _stage("link_activate",lambda:c.inside(s,"ip","link","set",n["si0"],"down"))
 return activation_start,activation_complete
def _r8(command,seed,peer,address,peer_address,new_address,bind,extra):
 return [sys.executable,str(ROOT/"reference/r8move.py"),command,"--local-seed-hex",seed.hex(),"--peer-public-key-hex",peer.hex(),"--service-context","1","--server-context-id","1","--address",address,"--peer-address",peer_address,"--new-address",new_address,"--bind",bind,"--allow-isolated-underlay","--binding-budget","1252","--deterministic-scid","1","--deterministic-candidate-hex","01"*16,"--deterministic-secret-hex","02"*32]+extra
def _events(fd):
 os.lseek(fd,0,os.SEEK_SET); raw=os.read(fd,1<<20)
 if len(raw)%16: raise StageError("authenticated_events")
 return [(seq,stamp) for seq,stamp in struct.iter_unpack("!QQ",raw)]
def partial_metrics(records,cut,end):
 return metrics({name:_events(fd) for name,fd in records.items()},cut,end)
def _wait(processes,stop=None):
 order=list(reversed(processes)) if stop else processes
 for process in order:
  try: process.wait(timeout=15)
  except subprocess.TimeoutExpired:
   try: process.kill()
   except ProcessLookupError: pass
   process.wait(timeout=3); return "endpoint_runtime"
  if stop and process is processes[-1]: Path(stop).touch()
 return "endpoint_runtime" if any(process.returncode for process in processes) else None
def _reap_namespace(c,namespace):
 result=c.call("ip","netns","pids",namespace,check=False)
 if result.returncode:
  listed={line.split()[0] for line in c.call("ip","netns","list",check=False).stdout.splitlines() if line.split()}
  return None if namespace not in listed else "cleanup_reap"
 pids=result.stdout.split()
 if any(not value.isdigit() for value in pids): return "cleanup_reap"
 for pid in pids:
  try: os.kill(int(pid),signal.SIGTERM)
  except ProcessLookupError: pass
 for pid in pids:
  try: os.kill(int(pid),signal.SIGKILL)
  except ProcessLookupError: pass
 deadline=time.monotonic()+1
 while True:
  verify=c.call("ip","netns","pids",namespace,check=False)
  if verify.returncode==0 and not verify.stdout.split(): return None
  listed={line.split()[0] for line in c.call("ip","netns","list",check=False).stdout.splitlines() if line.split()}
  if verify.returncode and namespace not in listed: return None
  if verify.returncode or time.monotonic()>=deadline or any(not value.isdigit() for value in verify.stdout.split()): return "cleanup_reap"
  time.sleep(.01)
def _cleanup(c,children,t):
 failures=[]
 for process in children:
  if getattr(process,"poll",lambda:0)() is None:
   try: process.terminate()
   except Exception: failures.append("cleanup_reap")
  try: process.wait(timeout=1)
  except Exception:
   try: process.kill(); process.wait(timeout=1)
   except Exception: failures.append("cleanup_reap")
 names=tuple(c.owned)
 if len(names)!=3: failures.append("cleanup_residual")
 for namespace in reversed(names):
  try:
   reap=_reap_namespace(c,namespace)
   if reap: failures.append(reap); continue
   result=c.call("ip","netns","del",namespace,check=False)
   if result.returncode: failures.append("cleanup_delete")
  except Exception: failures.append("cleanup_delete")
 c.owned.clear()
 try:
  remaining={line.split()[0] for line in c.call("ip","netns","list",check=False).stdout.splitlines() if line.split()}
  if set(names)&remaining: failures.append("cleanup_residual")
 except Exception: failures.append("cleanup_residual")
 return failures[0] if failures else None
def observed_topology(c,t):
 namespaces=(t["client"],t["server"],t["router"])
 listed={line.split()[0] for line in c.call("ip","netns","list",check=False).stdout.splitlines() if line.split()}
 if listed != set(namespaces): raise StageError("environment_verify")
 interfaces=non_loopback=veth=0
 for namespace in namespaces:
  links=c.inside(namespace,"ip","-o","link","show").stdout.splitlines()
  detailed=c.inside(namespace,"ip","-d","-o","link","show","type","veth").stdout.splitlines()
  if not links: raise StageError("environment_verify")
  interfaces+=len(links); non_loopback+=sum(": lo:" not in line for line in links); veth+=len(detailed)
 if veth%2: raise StageError("environment_verify")
 return {"namespace_count":len(namespaces),"interface_count":interfaces,"non_loopback_interface_count":non_loopback,"veth_pair_count":veth//2}
def worker(mechanism,arm,commands=None,control_path=None,evidence_dir=None,suffix=None):
 c=commands or Commands(); t=None; children=[]; records={}; pre_cpu=None; result=None; runtime=False; start=cut=end=None; pre_interfaces={}; sampler=None; sampler_stop=threading.Event(); sampler_records={}; sampler_errors=[]; topology_observation={}; environment_complete=False; topology_complete=False; fds=[]; child_reports=(); child_cpu=(0,0,0,0,0,0); parent_cpu_pre_ns=parent_cpu_post_ns=None; pre_counter_ns=post_counter_ns=None; old_term=signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(SystemExit()))
 if evidence_dir is not None:
  evidence=Path(evidence_dir)
  if not evidence.is_dir() or (evidence.stat().st_mode & 0o777) != 0o700: raise StageError("endpoint_setup")
 _control(control_path,"setup")
 try:
  c,t=topology(c,suffix); environment_complete=True; topology_observation=observed_topology(c,t); topology_complete=True
  with tempfile.TemporaryDirectory() as directory:
   directory=Path(directory); evidence=Path(evidence_dir) if evidence_dir is not None else directory; ready_r,ready_w=os.pipe(); server_schedule_r,server_schedule_w=os.pipe(); client_schedule_r,client_schedule_w=os.pipe(); server_gate_r,server_gate_w=os.pipe(); client_gate_r,client_gate_w=os.pipe(); cpu_r,cpu_w=os.pipe(); records={name:os.open(str(evidence/(name+".bin")),os.O_CREAT|os.O_RDWR|os.O_APPEND,0o600) for name in ("scheduled","attempted","sent","received")}; fds=[ready_r,ready_w,server_schedule_r,server_schedule_w,client_schedule_r,client_schedule_w,server_gate_r,server_gate_w,client_gate_r,client_gate_w,cpu_r,cpu_w,*records.values()]
   if mechanism=="R8":
    stable=hashlib.sha256(b"q1-r8-stable").digest(); moving=hashlib.sha256(b"q1-r8-moving").digest()
    shared=["--stream-rate","100","--timeout","15","--ready-fd",str(ready_w)]
    cutover_r,cutover_w=os.pipe(); fds.extend((cutover_r,cutover_w))
    server=_stage("endpoint_setup",lambda:c.spawn(t["client"],*_r8("serve",stable,Identity.from_seed(moving).public,"::2","::1","::3","10.88.0.2:53104",shared+["--schedule-fd",str(server_schedule_r),"--gate-fd",str(server_gate_r),"--cpu-fd",str(cpu_w),"--max-sessions","1","--expected-post-move","1"]),pass_fds=(ready_w,server_schedule_r,server_gate_r,cpu_w))); children.append(server)
    client_args=shared+["--schedule-fd",str(client_schedule_r),"--gate-fd",str(client_gate_r),"--cutover-gate-fd",str(cutover_r),"--events-fd",str(records["received"]),"--attempt-fd",str(records["attempted"]),"--sent-fd",str(records["sent"]),"--cpu-fd",str(cpu_w),"--peer","10.88.0.2:53104","--candidate-bind","10.88.1.3:0","--mode","abrupt" if arm=="abrupt-break" else "mbb"]
    client=_stage("endpoint_setup",lambda:c.spawn(t["server"],*_r8("connect",moving,Identity.from_seed(stable).public,"::1","::2","::3","10.88.1.2:0",client_args),pass_fds=(ready_w,client_schedule_r,client_gate_r,cutover_r,records["received"],records["attempted"],records["sent"],cpu_w))); children.append(client)
   else:
    stop=str(directory/"stop")
    server=_stage("endpoint_setup",lambda:c.spawn(t["server"],sys.executable,str(Path(__file__).resolve()),"endpoint-server","--mechanism",mechanism,"--ready-fd",str(ready_w),"--schedule-fd",str(server_schedule_r),"--gate-fd",str(server_gate_r),"--stop",stop,"--old-dev",t["names"]["si0"],"--new-dev",t["names"]["si1"],"--cpu-fd",str(cpu_w),pass_fds=(ready_w,server_schedule_r,server_gate_r,cpu_w))); children.append(server)
    client=_stage("endpoint_setup",lambda:c.spawn(t["client"],sys.executable,str(Path(__file__).resolve()),"endpoint-client","--mechanism",mechanism,"--ready-fd",str(ready_w),"--schedule-fd",str(client_schedule_r),"--gate-fd",str(client_gate_r),"--attempt-fd",str(records["attempted"]),"--sent-fd",str(records["sent"]),"--received-fd",str(records["received"]),"--cpu-fd",str(cpu_w),pass_fds=(ready_w,client_schedule_r,client_gate_r,records["attempted"],records["sent"],records["received"],cpu_w))); children.append(client)
   os.close(ready_w); fds[fds.index(ready_w)]=None; _read_exact(ready_r,2)
   pre_interfaces=counters(t["server"],(t["names"]["si0"],t["names"]["si1"]),c); pre_counter_ns=time.monotonic_ns(); start=pre_counter_ns+BOUNDARY_SKEW_NS; pre_cpu=resource.getrusage(resource.RUSAGE_SELF); parent_cpu_pre_ns=time.monotonic_ns()
   if parent_cpu_pre_ns>=start: raise StageError("timeline")
   cut=start+3_000_000_000; end=cut+5_000_000_000
   for sequence in range(800): _fd_write(records["scheduled"],sequence,start+sequence*RATE_NS)
   activation_ns=cut-2_000_000_000 if arm=="make-before-break" else cut; os.write(server_schedule_w,struct.pack("!QQQ",start,cut,end)); os.write(client_schedule_w,struct.pack("!QQQ",start,cut,end)); os.write(server_gate_w,b"G"); os.write(client_gate_w,b"G"); runtime=True; _control(control_path,"runtime",t_minus_3_ns=start,activation_ns=activation_ns,cutover_ns=cut,observation_end_ns=end)
   sampler=threading.Thread(target=_activation_sampler,args=(c,t,cut,sampler_stop,sampler_records,sampler_errors),daemon=True); sampler.start()
   activation_start,activation_complete=actions(c,t,mechanism,arm,cut,control_path)
   if mechanism=="R8": os.write(cutover_w,b"G")
   category=_wait(children,stop if mechanism!="R8" else None); sampler_stop.set(); sampler.join(timeout=max(0,(end-time.monotonic_ns())/1e9)); post_cpu=resource.getrusage(resource.RUSAGE_SELF); parent_cpu_post_ns=time.monotonic_ns()
   if sampler.is_alive() or sampler_errors: raise StageError("counter_read")
   child_reports=tuple(struct.iter_unpack("!QQQQQQ",_read_exact(cpu_r,96))) if category is None else ()
   child_cpu=tuple(sum(report[index] for report in child_reports) for index in range(6)) if category is None else (0,0,0,0,0,0)
   event={name:_events(fd) for name,fd in records.items()}
   post_interfaces=counters(t["server"],(t["names"]["si0"],t["names"]["si1"]),c); post_counter_ns=time.monotonic_ns()
   scheduled_activation=cut-2_000_000_000 if arm=="make-before-break" else cut
   result=metrics(event,cut,end); timestamps={"pre":pre_counter_ns,"activation":sampler_records.get("activation_timestamp_ns"),"post":post_counter_ns}; complete=pre_counter_ns<=start<=pre_counter_ns+BOUNDARY_SKEW_NS and isinstance(timestamps["activation"],int) and abs(timestamps["activation"]-cut)<=BOUNDARY_SKEW_NS and end<=post_counter_ns<=end+BOUNDARY_SKEW_NS; result.update({"setup_status":"complete","error_category":category,"t_minus_3_ns":start,"activation_ns":scheduled_activation,"activation_start_ns":activation_start,"activation_complete_ns":activation_complete,"cutover_ns":cut,"observation_end_ns":end,"interface_counter_by_ordinal":{"pre":pre_interfaces,"activation":sampler_records.get("activation",{}),"post":post_interfaces},"interface_counter_timestamp_ns_by_ordinal":timestamps,"counter_complete":complete})
   if category: result["failure"]=result["censored"]=True
 except StageError as error:
  result={"setup_status":"complete" if runtime else "failed","error_category":error.category,"failure":True,"censored":True,"scheduled_payloads":None,"attempted_payloads":None,"sent_payloads":None,"received_payloads":None,"lost_payloads":None,"duplicate_payloads":None,"reordered_payloads":None,"outage_ns":None,"interface_counter_by_ordinal":{},"interface_counter_timestamp_ns_by_ordinal":{},"counter_complete":False}
 except SystemExit:
  result={"setup_status":"complete" if runtime else "failed","error_category":"worker_timeout","failure":True,"censored":True,"scheduled_payloads":None,"attempted_payloads":None,"sent_payloads":None,"received_payloads":None,"lost_payloads":None,"duplicate_payloads":None,"reordered_payloads":None,"outage_ns":None,"interface_counter_by_ordinal":{},"interface_counter_timestamp_ns_by_ordinal":{},"counter_complete":False}
 except Exception:
  result={"setup_status":"complete" if runtime else "failed","error_category":"worker_internal","failure":True,"censored":True,"scheduled_payloads":None,"attempted_payloads":None,"sent_payloads":None,"received_payloads":None,"lost_payloads":None,"duplicate_payloads":None,"reordered_payloads":None,"outage_ns":None,"interface_counter_by_ordinal":{},"interface_counter_timestamp_ns_by_ordinal":{},"counter_complete":False}
 finally:
  cleanup=_cleanup(c,children,t) if t else None
  sampler_stop.set()
  if sampler is not None: sampler.join(timeout=1)
  if runtime and cut is not None and end is not None:
   try: partial=partial_metrics(records,cut,end)
   except StageError: partial={"scheduled_payloads":None,"attempted_payloads":None,"sent_payloads":None,"received_payloads":None,"lost_payloads":None,"duplicate_payloads":None,"reordered_payloads":None,"outage_ns":None,"readiness_ns":None,"failure":True,"censored":True}
   category=result.get("error_category") if result else "endpoint_runtime"
   if cleanup: category=cleanup
   partial.update({"setup_status":"complete","error_category":category,"t_minus_3_ns":start,"activation_ns":cut-2_000_000_000 if arm=="make-before-break" else cut,"cutover_ns":cut,"observation_end_ns":end,"activation_start_ns":result.get("activation_start_ns") if result else None,"activation_complete_ns":result.get("activation_complete_ns") if result else None,"interface_counter_by_ordinal":{"pre":pre_interfaces,"activation":result.get("interface_counter_by_ordinal",{}).get("activation",sampler_records.get("activation",{})) if result else sampler_records.get("activation",{}),"post":result.get("interface_counter_by_ordinal",{}).get("post",{}) if result else {}},"interface_counter_timestamp_ns_by_ordinal":result.get("interface_counter_timestamp_ns_by_ordinal",{"pre":pre_counter_ns,"activation":sampler_records.get("activation_timestamp_ns"),"post":post_counter_ns}) if result else {"pre":pre_counter_ns,"activation":sampler_records.get("activation_timestamp_ns"),"post":post_counter_ns},"counter_complete":result.get("counter_complete",False) if result else False})
   if category: partial["failure"]=partial["censored"]=True
   result=partial
  elif cleanup: result["error_category"]=cleanup
  _control(control_path,"terminal",t_minus_3_ns=result.get("t_minus_3_ns"),activation_ns=result.get("activation_ns"),activation_start_ns=result.get("activation_start_ns"),activation_complete_ns=result.get("activation_complete_ns"),cutover_ns=result.get("cutover_ns"),observation_end_ns=result.get("observation_end_ns"),cleanup_complete=not bool(cleanup))
  snapshot=post_cpu if "post_cpu" in locals() else resource.getrusage(resource.RUSAGE_SELF)
  reports_valid=len(child_reports)==2 and all(report[0]<=start and report[3]>=end and report[1]<=report[4] and report[2]<=report[5] for report in child_reports)
  if reports_valid and parent_cpu_pre_ns<=start and parent_cpu_post_ns>=end:
   result["process_user_cpu_ns"]=int((snapshot.ru_utime-pre_cpu.ru_utime)*1e9+child_cpu[4]-child_cpu[1]); result["process_system_cpu_ns"]=int((snapshot.ru_stime-pre_cpu.ru_stime)*1e9+child_cpu[5]-child_cpu[2]); result["process_cpu_timestamp_ns_by_ordinal"]={"endpoint_0":{"pre":child_reports[0][0],"post":child_reports[0][3]},"endpoint_1":{"pre":child_reports[1][0],"post":child_reports[1][3]},"parent":{"pre":parent_cpu_pre_ns,"post":parent_cpu_post_ns}}; result["cpu_complete"]=True
  else: result["process_user_cpu_ns"]=result["process_system_cpu_ns"]=None; result["process_cpu_timestamp_ns_by_ordinal"]={}; result["cpu_complete"]=False
  result["evidence_complete"]=bool(records) and all((lambda fd: (os.lseek(fd,0,os.SEEK_END) % 16) == 0)(fd) for fd in records.values()); result["cleanup_complete"]=not bool(cleanup); result["environment_complete"]=environment_complete; result["topology_complete"]=topology_complete; result.update(topology_observation); result["command_sha256"]=hashlib.sha256(json.dumps(c.transcript,separators=(",",":")).encode()).hexdigest(); [os.close(fd) for fd in fds if fd is not None]; signal.signal(signal.SIGTERM,old_term)
 return result
def main(argv=None):
 p=argparse.ArgumentParser(); p.add_argument("command"); p.add_argument("--mechanism",choices=PORTS); p.add_argument("--arm",choices=("abrupt-break","make-before-break")); p.add_argument("--control-path"); p.add_argument("--evidence-dir"); p.add_argument("--suffix"); p.add_argument("--ready-fd",type=int); p.add_argument("--stop"); p.add_argument("--schedule-fd",type=int); p.add_argument("--gate-fd",type=int); p.add_argument("--attempt-fd",type=int); p.add_argument("--sent-fd",type=int); p.add_argument("--received-fd",type=int); p.add_argument("--cpu-fd",type=int); p.add_argument("--old-dev"); p.add_argument("--new-dev"); a=p.parse_args(argv)
 if a.command=="worker": print(json.dumps(worker(a.mechanism,a.arm,control_path=a.control_path,evidence_dir=a.evidence_dir,suffix=a.suffix),sort_keys=True))
 elif a.command=="endpoint-server": endpoint_server(a.mechanism,a.ready_fd,a.schedule_fd,a.gate_fd,a.stop,a.old_dev,a.new_dev,a.cpu_fd)
 elif a.command=="endpoint-client": endpoint_client(a.mechanism,a.ready_fd,a.schedule_fd,a.gate_fd,a.attempt_fd,a.sent_fd,a.received_fd,a.cpu_fd)
 else: p.error("unknown endpoint command")
if __name__=="__main__": main()
