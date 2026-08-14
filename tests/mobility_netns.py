#!/usr/bin/env python3
"""Privileged Q1 network-namespace worker and its real TCP endpoint helpers."""
import argparse, hashlib, json, os, resource, socket, struct, subprocess, sys, tempfile, threading, time, uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / "reference"))
from r8session import Identity
PAYLOAD_SIZE=64; RATE_NS=10_000_000; PORTS={"TCP-reconnect":(53101,53102),"GARP-VIP":(53103,53103),"R8":(53104,53104)}
COUNTERS=("rx_bytes","tx_bytes","rx_packets","tx_packets","rx_dropped","tx_dropped","rx_errors","tx_errors")
class Commands:
 def __init__(self,run=subprocess.run,popen=subprocess.Popen): self.run,self.popen,self.owned,self.transcript=run,popen,[],[]
 def call(self,*a,check=True): self.transcript.append(tuple(a)); return self.run(a,check=check,text=True,capture_output=True)
 def inside(self,ns,*a): return self.call("ip","netns","exec",ns,*a)
 def netns(self,n): self.call("ip","netns","add",n); self.owned.append(n)
 def spawn(self,ns,*a,pass_fds=()): self.transcript.append(("ip","netns","exec",ns)+a); return self.popen(("ip","netns","exec",ns)+a,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=pass_fds)
 def cleanup(self):
  for n in reversed(self.owned):
   try: self.call("ip","netns","del",n,check=False)
   except Exception: pass
def payload(n): return struct.pack("!Q",n)+b"\0"*56
def _n(x,s): return x+"-"+s
def topology(commands=None,suffix=None):
 c=commands or Commands(); s=suffix or uuid.uuid4().hex[:10]; client,server,router=(_n(x,s) for x in ("r8q1-client","r8q1-server","r8q1-router")); n={"cr0":"qc"+s[:8],"cr1":"qr"+s[:8],"si0":"qso"+s[:7],"rb0":"qbo"+s[:7],"si1":"qsn"+s[:7],"rb1":"qbn"+s[:7]}
 try:
  for x in (client,server,router): c.netns(x)
  c.inside(router,"sysctl","-w","net.ipv4.ip_forward=1")
  for a,b in ((n["cr0"],n["cr1"]),(n["si0"],n["rb0"]),(n["si1"],n["rb1"])): c.call("ip","link","add",a,"type","veth","peer","name",b)
  c.call("ip","link","set",n["cr0"],"netns",client); c.call("ip","link","set",n["cr1"],"netns",router)
  for x in ("rb0","rb1"): c.call("ip","link","set",n[x],"netns",router)
  for x in ("si0","si1"): c.call("ip","link","set",n[x],"netns",server)
  c.inside(router,"ip","link","add","brq1","type","bridge")
  for x in (n["rb0"],n["rb1"]): c.inside(router,"ip","link","set",x,"master","brq1")
  c.inside(client,"ip","addr","add","10.88.0.2/24","dev",n["cr0"]); c.inside(router,"ip","addr","add","10.88.0.1/24","dev",n["cr1"]); c.inside(router,"ip","addr","add","10.88.1.1/24","dev","brq1")
  c.inside(server,"ip","addr","add","10.88.1.2/24","dev",n["si0"]); c.inside(server,"ip","addr","add","10.88.1.3/24","dev",n["si1"]); c.inside(server,"ip","addr","add","10.88.1.100/32","dev",n["si0"])
  c.inside(client,"ip","route","add","default","via","10.88.0.1"); c.inside(server,"ip","route","add","10.88.0.0/24","via","10.88.1.1")
  c.inside(server,"ip","route","add","10.88.0.0/24","dev",n["si0"],"table","101"); c.inside(server,"ip","rule","add","from","10.88.1.2/32","table","101")
  c.inside(server,"ip","route","add","10.88.0.0/24","dev",n["si1"],"table","102"); c.inside(server,"ip","rule","add","from","10.88.1.3/32","table","102")
  c.inside(server,"ip","route","add","10.88.0.0/24","dev",n["si0"],"table","103"); c.inside(server,"ip","rule","add","from","10.88.1.100/32","table","103")
  for ns,devs in ((client,(n["cr0"],)),(router,(n["cr1"],n["rb0"],n["rb1"],"brq1")),(server,(n["si0"],))):
   c.inside(ns,"ip","link","set","lo","up")
   for d in devs: c.inside(ns,"ip","link","set",d,"up")
  # Candidate server interface is intentionally left administratively down until arm-defined activation.
  return c,{"client":client,"server":server,"router":router,"names":n}
 except Exception: c.cleanup(); raise
def counters(ns,devs,c):
 out={}
 for i,d in enumerate(devs):
  out[str(i)]={}
  for f in COUNTERS:
   try: out[str(i)][f]=int(c.inside(ns,"cat",f"/sys/class/net/{d}/statistics/{f}").stdout.strip())
   except Exception as error: raise RuntimeError("counter_failure") from error
 return out
def _recv_exact(s,n):
 b=b""
 while len(b)<n:
  p=s.recv(n-len(b))
  if not p: raise OSError("eof")
  b+=p
 return b
def endpoint_server(mechanism,ready,stop):
 ports=PORTS[mechanism]; listeners=[]
 try:
  bind=["0.0.0.0"] if mechanism=="GARP-VIP" else ["10.88.1.2","10.88.1.3"]
  for ip,port in zip(bind,ports):
   s=socket.socket(); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((ip,port)); s.listen(); s.settimeout(.05); listeners.append(s)
  Path(ready).write_text("ready")
  conns=[]
  while not Path(stop).exists():
   for l in listeners:
    try: conns.append(l.accept()[0])
    except socket.timeout: pass
   for s in conns[:]:
    s.settimeout(.001)
    try: s.sendall(_recv_exact(s,PAYLOAD_SIZE))
    except socket.timeout: pass
    except OSError: conns.remove(s); s.close()
 finally:
  for s in listeners: s.close()
def endpoint_client(mechanism,start,cut,end,events):
 target="10.88.1.100" if mechanism=="GARP-VIP" else "10.88.1.2"; old,new=PORTS[mechanism]; port=old; sock=None; sent=[]; received=[]; seq=0; scheduled=list(range(800))
 if end-start != len(scheduled)*RATE_NS: raise RuntimeError("invalid trial timeline")
 while time.monotonic_ns()<start: time.sleep(min(.001,(start-time.monotonic_ns())/1e9))
 while True:
  due=start+seq*RATE_NS
  if due>=end: break
  now=time.monotonic_ns()
  if now<due: time.sleep((due-now)/1e9); continue
  if now>=due+RATE_NS:
   seq+=(now-due)//RATE_NS; continue
  if mechanism=="TCP-reconnect" and now>=cut: target,port="10.88.1.3",new
  if sock is None:
   try:
    sock=socket.socket(); sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1); sock.settimeout(.005); sock.connect((target,port))
   except OSError:
    if sock: sock.close()
    sock=None
  if sock:
   try: sock.sendall(payload(seq)); sent.append(seq); got=struct.unpack("!Q",_recv_exact(sock,PAYLOAD_SIZE)[:8])[0]; received.append((time.monotonic_ns(),got))
   except OSError: sock.close(); sock=None
  seq+=1
 if sock: sock.close()
 Path(events).write_text(json.dumps({"scheduled":scheduled,"sent":sent,"received":received}))
def metrics(event,t,end):
 scheduled,event_received=event["scheduled"],event["received"]; post=[x for x in event_received if x[0]>=t]; seen=set(); dup=reorder=0; high=-1
 for _,seq in event_received:
  if seq in seen: dup+=1
  else: reorder+=seq<high; high=max(high,seq); seen.add(seq)
 ready=None
 for i in range(len(post)-9):
  if all(post[j+1][1]==post[j][1]+1 for j in range(i,i+9)): ready=post[i+9][0]; break
 pre=[x for x in event_received if x[0]<t]; failed=ready is None or not pre
 return {"readiness_ns":ready,"censored":failed,"failure":failed,"sent_payloads":len(scheduled),"received_payloads":len(event_received),"lost_payloads":len(set(scheduled)-seen),"duplicate_payloads":dup,"reordered_payloads":reorder,"outage_ns":ready-pre[-1][0] if ready and pre else None}
def actions(c,t,mech,arm,cut):
 n=t["names"]; s=t["server"]
 if arm=="make-before-break":
  while time.monotonic_ns()<cut-2_000_000_000: time.sleep(.001)
  c.inside(s,"ip","link","set",n["si1"],"up")
 while time.monotonic_ns()<cut: time.sleep(.0005)
 if arm=="abrupt-break": c.inside(s,"ip","link","set",n["si1"],"up")
 if mech=="TCP-reconnect": c.inside(s,"ip","link","set",n["si0"],"down")
 elif mech=="GARP-VIP":
  c.inside(s,"ip","addr","del","10.88.1.100/32","dev",n["si0"]); c.inside(s,"ip","addr","add","10.88.1.100/32","dev",n["si1"])
  c.inside(s,"ip","route","replace","10.88.0.0/24","dev",n["si1"],"table","103")
  for _ in range(3): c.inside(s,"arping","-U","-I",n["si1"],"10.88.1.100"); time.sleep(.1)
 else:
  if arm=="abrupt-break": c.inside(s,"ip","link","set",n["si0"],"down")
def _r8(command,seed,peer,address,peer_address,new_address,bind,extra):
 return [sys.executable,str(ROOT/"reference/r8move.py"),command,"--local-seed-hex",seed.hex(),"--peer-public-key-hex",peer.hex(),"--service-context","1","--server-context-id","1","--address",address,"--peer-address",peer_address,"--new-address",new_address,"--bind",bind,"--allow-isolated-underlay","--binding-budget","1252","--timeout","12","--deterministic-scid","1","--deterministic-candidate-hex","01"*16,"--deterministic-secret-hex","02"*32]+extra
def _r8events(fd):
 os.lseek(fd,0,os.SEEK_SET); raw=os.read(fd,1<<20)
 if len(raw)%16: raise RuntimeError("bad authenticated event")
 return {"scheduled":list(range(800)),"sent":list(range(800)),"received":[(stamp,seq) for seq,stamp in struct.iter_unpack("!QQ",raw)]}
def worker(mechanism,arm,commands=None):
 c=commands or Commands(); t=None; children=[]; event=None; start=cut=end=activation=None; cpu=resource.getrusage(resource.RUSAGE_SELF); child_cpu=resource.getrusage(resource.RUSAGE_CHILDREN)
 try:
  c,t=topology(c)
  with tempfile.TemporaryDirectory() as d:
   start=time.monotonic_ns()+500_000_000; cut=start+3_000_000_000; end=cut+5_000_000_000; activation=cut-2_000_000_000 if arm=="make-before-break" else cut; pre=counters(t["server"],(t["names"]["si0"],t["names"]["si1"]),c)
   if mechanism=="R8":
    stable=hashlib.sha256(b"q1-r8-stable").digest(); moving=hashlib.sha256(b"q1-r8-moving").digest(); event=os.open(str(Path(d)/"events.bin"),os.O_CREAT|os.O_RDWR,0o600)
    common=["--stream-rate","100","--stream-start-ns",str(start),"--stream-cutover-ns",str(cut),"--stream-end-ns",str(end)]
    server=c.spawn(t["client"],*_r8("serve",stable,Identity.from_seed(moving).public,"::2","::1","::3","10.88.0.2:53104",common+["--max-sessions","1","--expected-post-move","1"]),pass_fds=(event,)); children.append(server)
    client=c.spawn(t["server"],*_r8("connect",moving,Identity.from_seed(stable).public,"::1","::2","::3","10.88.1.2:0",common+["--peer","10.88.0.2:53104","--candidate-bind","10.88.1.3:0","--mode","abrupt" if arm=="abrupt-break" else "mbb","--events-fd",str(event)]),pass_fds=(event,)); children.append(client)
    actions(c,t,mechanism,arm,cut); client.wait(timeout=15); server.wait(timeout=15); event_data=_r8events(event)
   else:
    ready,stop,events=(str(Path(d)/x) for x in ("ready","stop","events")); server=c.spawn(t["server"],sys.executable,str(Path(__file__).resolve()),"endpoint-server","--mechanism",mechanism,"--ready",ready,"--stop",stop); children.append(server)
    deadline=time.monotonic()+2
    while not Path(ready).exists() and time.monotonic()<deadline: time.sleep(.01)
    if not Path(ready).exists(): raise RuntimeError("endpoint_setup")
    client=c.spawn(t["client"],sys.executable,str(Path(__file__).resolve()),"endpoint-client","--mechanism",mechanism,"--start",str(start),"--cut",str(cut),"--end",str(end),"--events",events); children.append(client)
    actions(c,t,mechanism,arm,cut); client.wait(timeout=15); Path(stop).touch(); server.wait(timeout=3); event_data=json.loads(Path(events).read_text())
   if len(event_data["scheduled"]) != 800 or event_data["scheduled"] != list(range(800)) or any(p.returncode for p in children): raise RuntimeError("endpoint_failure")
   result=metrics(event_data,cut,end)
   if not event_data["received"]: raise RuntimeError("no_live_delivery")
   result.update({"setup_status":"complete","t_minus_3_ns":start,"activation_ns":activation,"cutover_ns":cut,"observation_end_ns":end,"interface_counter_by_ordinal":{"pre":pre,"post":counters(t["server"],(t["names"]["si0"],t["names"]["si1"]),c)}})
 except Exception: result={"setup_status":"failed","failure":True,"censored":True,"t_minus_3_ns":start,"activation_ns":activation,"cutover_ns":cut,"observation_end_ns":end,"sent_payloads":0,"received_payloads":0,"lost_payloads":800,"duplicate_payloads":0,"reordered_payloads":0,"outage_ns":None,"interface_counter_by_ordinal":{}}
 finally:
  for p in children:
   if getattr(p,"poll",lambda: 0)() is None: p.kill()
   try: p.wait(timeout=1)
   except Exception: pass
  if event is not None:
   try: os.close(event)
   except OSError: pass
  c.cleanup()
 after=resource.getrusage(resource.RUSAGE_SELF); child_after=resource.getrusage(resource.RUSAGE_CHILDREN); result["process_user_cpu_ns"]=int(((after.ru_utime-cpu.ru_utime)+(child_after.ru_utime-child_cpu.ru_utime))*1e9); result["process_system_cpu_ns"]=int(((after.ru_stime-cpu.ru_stime)+(child_after.ru_stime-child_cpu.ru_stime))*1e9); result["command_sha256"]=hashlib.sha256(json.dumps(c.transcript,separators=(",",":")).encode()).hexdigest(); return result
def main(argv=None):
 p=argparse.ArgumentParser(); p.add_argument("command"); p.add_argument("--mechanism",choices=PORTS); p.add_argument("--arm",choices=("abrupt-break","make-before-break")); p.add_argument("--ready"); p.add_argument("--stop"); p.add_argument("--start",type=int); p.add_argument("--cut",type=int); p.add_argument("--end",type=int); p.add_argument("--events"); a=p.parse_args(argv)
 if a.command=="worker": print(json.dumps(worker(a.mechanism,a.arm),sort_keys=True))
 elif a.command=="endpoint-server": endpoint_server(a.mechanism,a.ready,a.stop)
 elif a.command=="endpoint-client": endpoint_client(a.mechanism,a.start,a.cut,a.end,a.events)
 else: p.error("unknown endpoint command")
if __name__=="__main__": main()
