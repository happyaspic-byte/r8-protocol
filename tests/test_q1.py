import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod
q1=load(ROOT/"bench/q1.py","q1")
net=load(ROOT/"tests/mobility_netns.py","mobility_netns")
class Q1Tests(unittest.TestCase):
 def test_schedule(self):
  rows=q1.schedule(); self.assertEqual(len(rows),1320); self.assertEqual([sum(x["block_id"]==b for x in rows) for b in range(66)],[20]*66)
  for pair in q1.PAIR_ORDER:
   selected=[x for x in rows if (x["mechanism"],x["arm"])==pair]; self.assertEqual((len(selected),sum(x["exclusion_reason"]=="warmup" for x in selected)),(220,20))
  self.assertEqual(rows,q1.schedule())
 def test_smoke(self): self.assertTrue(all(x["exclusion_reason"]=="smoke_non_result" for x in q1.schedule(True)))
 def test_v2_randomization_seeds_are_frozen(self):
  self.assertEqual((q1.ORDER_SEED,q1.BOOTSTRAP_SEED),("r8-q1-block-order-v2","r8-q1-block-bootstrap-v2"))
  self.assertIn("worker_internal",q1.ERROR_CATEGORIES)
 def test_preflight_uid_refusal(self):
  old=q1.os.geteuid; q1.os.geteuid=lambda:1000
  try:
   with self.assertRaisesRegex(RuntimeError,"uid 0"): q1.preflight()
  finally: q1.os.geteuid=old
 def test_payload_and_live_metrics(self):
  self.assertEqual(len(net.payload(7)),64)
  data={"scheduled":list(range(800)),"sent":[1,2,3,4],"received":[(1,1),(2,3),(3,2),(4,3)]+[(5+i,4+i) for i in range(9)]}
  got=net.metrics(data,4,20); self.assertEqual(got["duplicate_payloads"],1); self.assertEqual(got["reordered_payloads"],1); self.assertFalse(got["censored"]); self.assertEqual((got["sent_payloads"],got["lost_payloads"]),(800,788))
 def test_no_pre_delivery_is_censored_failure(self):
  data={"scheduled":list(range(800)),"sent":[],"received":[(10+i,i) for i in range(10)]}
  got=net.metrics(data,10,20)
  self.assertTrue(got["failure"]); self.assertTrue(got["censored"]); self.assertIsNone(got["outage_ns"])
 def test_setup_and_counter_failures_are_retained_and_cleaned(self):
  calls=[]
  attempts=[0]
  def failing(args,**kw):
   calls.append(tuple(args)); attempts[0]+=1
   if attempts[0] > 3: raise subprocess.CalledProcessError(1,args)
   return subprocess.CompletedProcess(args,0,"","")
  result=net.worker("R8","abrupt-break",net.Commands(run=failing))
  self.assertEqual(result["setup_status"],"failed"); self.assertEqual(result["error_category"],"forwarding_config"); self.assertEqual(result["lost_payloads"],800); self.assertIn("command_sha256",result)
  self.assertTrue(any(a[:3]==("ip","netns","add") for a in calls))
  self.assertTrue(any(a[:3]==("ip","netns","del") for a in calls))
  class Bad:
   def inside(self,*args): return subprocess.CompletedProcess(args,0,"not-a-number","")
  with self.assertRaises(RuntimeError): net.counters("server",("dev",),Bad())
 def test_unexpected_worker_error_maps_to_worker_internal(self):
  old=net.topology
  net.topology=lambda commands=None: (_ for _ in ()).throw(ValueError())
  try:
   result=net.worker("R8","abrupt-break")
  finally: net.topology=old
  self.assertEqual(result["error_category"],"worker_internal")
 def test_topology_ownership_routes_and_candidate_down(self):
  calls=[]
  def run(args,**kw): calls.append(tuple(args)); return subprocess.CompletedProcess(args,0,"0\n","")
  c,t=net.topology(net.Commands(run=run),"fixed"); c.cleanup()
  adds=[x[3] for x in calls if x[:3]==("ip","netns","add")]; dels=[x[3] for x in calls if x[:3]==("ip","netns","del")]
  self.assertEqual(dels,list(reversed(adds))); self.assertFalse(any("flush" in x for a in calls for x in a if isinstance(x,str)))
  candidate_up=[i for i,a in enumerate(calls) if a[-2:]==(t["names"]["si1"],"up")]
  candidate_down=[i for i,a in enumerate(calls) if a[-2:]==(t["names"]["si1"],"down")]
  self.assertEqual(len(candidate_up),1); self.assertEqual(len(candidate_down),1)
  candidate_routes=[i for i,a in enumerate(calls) if "table" in a and "102" in a]
  self.assertLess(candidate_up[0],min(candidate_routes)); self.assertGreater(candidate_down[0],max(candidate_routes))
  self.assertFalse(any(a[-2:]==(t["names"]["si1"],"up") for a in calls[candidate_down[0]+1:]))
  routes=[i for i,a in enumerate(calls) if "route" in a]
  links=[i for i,a in enumerate(calls) if a[-2:] in {(t["names"]["cr0"],"up"),(t["names"]["si0"],"up")} or "brq1" in a and a[-1:] == ("up",)]
  self.assertLess(max(links),min(routes))
  policy=[a for a in calls if "table" in a]
  self.assertEqual(sum("101" in a for a in policy),3)
  self.assertEqual(sum("102" in a for a in policy),3)
  self.assertEqual(sum("103" in a for a in policy),3)
  for table in ("101","102","103"):
   connected=next(i for i,a in enumerate(calls) if "route" in a and table in a and "10.88.1.0/24" in a)
   remote=next(i for i,a in enumerate(calls) if "route" in a and table in a and "10.88.0.0/24" in a)
   self.assertLess(connected,remote)
  candidate=next(a for a in policy if "102" in a and "route" in a and "10.88.0.0/24" in a)
  self.assertEqual(candidate[candidate.index("via")+1],"10.88.1.1"); self.assertIn("onlink",candidate)
 def test_server_strong_host_sysctls_precede_activation_and_fail_as_forwarding(self):
  calls=[]; c,t=net.topology(net.Commands(run=lambda args,**kw: (calls.append(tuple(args)) or subprocess.CompletedProcess(args,0,"",""))),"fixed")
  c.cleanup()
  sysctls=[(i,a) for i,a in enumerate(calls) if "sysctl" in a and any(str(x).startswith("net.ipv4.conf.") for x in a)]
  self.assertEqual(len(sysctls),12)
  activation=min(i for i,a in enumerate(calls) if a[-2:]==(t["names"]["si0"],"up"))
  self.assertLess(max(i for i,_ in sysctls),activation)
  values={next(str(x) for x in a if str(x).startswith("net.ipv4.conf.")) for _,a in sysctls}
  for scope in ("all","default",t["names"]["si0"],t["names"]["si1"]):
   self.assertTrue({f"net.ipv4.conf.{scope}.rp_filter=0",f"net.ipv4.conf.{scope}.arp_ignore=1",f"net.ipv4.conf.{scope}.arp_announce=2"} <= values)
  def fail(args,**kw):
   if any(str(x).startswith("net.ipv4.conf.") for x in args): raise subprocess.CalledProcessError(1,args)
   return subprocess.CompletedProcess(args,0,"","")
  result=net.worker("R8","abrupt-break",net.Commands(run=fail))
  self.assertEqual((result["setup_status"],result["error_category"]),("failed","forwarding_config"))
 def test_route_stage_categories_for_exact_command_groups(self):
  groups={
   "route_client_default":lambda a:"route" in a and "default" in a,
   "route_server_main":lambda a:"route" in a and "10.88.0.0/24" in a and "table" not in a,
   "route_old_policy":lambda a:"route" in a and "table" in a and "101" in a,
   "route_candidate_policy":lambda a:"route" in a and "table" in a and "102" in a,
   "route_vip_policy":lambda a:"route" in a and "table" in a and "103" in a,
   "candidate_deactivate":lambda a:a[-3:][0]=="set" and a[-1]=="down",
  }
  for category,matches in groups.items():
   def run(args,**kw):
    if matches(tuple(args)): raise subprocess.CalledProcessError(1,args)
    return subprocess.CompletedProcess(args,0,"","")
   result=net.worker("R8","abrupt-break",net.Commands(run=run))
   self.assertEqual((result["setup_status"],result["error_category"]),("failed",category))
  self.assertTrue({"route_client_default","route_server_main","route_old_policy","route_candidate_policy","route_vip_policy","candidate_deactivate"} <= q1.ERROR_CATEGORIES)
 def test_only_garp_replaces_vip_policy_route(self):
  calls=[]
  def run(args,**kw): calls.append(tuple(args)); return subprocess.CompletedProcess(args,0,"","")
  c=net.Commands(run=run); topology={"server":"s","names":{"si0":"old","si1":"new"}}
  old_clock,old_sleep=net.time.monotonic_ns,net.time.sleep
  net.time.monotonic_ns=lambda:10; net.time.sleep=lambda _:None
  try:
   net.actions(c,topology,"GARP-VIP","abrupt-break",10)
   garp_replaces=[a for a in calls if "route" in a and "replace" in a]
   self.assertEqual(len(garp_replaces),1)
   self.assertIn("103",garp_replaces[0]); self.assertIn("onlink",garp_replaces[0]); self.assertIn("via",garp_replaces[0])
   calls.clear(); net.actions(c,topology,"R8","abrupt-break",10); net.actions(c,topology,"TCP-reconnect","abrupt-break",10)
   self.assertFalse(any("route" in a and "replace" in a for a in calls))
   self.assertEqual(sum(a[-2:]==("new","up") for a in calls),2)
   net.actions(c,topology,"R8","make-before-break",10)
   self.assertEqual(sum(a[-2:]==("new","up") for a in calls),3)
  finally: net.time.monotonic_ns,net.time.sleep=old_clock,old_sleep
 def test_garp_emits_three_spaced_unsolicited_announcements(self):
  calls=[]; sleeps=[]
  def run(args,**kw): calls.append(tuple(args)); return subprocess.CompletedProcess(args,0,"","")
  c=net.Commands(run=run); topology={"server":"s","names":{"si0":"old","si1":"new"}}
  old_clock,old_sleep=net.time.monotonic_ns,net.time.sleep
  net.time.monotonic_ns=lambda:10; net.time.sleep=lambda delay:sleeps.append(delay)
  try: net.actions(c,topology,"GARP-VIP","abrupt-break",10)
  finally: net.time.monotonic_ns,net.time.sleep=old_clock,old_sleep
  arps=[a for a in calls if "arping" in a]
  self.assertEqual(len(arps),3)
  self.assertTrue(all(a[-9:]==("arping","-U","-c","1","-w","1","-I","new","10.88.1.100") for a in arps))
  self.assertEqual(sleeps,[.1,.1])
 def test_garp_accepts_status_zero_one_and_categories_other_statuses(self):
  topology={"server":"s","names":{"si0":"old","si1":"new"}}
  for status in (0,1):
   c=net.Commands(run=lambda args,**kw: subprocess.CompletedProcess(args,status,"",""))
   old_clock,old_sleep=net.time.monotonic_ns,net.time.sleep
   net.time.monotonic_ns=lambda:10; net.time.sleep=lambda _:None
   try: net.actions(c,topology,"GARP-VIP","abrupt-break",10)
   finally: net.time.monotonic_ns,net.time.sleep=old_clock,old_sleep
  c=net.Commands(run=lambda args,**kw: subprocess.CompletedProcess(args,2,"",""))
  old_clock,old_sleep=net.time.monotonic_ns,net.time.sleep
  net.time.monotonic_ns=lambda:10; net.time.sleep=lambda _:None
  try:
   with self.assertRaises(net.StageError) as raised: net.actions(c,topology,"GARP-VIP","abrupt-break",10)
  finally: net.time.monotonic_ns,net.time.sleep=old_clock,old_sleep
  self.assertEqual(raised.exception.category,"garp_announce")
  self.assertIn("garp_announce",q1.ERROR_CATEGORIES)
 def test_selector_echo_framing_handles_fragments_multiple_frames_and_listeners(self):
  first_in,first_out=bytearray(net.payload(1)[:17]),bytearray()
  second_in,second_out=bytearray(net.payload(3)+net.payload(4)),bytearray()
  net._queue_frames(first_in,first_out); net._queue_frames(second_in,second_out)
  self.assertEqual(bytes(first_out),b""); self.assertEqual(bytes(second_out),net.payload(3)+net.payload(4))
  first_in.extend(net.payload(1)[17:]+net.payload(2)); net._queue_frames(first_in,first_out)
  self.assertEqual(bytes(first_out),net.payload(1)+net.payload(2))
 def test_endpoint_dispatch(self):
  calls=[]
  class Proc:
   returncode=0
   def wait(self,timeout=None): return 0
  class Fake(net.Commands):
   def __init__(self): super().__init__(run=lambda a,**k: subprocess.CompletedProcess(a,0,"0\n","") ,popen=lambda a,**k: Proc())
   def spawn(self,ns,*a): calls.append((ns,a)); return Proc()
  old_topology,old_temp=net.topology,net.tempfile.TemporaryDirectory
  class Temp:
   def __enter__(self): self.p=Path("/tmp/q1-test-events"); self.p.mkdir(exist_ok=True); (self.p/"ready").write_text("ready"); (self.p/"events").write_text(json.dumps({"sent":[1]*10,"received":[(1+i,i) for i in range(10)]})); return str(self.p)
   def __exit__(self,*x): pass
  net.topology=lambda commands=None:(Fake(),{"client":"c","server":"s","names":{"si0":"o","si1":"n"}}); net.tempfile.TemporaryDirectory=lambda:Temp()
  try: net.worker("TCP-reconnect","abrupt-break")
  finally: net.topology,net.tempfile.TemporaryDirectory=old_topology,old_temp
  self.assertEqual(len(calls),2); self.assertEqual(calls[0][1][2],"endpoint-server"); self.assertEqual(calls[1][1][2],"endpoint-client")
 def test_r8_uses_udp_r8move_not_tcp_endpoint(self):
  seed=b"x"*32; peer=net.Identity.from_seed(b"y"*32).public
  command=net._r8("connect",seed,peer,"::1","::2","::3","10.88.1.2:0",["--peer","10.88.0.2:53104"])
  self.assertIn(str(ROOT/"reference/r8move.py"),command); self.assertIn("connect",command)
  self.assertNotIn("endpoint-client",command); self.assertIn("--allow-isolated-underlay",command)
  self.assertEqual(command[command.index("--timeout")+1],"3")
 def test_runner_worker_timeout_is_forty_seconds(self):
  seen=[]; original=q1.subprocess.run
  def run(*args,**kwargs):
   seen.append(kwargs["timeout"])
   return subprocess.CompletedProcess(args[0],0,json.dumps({"setup_status":"complete","failure":False,"censored":False,"error_category":None}),"")
  q1.subprocess.run=run
  try: q1.invoke_worker(q1.schedule(True)[0],"config")
  finally: q1.subprocess.run=original
  self.assertEqual(seen,[40])
 def test_bootstrap_and_manifest_tamper(self):
  plans=[p for p in q1.schedule() if p["exclusion_reason"] is None and p["mechanism"]=="R8" and p["arm"]=="abrupt-break" and p["block_id"]%2==0]
  rows=[{"trial_id":p["trial_id"],"mechanism":p["mechanism"],"arm":p["arm"],"block_id":p["block_id"],"setup_status":"failed" if i==0 else "complete","failure":i==0,"outage_ns":None if i==0 else p["block_id"]+1} for i,p in enumerate(plans)]
  one,two=q1.summary(rows,"x"),q1.summary(rows,"x")
  self.assertEqual(one,two)
  active=next(x for x in one if (x["mechanism"],x["arm"])==("R8","abrupt-break"))
  empty=next(x for x in one if (x["mechanism"],x["arm"])==("TCP-reconnect","abrupt-break"))
  self.assertEqual(set(active["block_bootstrap_95_percent_ci"]),{"failure_rate","outage_p50_ns","outage_p95_ns"})
  self.assertEqual(active["setup_failure_count"],1)
  self.assertIsNone(empty["block_bootstrap_95_percent_ci"]["failure_rate"])
  original=q1.MANIFEST; manifest=json.loads(original.read_text()); manifest["preregistrations"][0]["sha256"]="0"*64
  class Tampered:
   def read_text(self): return json.dumps(manifest)
  q1.MANIFEST=Tampered()
  try:
   with self.assertRaises(RuntimeError): q1.contract()
  finally: q1.MANIFEST=original
 def test_smoke_package_and_regeneration_bindings(self):
  original_preflight,original_invoke=q1.preflight,q1.invoke_worker
  def complete(plan,config):
   return {"protocol_id":"Q1","contract_version":"r8-benchmark-preregistration-v3","trial_id":plan["trial_id"],"block_id":plan["block_id"],"mechanism":plan["mechanism"],"arm":plan["arm"],"setup_status":"complete","error_category":None,"t_minus_3_ns":1,"activation_ns":2,"cutover_ns":3,"observation_end_ns":4,"readiness_ns":4,"censored":False,"failure":False,"sent_payloads":800,"received_payloads":800,"lost_payloads":0,"duplicate_payloads":0,"reordered_payloads":0,"outage_ns":1,"interface_counter_by_ordinal":{"pre":{},"post":{}},"process_user_cpu_ns":1,"process_system_cpu_ns":1,"configuration_sha256":config,"_command_sha256":"a"*64}
  q1.preflight=lambda:{"capabilities":["CAP_NET_ADMIN","CAP_NET_RAW"],"required_binaries":["ip","tc","arping"]}
  q1.invoke_worker=complete
  try:
   with tempfile.TemporaryDirectory() as directory:
    root=Path(directory); package=root/"package"; q1.package(package,"source","epoch",True)
    required={"environment.json","topology.json","raw.json","summary.json","smoke_non_result.json","preflight.json","manifest.json"}
    self.assertEqual({p.name for p in package.iterdir()},required)
    manifest=json.loads((package/"manifest.json").read_text())
    self.assertEqual((manifest["source_identity"],manifest["host_epoch"],manifest["row_count"]),("source","epoch",6))
    for name,digest in manifest["files"].items(): self.assertEqual(q1.sha(package/name),digest)
    environment=json.loads((package/"environment.json").read_text()); topology=json.loads((package/"topology.json").read_text())
    self.assertEqual((environment["interface_count"],environment["non_loopback_interface_count"],environment["veth_pair_count"]),(10,7,3))
    self.assertEqual((topology["interface_count"],topology["non_loopback_interface_count"],topology["veth_pair_count"]),(10,7,3))
    serialized="\n".join((package/name).read_text() for name in required)
    self.assertNotIn("10.88.",serialized); self.assertNotIn("r8q1-",serialized); self.assertNotIn("argv",serialized)
    before=(package/"manifest.json").read_bytes(); self.assertEqual(q1.regenerate(package),0); self.assertEqual((package/"manifest.json").read_bytes(),before)
    for component in ("raw.json","environment.json","topology.json","summary.json"):
     damaged=root/component; shutil.copytree(package,damaged)
     (damaged/component).write_text("{}")
     with self.assertRaises(RuntimeError): q1.regenerate(damaged)
  finally: q1.preflight,q1.invoke_worker=original_preflight,original_invoke
 def test_retained_v2_setup_failure_package_is_not_a_v3_result(self):
  package=ROOT/"bench/results/q1-setup-failure-v2"
  required={"environment.json","topology.json","raw.json","summary.json","smoke_non_result.json","preflight.json","manifest.json"}
  self.assertEqual({path.name for path in package.iterdir()},required)
  manifest=json.loads((package/"manifest.json").read_text())
  self.assertEqual(manifest["row_count"],1320)
  self.assertTrue(manifest["source_identity"].startswith("git:c8e"))
  self.assertEqual(manifest["host_epoch"],"closed-lab-epoch-004")
  for name,digest in manifest["files"].items(): self.assertEqual(q1.sha(package/name),digest)
  raw=json.loads((package/"raw.json").read_text())
  self.assertEqual(len(raw),1320)
  self.assertTrue(all(row["contract_version"]=="r8-benchmark-preregistration-v2" and row["setup_status"]=="failed" for row in raw))
  summary=json.loads((package/"summary.json").read_text())
  self.assertEqual(len(summary),6)
  for entry in summary:
   self.assertEqual(entry["contract_version"],"r8-benchmark-preregistration-v2")
   self.assertEqual(entry["setup_failure_count"],200)
   self.assertIsNone(entry["failure_rate"])
   self.assertIsNone(entry["outage_p50_ns"])
   self.assertIsNone(entry["outage_p95_ns"])
   self.assertTrue(all(value is None for value in entry["block_bootstrap_95_percent_ci"].values()))
  self.assertFalse(json.loads((package/"smoke_non_result.json").read_text()))
  self.assertNotEqual(q1.contract()["contract_version"],raw[0]["contract_version"])
if __name__=="__main__": unittest.main()
