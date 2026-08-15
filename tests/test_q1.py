import importlib.util
import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod
q1=load(ROOT/'bench/q1.py','q1')
net=load(ROOT/'tests/mobility_netns.py','mobility_netns')
r8move=load(ROOT/'reference/r8move.py','r8move_q1')

class Q1V4Tests(unittest.TestCase):
 def test_balanced_schedule(self):
  rows=q1.schedule(); self.assertEqual(len(rows),1320)
  for pair in q1.PAIR_ORDER:
   selected=[row for row in rows if (row['mechanism'],row['arm'])==pair]
   self.assertEqual(len(selected),220); self.assertEqual(sum(row['exclusion_reason']=='warmup' for row in selected),20)
   self.assertEqual(sum(sum((row['mechanism'],row['arm'])==pair for row in rows if row['block_id']==block)==4 for block in range(66)),22)
  self.assertTrue(all(sum(row['block_id']==block for row in rows)==20 for block in range(66)))
  self.assertEqual(rows,q1.schedule())
 def test_smoke_schedule_is_non_result(self):
  self.assertTrue(all(row['exclusion_reason']=='smoke_non_result' for row in q1.schedule(True)))
 def test_private_schedule_gate(self):
  schedule_r,schedule_w=os.pipe(); gate_r,gate_w=os.pipe()
  os.write(schedule_w,struct.pack('!QQQ',1,3_000_000_001,8_000_000_001)); os.write(gate_w,b'G')
  self.assertEqual(net._schedule(schedule_r,gate_r),(1,3_000_000_001,8_000_000_001))
 def test_each_endpoint_has_its_own_schedule_gate_and_cpu_report(self):
  source=(ROOT/'tests/mobility_netns.py').read_text()
  self.assertIn('server_schedule_r,server_schedule_w=os.pipe()',source)
  self.assertIn('client_schedule_r,client_schedule_w=os.pipe()',source)
  self.assertIn('server_gate_r,server_gate_w=os.pipe()',source)
  self.assertIn('client_gate_r,client_gate_w=os.pipe()',source)
  self.assertIn('_read_exact(cpu_r,96)',source)
  self.assertIn('endpoint-server","--mechanism",mechanism,"--ready-fd",str(ready_w),"--schedule-fd"',source)
 def test_parent_bounds_readiness_and_closes_writer(self):
  source=(ROOT/"tests/mobility_netns.py").read_text()
  self.assertIn("_read_endpoint_ready(ready_r,(server,client),count=2,record_size=8)",source)
  self.assertIn("_read_endpoint_ready(ready_r,(server,))",source)
  self.assertLess(source.rindex("_read_endpoint_ready("),source.index("os.close(ready_w)"))
  self.assertIn("process.poll() is not None",source)
  self.assertIn("fds[fds.index(ready_w)]=None",source)
 def test_r8_readiness_uses_two_nonzero_timestamp_records(self):
  class Process:
   @staticmethod
   def poll(): return None
  read_fd,write_fd=os.pipe()
  try:
   os.write(write_fd,struct.pack("!QQ",1,2)); os.close(write_fd); write_fd=None
   net._read_endpoint_ready(read_fd,(Process(),Process()),count=2,record_size=8,timeout=.1)
  finally:
   os.close(read_fd)
   if write_fd is not None: os.close(write_fd)
  read_fd,write_fd=os.pipe()
  try:
   os.write(write_fd,struct.pack("!QQ",0,2)); os.close(write_fd); write_fd=None
   with self.assertRaisesRegex(net.StageError,"endpoint_ready"):
    net._read_endpoint_ready(read_fd,(Process(),Process()),count=2,record_size=8,timeout=.1)
  finally:
   os.close(read_fd)
   if write_fd is not None: os.close(write_fd)
 def test_pre_runtime_failure_never_claims_complete_evidence(self):
  source=(ROOT/"tests/mobility_netns.py").read_text()
  self.assertIn('result["evidence_complete"]=runtime and bool(records)',source)
 def test_baseline_server_waits_for_gate_and_reports_cpu(self):
  source=(ROOT/'tests/mobility_netns.py').read_text()
  self.assertIn('_,_,end=_schedule(schedule_fd,gate_fd); before_ns=time.monotonic_ns(); before=resource.getrusage',source)
  self.assertIn('time.monotonic_ns()<end',source)
  self.assertIn('_cpu_record(before_ns,before,after_ns,after)',source)
 def test_r8_server_authenticates_before_gate_and_runs_to_end(self):
  source=(ROOT/'reference/r8move.py').read_text()
  self.assertIn('if not record["established"]:',source)
  connect=source[source.index('def _connect'):]; self.assertLess(connect.index('_ready(a.ready_fd)'),connect.index('_read_schedule(a.schedule_fd)')); self.assertLess(connect.index('_read_schedule(a.schedule_fd)'),connect.index('_wait_gate(a.gate_fd)'))
  self.assertIn('deadline=stream_end_ns/1_000_000_000+a.timeout',source)
  self.assertIn('time.monotonic_ns()<stream_end_ns',source)
 def test_r8_serve_retains_explicit_interop_stream_end(self):
  source=(ROOT/'reference/r8move.py').read_text()
  self.assertIn('stream_end_ns=a.stream_end_ns if a.stream_rate else 0',source)
  self.assertIn('deadline=max(time.monotonic()+a.timeout,stream_end_ns/1_000_000_000+a.timeout if stream_end_ns else 0)',source)
 def test_events_are_observed_not_synthesized(self):
  event={'scheduled':[(0,0),(1,net.RATE_NS),(2,2*net.RATE_NS)],'attempted':[(0,1),(2,2*net.RATE_NS+1)],'sent':[(0,2)],'received':[(0,3)]}
  measured=net.metrics(event,net.RATE_NS,8*net.RATE_NS)
  self.assertEqual((measured['scheduled_payloads'],measured['attempted_payloads'],measured['sent_payloads'],measured['received_payloads']),(3,2,1,1))
 def test_baseline_deadline_timeout_never_extends_next_due(self):
  due=100*net.RATE_NS; deadline=due+net.RATE_NS
  class Socket:
   def __init__(self): self.timeouts=[]; self.calls=[]
   def settimeout(self,value): self.timeouts.append(value)
   def connect(self): self.calls.append("connect")
   def sendall(self): self.calls.append("sendall")
   def recv(self): self.calls.append("recv")
  socket=Socket(); original=net.time.monotonic_ns
  try:
   net.time.monotonic_ns=lambda:deadline-1
   for operation in (socket.connect,socket.sendall,socket.recv):
    timeout=net._deadline_timeout(deadline)
    self.assertIsNotNone(timeout); socket.settimeout(timeout); operation()
   net.time.monotonic_ns=lambda:deadline
   self.assertIsNone(net._deadline_timeout(deadline))
  finally: net.time.monotonic_ns=original
  self.assertEqual(socket.timeouts,[1e-9]*3); self.assertEqual(socket.calls,["connect","sendall","recv"])
 def test_r8_receive_any_uses_exact_remaining_deadline(self):
  timeouts=[]; original_clock,original_select=r8move.time.monotonic,r8move.select.select
  clock=iter((1.0,1.0,1.005,1.01))
  r8move.time.monotonic=lambda:next(clock)
  r8move.select.select=lambda sockets,read,write,timeout:(timeouts.append(timeout) or ([],[],[]))
  try:
   with self.assertRaises(Exception): r8move._receive_any((),1.01,1)
  finally: r8move.time.monotonic,r8move.select.select=original_clock,original_select
  self.assertTrue(timeouts and all(0 < timeout <= .010000001 for timeout in timeouts)); self.assertTrue(all(timeout > .001 for timeout in timeouts))
 def test_partial_binary_events_retain_actual_counts_after_runtime_failure(self):
  with tempfile.TemporaryDirectory() as directory:
   records={name:os.open(str(Path(directory)/(name+".bin")),os.O_CREAT|os.O_RDWR|os.O_APPEND,0o600) for name in ("scheduled","attempted","sent","received")}
   try:
    for sequence in range(800): net._fd_write(records["scheduled"],sequence,sequence*net.RATE_NS)
    for sequence in (0,1,2): net._fd_write(records["attempted"],sequence,sequence*net.RATE_NS+1)
    for sequence in (0,1): net._fd_write(records["sent"],sequence,sequence*net.RATE_NS+2)
    net._fd_write(records["received"],0,3)
    measured=net.partial_metrics(records,10*net.RATE_NS,800*net.RATE_NS)
   finally:
    for fd in records.values(): os.close(fd)
  self.assertEqual((measured["scheduled_payloads"],measured["attempted_payloads"],measured["sent_payloads"],measured["received_payloads"]),(800,3,2,1))
  self.assertNotEqual(measured["scheduled_payloads"],measured["sent_payloads"])
 def test_supervisor_reduces_partial_persistent_evidence_without_fabrication(self):
  with tempfile.TemporaryDirectory() as directory:
   evidence=Path(directory)
   for name,values in {"scheduled":[(sequence,sequence*net.RATE_NS) for sequence in range(800)],"attempted":[(0,1)],"sent":[(0,2)],"received":[(0,3),(0,4)]}.items():
    (evidence/(name+".bin")).write_bytes(b"".join(struct.pack("!QQ",*value) for value in values))
   row=q1._supervisor_outcome("worker_timeout",{"phase":"runtime","t_minus_3_ns":0,"activation_ns":0,"cutover_ns":net.RATE_NS,"observation_end_ns":2*net.RATE_NS},evidence)
  self.assertEqual((row["scheduled_payloads"],row["attempted_payloads"],row["sent_payloads"],row["received_payloads"]),(800,1,1,2))
  self.assertEqual((row["duplicate_payloads"],row["lost_payloads"],row["evidence_complete"]),(1,799,True))
 def test_corrupt_persistent_evidence_is_unavailable(self):
  with tempfile.TemporaryDirectory() as directory:
   evidence=Path(directory)
   for name in ("scheduled","attempted","sent","received"): (evidence/(name+".bin")).write_bytes(b"x")
   row=q1._supervisor_outcome("worker_timeout",{"phase":"runtime","t_minus_3_ns":0,"activation_ns":0,"cutover_ns":0,"observation_end_ns":1},evidence)
  self.assertIsNone(row["sent_payloads"]); self.assertFalse(row["evidence_complete"])
 def test_runtime_overlay_keeps_partial_events_for_action_endpoint_and_sigterm(self):
  source=(ROOT/"tests/mobility_netns.py").read_text()
  self.assertIn("if runtime and cut is not None and end is not None:",source)
  self.assertIn("category=result.get(\"error_category\")",source)
  self.assertIn("except SystemExit:",source)
  self.assertIn("partial_metrics(records,cut,end)",source)
 def test_baseline_client_streams_binary_events_before_completion(self):
  source=(ROOT/"tests/mobility_netns.py").read_text()
  self.assertIn('for sequence in range(800): _fd_write(records["scheduled"],sequence,start+sequence*RATE_NS)',source)
  self.assertNotIn('for sequence in range(800): _fd_write(scheduled_fd',source)
  self.assertIn('_fd_write(attempt_fd,sequence)',source)
  self.assertIn('_fd_write(sent_fd,sequence)',source)
  self.assertIn('if response != payload(sequence): sock.close(); sock=None',source); self.assertIn('_fd_write(received_fd,sequence)',source)
  self.assertNotIn('Path(events_fd).write_text',source)
 def test_r8_cutover_gate_is_released_only_after_activation(self):
  source=(ROOT/"tests/mobility_netns.py").read_text()
  self.assertIn('"--cutover-gate-fd",str(cutover_r)',source)
  self.assertIn('activation_start,activation_complete=actions(c,t,mechanism,arm,cut,control_path)',source)
  self.assertIn('if mechanism=="R8": os.write(cutover_w,b"G")',source)
 def test_bridge_environment_requires_nonempty_observations(self):
  source=(ROOT/"tests/mobility_netns.py").read_text()
  self.assertIn('((topology["router"],"brq1"),)',source)
  self.assertIn('if not link or "mtu 1500" not in link',source)
  self.assertIn('if not qdisc or "fq_codel" not in qdisc',source)
 def test_interposed_late_or_duplicate_receive_resets_readiness(self):
  scheduled=[(sequence,sequence*net.RATE_NS) for sequence in range(30)]
  received=[(0,1)]+[(sequence,sequence*net.RATE_NS+1) for sequence in range(10,15)]+[(99,15*net.RATE_NS+1)]+[(sequence,sequence*net.RATE_NS+1) for sequence in range(15,20)]
  sent=[(sequence,stamp-1) for sequence,stamp in received]
  self.assertTrue(net.metrics({"scheduled":scheduled,"attempted":sent,"sent":sent,"received":received},net.RATE_NS,30*net.RATE_NS)["failure"])
 def test_cpu_unavailable_and_cleanup_proof_are_explicit(self):
  source=(ROOT/"tests/mobility_netns.py").read_text()
  self.assertIn('result["process_user_cpu_ns"]=result["process_system_cpu_ns"]=None; result["process_cpu_timestamp_ns_by_ordinal"]={}; result["cpu_complete"]=False',source)
  self.assertIn('result["cleanup_complete"]=not bool(cleanup)',source)
 def test_skip_short_send_and_delayed_burst_do_not_qualify(self):
  scheduled=[(sequence,sequence*net.RATE_NS) for sequence in range(30)]
  delayed=[(sequence,30*net.RATE_NS+sequence) for sequence in range(10,20)]
  measured=net.metrics({'scheduled':scheduled,'attempted':[(0,0)]+[(sequence,stamp-1) for sequence,stamp in delayed],'sent':[(0,0)]+[(sequence,stamp-1) for sequence,stamp in delayed],'received':[(0,1)]+delayed},net.RATE_NS,80*net.RATE_NS)
  self.assertTrue(measured['failure']); self.assertTrue(measured['censored'])
 def test_equal_deadline_and_readiness_window(self):
  scheduled=[(sequence,sequence*net.RATE_NS) for sequence in range(30)]
  received=[(0,1)]+[(sequence,sequence*net.RATE_NS+1) for sequence in range(10,20)]
  measured=net.metrics({'scheduled':scheduled,'attempted':received,'sent':received,'received':received},net.RATE_NS,30*net.RATE_NS)
  self.assertFalse(measured['failure']); self.assertEqual(measured['readiness_ns'],19*net.RATE_NS+1)
 def test_no_pre_delivery_is_censored_failure(self):
  scheduled=[(i,i*net.RATE_NS) for i in range(20)]
  received=[(i,(10+i)*net.RATE_NS+1) for i in range(10)]
  self.assertTrue(net.metrics({'scheduled':scheduled,'attempted':[(sequence,stamp-1) for sequence,stamp in received],'sent':[(sequence,stamp-1) for sequence,stamp in received],'received':received},10*net.RATE_NS,20*net.RATE_NS)['failure'])
 def test_payload_and_framing(self):
  self.assertEqual(len(net.payload(7)),64)
  incoming,outgoing=bytearray(net.payload(1)[:17]),bytearray(); net._queue_frames(incoming,outgoing); self.assertEqual(bytes(outgoing),b'')
  incoming.extend(net.payload(1)[17:]+net.payload(2)); net._queue_frames(incoming,outgoing); self.assertEqual(bytes(outgoing),net.payload(1)+net.payload(2))
 def test_cpu_and_counter_timestamp_raw_fields(self):
  self.assertTrue({"interface_counter_timestamp_ns_by_ordinal","counter_complete","process_cpu_timestamp_ns_by_ordinal"} <= set(q1.RAW_FIELDS))
  self.assertEqual(net.BOUNDARY_SKEW_NS,100_000_000)
  source=(ROOT/"tests/mobility_netns.py").read_text()
  self.assertIn('struct.pack("!QQQQQQ"',source)
  self.assertIn('_read_exact(cpu_r,96)',source)
  self.assertIn('pre_counter_ns<=start<=pre_counter_ns+BOUNDARY_SKEW_NS',source)
 def test_action_timestamps_and_cpu_fields_are_raw_fields(self):
  self.assertTrue({'activation_start_ns','activation_complete_ns','process_user_cpu_ns','process_system_cpu_ns'} <= set(q1.RAW_FIELDS))
  source=(ROOT/'tests/mobility_netns.py').read_text(); self.assertIn('pre_cpu=resource.getrusage',source); self.assertIn('post_cpu=resource.getrusage',source)
  calls=[]; topology={'server':'s','names':{'si0':'old','si1':'new'}}; command=net.Commands(run=lambda args,**kw:(calls.append(tuple(args)) or subprocess.CompletedProcess(args,0,'','')))
  old_clock,old_sleep=net.time.monotonic_ns,net.time.sleep; net.time.monotonic_ns=lambda:10; net.time.sleep=lambda _:None
  try: self.assertEqual(net.actions(command,topology,'R8','make-before-break',10),(10,10))
  finally: net.time.monotonic_ns,net.time.sleep=old_clock,old_sleep
 def test_cpu_baseline_follows_pre_gate_interface_counters(self):
  source=(ROOT/'tests/mobility_netns.py').read_text()
  self.assertIn('pre_interfaces=counters(t["server"],(t["names"]["si0"],t["names"]["si1"]),c); pre_counter_ns=time.monotonic_ns(); start=pre_counter_ns+BOUNDARY_SKEW_NS; pre_cpu=resource.getrusage(resource.RUSAGE_SELF); parent_cpu_pre_ns=time.monotonic_ns()',source)
 def test_cleanup_reaps_escaped_namespace_pid(self):
  calls=[]; signals=[]
  class Commands:
   def call(self,*args,**kwargs):
    calls.append(args)
    output="123\n" if args[2:]==("pids","owned") and sum(item[2:]==("pids","owned") for item in calls)==1 else ""
    return subprocess.CompletedProcess(args,0,output,"")
  original=net.os.kill; net.os.kill=lambda pid,sig:signals.append((pid,sig))
  try: self.assertIsNone(net._reap_namespace(Commands(),"owned"))
  finally: net.os.kill=original
  self.assertEqual(signals,[(123,net.signal.SIGTERM),(123,net.signal.SIGKILL)])
 def test_received_requires_sent_sequence_and_timestamp(self):
  with self.assertRaises(net.StageError): net.metrics({"scheduled":[(0,0)],"sent":[],"received":[(0,1)]},0,2)
 def test_cleanup_failures_are_explicit(self):
  self.assertTrue({'cleanup_delete','cleanup_reap','cleanup_residual','control_parse'} <= q1.ERROR_CATEGORIES)
  self.assertIn('failures.append("cleanup_delete")',(ROOT/'tests/mobility_netns.py').read_text())
 def test_package_rejects_forged_commit_environment(self):
  original=q1.source_identity; q1.source_identity=lambda:"bound"
  try:
   with tempfile.TemporaryDirectory() as directory:
    with self.assertRaisesRegex(RuntimeError,"git commit required"): q1.package(Path(directory)/"out","bound","closed-lab-epoch-123",git_commit="F"*40)
  finally: q1.source_identity=original
 def test_regenerate_preserves_valid_ineligible_empty_summary(self):
  source=(ROOT/"bench/q1.py").read_text()
  self.assertIn('rebuilt=summary(raw,expected_config) if not smoke and eligible else []',source)
  self.assertIn('if published is not eligible: raise RuntimeError("publication binding mismatch")',source)
 def test_workflow_restores_q1_ownership_before_validation(self):
  for name,package,validation in (("ci.yml","q1-smoke","Validate Q1 smoke rows"),("q1-full.yml","q1-full","Validate full Q1 package")):
   workflow=(ROOT/".github/workflows"/name).read_text()
   self.assertLess(workflow.index("Restore"),workflow.index(validation)); self.assertIn(f'[ -e "$RUNNER_TEMP/{package}" ]',workflow); self.assertIn("chmod -R u+rwX",workflow)
 def test_smoke_package_rejects_source_identity_mismatch(self):
  with tempfile.TemporaryDirectory() as directory:
   with self.assertRaisesRegex(RuntimeError,"source identity mismatch"):
    q1.package(Path(directory)/"out","arbitrary","smoke_epoch",smoke=True,git_commit="0"*40)
 def test_git_attestation_uses_repository_root(self):
  source=(ROOT/"bench/q1.py").read_text()
  self.assertIn('("git","rev-parse","HEAD"),check=False,text=True,capture_output=True,cwd=ROOT',source)
  self.assertIn('("git","status","--porcelain","--untracked-files=all"),check=False,text=True,capture_output=True,cwd=ROOT',source)
 def test_fixed_environment(self):
  source=(ROOT/'tests/mobility_netns.py').read_text(); self.assertIn('"mtu","1500"',source); self.assertIn('"root","fq_codel"',source); self.assertIn('ethtool',source); self.assertIn('262144',source)
  environment=q1.environment('s','g','h','c','d'); self.assertEqual(environment['mtu'],1500); self.assertEqual(environment['socket_buffer'],q1.SOCKET_BUFFER)
 def test_timeout_keeps_partial_evidence(self):
  row=q1._supervisor_outcome('worker_timeout',{'phase':'runtime','t_minus_3_ns':1,'activation_ns':2,'cutover_ns':3,'observation_end_ns':4})
  self.assertEqual((row['scheduled_payloads'],row['attempted_payloads'],row['sent_payloads']), (None,None,None)); self.assertTrue(row['failure'])
 def test_workflow_is_structural_and_always_uploads(self):
  workflow=(ROOT/'.github/workflows/q1-full.yml').read_text(); self.assertIn('if: always()',workflow); self.assertNotIn('shutil.rmtree',workflow); self.assertIn('publication_eligible.json',workflow); self.assertIn('counter_complete',workflow); self.assertIn('all(row[field] is True for field in completeness)',workflow); self.assertIn('proof(row)',workflow); self.assertIn('in {3, 4}',workflow)
  self.assertIn('steps.upload.outputs.artifact-digest',workflow); self.assertIn('^[0-9a-f]{64}$',workflow); self.assertIn('GITHUB_STEP_SUMMARY',workflow)
 def test_preflight_uid_refusal(self):
  old=q1.os.geteuid; q1.os.geteuid=lambda:1000
  try:
   with self.assertRaisesRegex(RuntimeError,'uid 0'): q1.preflight()
  finally: q1.os.geteuid=old
 def test_setup_and_counter_failures_are_retained_and_cleaned(self):
  calls=[]; attempts=[0]
  def failing(args,**kw):
   calls.append(tuple(args)); attempts[0]+=1
   if attempts[0]==4: raise subprocess.CalledProcessError(1,args)
   return subprocess.CompletedProcess(args,0,'','')
  result=net.worker('R8','abrupt-break',net.Commands(run=failing))
  self.assertEqual(result['setup_status'],'failed'); self.assertEqual(result['error_category'],'forwarding_config'); self.assertIn('command_sha256',result); self.assertTrue(any(a[:3]==('ip','netns','add') for a in calls))
  class Bad:
   def inside(self,*args): return subprocess.CompletedProcess(args,0,'not-a-number','')
  with self.assertRaises(net.StageError): net.counters('server',('dev',),Bad())
 def test_counters_batches_all_statistics_per_sample(self):
  calls=[]
  class Commands:
   def inside(self,*args):
    calls.append(args)
    return subprocess.CompletedProcess(args,0,"\n".join(str(value) for value in range(16))+"\n","")
  measured=net.counters("server",("old","new"),Commands())
  self.assertEqual(len(calls),1); self.assertEqual(calls[0][:2],("server","cat")); self.assertEqual(measured["1"]["tx_errors"],15)
 def test_topology_ownership_routes_and_candidate_down(self):
  calls=[]
  def run(args,**kw):
   calls.append(tuple(args))
   if 'ethtool' in args: return subprocess.CompletedProcess(args,0,'generic-receive-offload: off\ngeneric-segmentation-offload: off\ntcp-segmentation-offload: off\n','')
   if 'tc' in args: return subprocess.CompletedProcess(args,0,'qdisc fq_codel 0: root\n','')
   if '-d' in args and 'veth' in args: return subprocess.CompletedProcess(args,0,'1: dev: <BROADCAST>\n','')
   if '-o' in args: return subprocess.CompletedProcess(args,0,'1: dev: <BROADCAST> mtu 1500\n','')
   if args[-2:]==('netns','list'): return subprocess.CompletedProcess(args,0,'','')
   return subprocess.CompletedProcess(args,0,'','')
  c,t=net.topology(net.Commands(run=run),'fixed'); c.cleanup()
  adds=[x[3] for x in calls if x[:3]==('ip','netns','add')]; dels=[x[3] for x in calls if x[:3]==('ip','netns','del')]
  self.assertEqual(dels,list(reversed(adds))); self.assertFalse(any('flush' in x for a in calls for x in a if isinstance(x,str)))
  candidate_down=next(i for i,a in enumerate(calls) if a[-2:]==(t['names']['si1'],'down')); self.assertTrue(any('table' in a and '102' in a for a in calls[:candidate_down]))
 def test_static_neighbor_and_strong_host_setup(self):
  calls=[]
  def run(args,**kw):
   calls.append(tuple(args))
   if 'ethtool' in args: return subprocess.CompletedProcess(args,0,'generic-receive-offload: off\ngeneric-segmentation-offload: off\ntcp-segmentation-offload: off\n','')
   if 'tc' in args: return subprocess.CompletedProcess(args,0,'qdisc fq_codel 0: root\n','')
   if '-o' in args: return subprocess.CompletedProcess(args,0,'1: dev: <BROADCAST> mtu 1500\n','')
   return subprocess.CompletedProcess(args,0,'','')
  c,t=net.topology(net.Commands(run=run),'fixed'); c.cleanup()
  neighbors=[a for a in calls if 'neigh' in a]; self.assertEqual(len(neighbors),4); self.assertTrue(all('permanent' in a for a in neighbors)); self.assertFalse(any('10.88.1.100' in a for a in neighbors))
  sysctls=[a for a in calls if 'sysctl' in a and any(str(x).startswith('net.ipv4.conf.') for x in a)]; self.assertEqual(len(sysctls),12)
 def test_route_categories_and_activation_order(self):
  topology={'server':'s','names':{'si0':'old','si1':'new'}}; calls=[]; c=net.Commands(run=lambda args,**kw:(calls.append(tuple(args)) or subprocess.CompletedProcess(args,0,'','')))
  old_clock,old_sleep=net.time.monotonic_ns,net.time.sleep; net.time.monotonic_ns=lambda:10; net.time.sleep=lambda _:None
  try: start,complete=net.actions(c,topology,'GARP-VIP','abrupt-break',10)
  finally: net.time.monotonic_ns,net.time.sleep=old_clock,old_sleep
  self.assertEqual((start,complete),(10,10)); self.assertTrue(any(a==('ip','netns','exec','s','ip','route','replace','10.88.0.0/24','via','10.88.1.1','dev','new','onlink') for a in calls)); self.assertTrue(any(a==('ip','netns','exec','s','ip','route','get','10.88.0.2','from','10.88.1.3') for a in calls)); self.assertEqual(len([a for a in calls if 'arping' in a]),3)
 def test_tcp_listener_uses_per_device_binding(self):
  source=(ROOT/'tests/mobility_netns.py').read_text(); self.assertIn('socket.SO_BINDTODEVICE',source); self.assertIn('(old_dev,new_dev)[index].encode()+b"\\0"',source)
 def test_r8_uses_udp_r8move_and_private_fds(self):
  command=net._r8('connect',b'x'*32,net.Identity.from_seed(b'y'*32).public,'::1','::2','::3','10.88.1.2:0',['--peer','10.88.0.2:53104'])
  self.assertIn(str(ROOT/'reference/r8move.py'),command); self.assertNotIn('endpoint-client',command); self.assertEqual(command.count("--timeout"),0)
  source=(ROOT/'reference/r8move.py').read_text(); self.assertIn('--schedule-fd',source); self.assertIn('--attempt-fd',source)
  for forbidden in ('--deterministic-scid','--deterministic-candidate-hex','--deterministic-secret-hex'):
   self.assertNotIn(forbidden,command); self.assertNotIn(forbidden,source)
  self.assertIn('retry_waits = (0.5, 1.0, 2.0)',source)
  self.assertIn('retry_deadlines = (opened_at + 0.5, opened_at + 1.5, opened_at + 3.5)',source)
  handshake=source[source.index('def _handshake'):source.index('def _exchange')]
  self.assertNotIn('time.monotonic() + retry_waits[retry_index]',handshake)
  self.assertIn('deadline=time.monotonic()+3',source)
  for due in (10,10_000_000,123_456_780):
   self.assertEqual((due+10_000_000)/1e9,due/1e9+10_000_000/1e9)
 def test_r8_nonzero_identifiers_retry_fresh_os_randomness(self):
  original=r8move._random
  values=iter((b"\0"*8,b"\x01"+b"\0"*7))
  r8move._random=lambda size: next(values)
  try: self.assertEqual(r8move._nonzero_random(8),b"\x01"+b"\0"*7)
  finally: r8move._random=original
 def test_supervisor_control_parse_failure(self):
  self.assertEqual(q1._supervisor_outcome('worker_exit',{'_parse_failure':True})['error_category'],'control_parse')
 def test_graceful_timeout_worker_payload_is_retained(self):
  payload={"setup_status":"complete","error_category":"worker_timeout","failure":True,"censored":True,"scheduled_payloads":None,"attempted_payloads":None,"sent_payloads":None,"received_payloads":None,"lost_payloads":None,"duplicate_payloads":None,"reordered_payloads":None,"outage_ns":None,"interface_counter_by_ordinal":{},"evidence_complete":False}
  class Process:
   returncode=0
   def __init__(self): self.calls=0; self.pid=123
   def communicate(self,timeout=None):
    self.calls+=1
    if self.calls==1: raise subprocess.TimeoutExpired("worker",timeout)
    return json.dumps(payload),"graceful"
  original_popen,original_killpg,original_contract,original_cleanup=q1.subprocess.Popen,q1.os.killpg,q1.contract,q1._cleanup_worker_namespaces
  q1.subprocess.Popen=lambda *args,**kwargs:Process(); q1.os.killpg=lambda pid,sig:None; q1.contract=lambda:{"contract_version":"r8-benchmark-preregistration-v5"}; q1._cleanup_worker_namespaces=lambda suffix:None
  try:
   row=q1.invoke_worker({"trial_id":0,"block_id":0,"mechanism":"R8","arm":"abrupt-break","exclusion_reason":None},"config")
  finally:
   q1.subprocess.Popen,q1.os.killpg,q1.contract,q1._cleanup_worker_namespaces=original_popen,original_killpg,original_contract,original_cleanup
  self.assertEqual((row["scheduled_payloads"],row["attempted_payloads"],row["sent_payloads"],row["received_payloads"]),(None,None,None,None)); self.assertTrue(row["cleanup_complete"])
  self.assertEqual(row["error_category"],"worker_timeout")
 def test_worker_payload_allows_authenticated_receive_duplicates(self):
  payload={"setup_status":"complete","error_category":None,"failure":False,"censored":False,"scheduled_payloads":3,"attempted_payloads":2,"sent_payloads":2,"received_payloads":3,"evidence_complete":True}
  self.assertEqual(q1._worker_payload(json.dumps(payload)),payload)
 def test_partial_runtime_without_missing_counters_does_not_fabricate(self):
  source=(ROOT/"tests/mobility_netns.py").read_text()
  self.assertIn('"activation":result.get("interface_counter_by_ordinal",{}).get("activation",sampler_records.get("activation",{}))',source)
  self.assertIn('"post":result.get("interface_counter_by_ordinal",{}).get("post",{}) if result else {}',source)
 def test_activation_sampler_records_at_cutover_independently(self):
  class Stop:
   def __init__(self): self.delays=[]
   def wait(self,delay): self.delays.append(delay); return False
  records={}; errors=[]; stop=Stop(); original_clock,original_counters=net.time.monotonic_ns,net.counters
  net.time.monotonic_ns=lambda:100
  net.counters=lambda ns,devs,commands:{"0":{"rx_packets":1}}
  try: net._activation_sampler(None,{"server":"server","names":{"si0":"old","si1":"new"}},200,stop,records,errors)
  finally: net.time.monotonic_ns,net.counters=original_clock,original_counters
  self.assertEqual(stop.delays,[1e-7]); self.assertEqual(records["activation"]["0"]["rx_packets"],1); self.assertEqual(errors,[])
 def test_ci_smoke_uses_identity_and_observed_count_bounds(self):
  workflow=(ROOT/".github/workflows/ci.yml").read_text()
  self.assertIn('SOURCE_IDENTITY="$(python3 bench/q1.py source-identity)"',workflow)
  self.assertIn('--source-identity "$SOURCE_IDENTITY"',workflow)
  self.assertIn('row["scheduled_payloads"] == 800',workflow)
  self.assertIn('0 <= row["sent_payloads"] <= row["attempted_payloads"] <= row["scheduled_payloads"] == 800 and row["received_payloads"] >= 0',workflow)
  self.assertNotIn('row["sent_payloads"] == 800',workflow)
  self.assertIn('tshark=4.6.4-1 iproute2 arping ethtool',workflow); self.assertIn('{"pre", "activation", "post"}',workflow); self.assertIn('counter_complete',workflow); self.assertIn('proof(row)',workflow)
 def test_timestamp_proof_predicate_semantics(self):
  def proof(row):
   counters=row["interface_counter_timestamp_ns_by_ordinal"]; cpu=row["process_cpu_timestamp_ns_by_ordinal"]
   return set(counters)=={"pre","activation","post"} and counters["pre"]<=row["t_minus_3_ns"]<=counters["pre"]+100000000 and abs(counters["activation"]-row["cutover_ns"])<=100000000 and row["observation_end_ns"]<=counters["post"]<=row["observation_end_ns"]+100000000 and set(cpu)=={"endpoint_0","endpoint_1","parent"} and all(value["pre"]<=row["t_minus_3_ns"] and value["post"]>=row["observation_end_ns"] for value in cpu.values())
  row={"t_minus_3_ns":100,"cutover_ns":200,"observation_end_ns":300,"interface_counter_timestamp_ns_by_ordinal":{"pre":0,"activation":200,"post":300},"process_cpu_timestamp_ns_by_ordinal":{key:{"pre":100,"post":300} for key in ("endpoint_0","endpoint_1","parent")}}
  self.assertTrue(proof(row)); row["interface_counter_timestamp_ns_by_ordinal"]["activation"]=100000201; self.assertFalse(proof(row))
 def test_source_identity_is_canonical(self):
  frozen=json.loads((ROOT/'bench/protocols/q1.json').read_text())['implementation_binding']
  self.assertEqual(q1.contract()['implementation_binding'],frozen)
  self.assertEqual(q1.implementation_sources(),frozen['source_map'])
  self.assertEqual(q1.stable_sha(frozen['source_map']),frozen['source_map_sha256'])
  self.assertEqual(q1.source_identity(),"sha256:"+frozen['source_map_sha256'])
  self.assertNotIn("bench/protocols/q1.json",q1.implementation_sources())
 def test_contract_rejects_tampered_frozen_source_map(self):
  original=q1.implementation_sources
  tampered=dict(original()); tampered["bench/q1.py"]="0"*64
  q1.implementation_sources=lambda:tampered
  try:
   with self.assertRaisesRegex(RuntimeError,"source drift"): q1.contract()
  finally: q1.implementation_sources=original
 def test_summary_bootstrap_is_deterministic(self):
  plans=[p for p in q1.schedule() if p['exclusion_reason'] is None and p['mechanism']=='R8' and p['arm']=='abrupt-break']
  rows=[{'trial_id':p['trial_id'],'mechanism':p['mechanism'],'arm':p['arm'],'block_id':p['block_id'],'setup_status':'complete','failure':False,'outage_ns':p['block_id']+1} for p in plans]
  original=q1.contract; q1.contract=lambda:{"contract_version":"r8-benchmark-preregistration-v5"}
  try: self.assertEqual(q1.summary(rows,'x'),q1.summary(rows,'x'))
  finally: q1.contract=original
 def test_manifest_tamper_is_refused(self):
  original=q1.MANIFEST; manifest=json.loads(original.read_text()); manifest['preregistrations'][0]['sha256']='0'*64
  class Tampered:
   def read_text(self): return json.dumps(manifest)
  q1.MANIFEST=Tampered()
  try:
   with self.assertRaises(RuntimeError): q1.contract()
  finally: q1.MANIFEST=original
 def test_reducer_rejects_noncanonical_parent_schedule(self):
  with tempfile.TemporaryDirectory() as directory:
   evidence=Path(directory)
   for name in ("scheduled","attempted","sent","received"): (evidence/(name+".bin")).write_bytes(b"")
   row=q1._supervisor_outcome("worker_timeout",{"phase":"runtime","t_minus_3_ns":0,"activation_ns":0,"cutover_ns":0,"observation_end_ns":1},evidence)
  self.assertFalse(row["evidence_complete"]); self.assertIsNone(row["scheduled_payloads"])
 def test_supervisor_cleanup_uses_only_deterministic_owned_namespaces(self):
  calls=[]
  class Result: returncode=0; stdout=""
  original=q1.subprocess.run
  q1.subprocess.run=lambda args,**kwargs:(calls.append(args) or Result())
  try: self.assertIsNone(q1._cleanup_worker_namespaces("fixed"))
  finally: q1.subprocess.run=original
  deletes=[call for call in calls if call[:3]==("ip","netns","del")]
  self.assertEqual(deletes,[("ip","netns","del","r8q1-client-fixed"),("ip","netns","del","r8q1-server-fixed"),("ip","netns","del","r8q1-router-fixed")])
  inspected=[call[3] for call in calls if call[:3]==("ip","netns","pids")]
  self.assertEqual(set(inspected),{"r8q1-client-fixed","r8q1-server-fixed","r8q1-router-fixed"}); self.assertTrue(all(inspected.count(name)>=1 for name in set(inspected)))
 def test_worker_payload_null_counts_require_censored_failure(self):
  payload={"setup_status":"complete","error_category":"worker_timeout","failure":True,"censored":True,"scheduled_payloads":None,"attempted_payloads":None,"sent_payloads":None,"received_payloads":None,"evidence_complete":False}
  self.assertEqual(q1._worker_payload(json.dumps(payload)),payload)
  payload["censored"]=False; self.assertIsNone(q1._worker_payload(json.dumps(payload)))
 def test_observed_topology_requires_all_owned_namespaces(self):
  class Commands:
   def call(self,*args,**kwargs): return subprocess.CompletedProcess(args,0,"only-one\n","")
  with self.assertRaises(net.StageError): net.observed_topology(Commands(),{"client":"a","server":"b","router":"c"})
 def test_retained_v2_artifact_is_not_current_contract(self):
  package=ROOT/'bench/results/q1-setup-failure-v2'; manifest=json.loads((package/'manifest.json').read_text()); raw=json.loads((package/'raw.json').read_text())
  self.assertEqual(manifest['row_count'],1320); self.assertTrue(all(row['setup_status']=='failed' for row in raw)); self.assertEqual(json.loads((ROOT/'bench/protocols/q1.json').read_text())['contract_version'],'r8-benchmark-preregistration-v5'); self.assertNotEqual('r8-benchmark-preregistration-v5',raw[0]['contract_version'])

if __name__=='__main__': unittest.main()
