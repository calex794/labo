#!/usr/bin/env python3
"""TIME-04 two independent OS processes over local TCP; fail closed."""
import json,socket,subprocess,sys,time
from pathlib import Path

binary=sys.argv[1]
out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
cases={
 "honest":"BOUND_SIGNED_UNTRUSTED_UTC",
 "signed-lie":"BOUND_SIGNED_UNTRUSTED_UTC",
 "replay":"REJECT_REPLAY",
 "old-epoch":"REJECT_EPOCH",
 "rollback":"REJECT_ROLLBACK",
 "tamper":"ERROR",
 "wrong-noise-key":"ERROR",
 "silent":"ERROR",
}
results=[]
for scenario,expected in cases.items():
 with socket.socket() as probe:
  probe.bind(("127.0.0.1",0));port=probe.getsockname()[1]
 addr=f"127.0.0.1:{port}"
 server=subprocess.Popen([binary,"server",addr,scenario],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
 try:
  ready=server.stdout.readline().strip()
  assert ready=="READY",(scenario,ready,server.stderr.read())
  client=subprocess.run([binary,"client",addr],capture_output=True,text=True,timeout=8)
  final=client.stdout.strip()
  status=next((line.removeprefix("RESULT ") for line in final.splitlines() if line.startswith("RESULT ")),"ERROR")
  assert status==expected,(scenario,status,client.stderr)
  if expected=="ERROR":
   assert client.returncode!=0
  else:
   assert client.returncode==0
  stdout,stderr=server.communicate(timeout=8)
  results.append({"scenario":scenario,"expected":expected,"actual":status,
     "client_exit_code":client.returncode,"server_exit_code":server.returncode})
 finally:
  if server.poll() is None:
   server.kill();server.communicate()
assert len(results)==len(cases)
assert results[0]["actual"]=="BOUND_SIGNED_UNTRUSTED_UTC"
assert results[1]["actual"]=="BOUND_SIGNED_UNTRUSTED_UTC" # signed lie passes cryptography
(out/"results.json").write_text(json.dumps({"schema":"labo-time04-noise-v1","claim":"real-noise-loopback-only-synthetic-utc","cases":results},indent=2)+"\n")
text=["# TIME-04: Noise IK protected two-process UTC claims","","The two peers use genuine Noise IK encrypted TCP loopback, with deterministic INSECURE laboratory keys.", "A verified signature still cannot establish truth of UTC: honest and signed-lie both remain signed but untrusted.","","| Scenario | Expected | Actual |","|---|---|---|"]
for x in results:text.append(f'| {x["scenario"]} | {x["expected"]} | {x["actual"]} |')
text+=["","No Roughtime/NTS, QUIC, multiple physical hosts, RTC, W3/W4 or remote operator attestation.","This experiment must never update the OS clock or authorize an expiring FETCH."]
(out/"report.md").write_text("\n".join(text)+"\n")
print("\n".join(text))
