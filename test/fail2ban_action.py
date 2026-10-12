"""Runs the Gen0Sec Fail2Ban action's commands, rendered by Fail2Ban itself,
against a local mock of the Signal API, and checks each exits 0 only on 200.

Needs Fail2Ban's Python package (the fail2ban package on Debian and Ubuntu).
Usage, from the repository root:  python3 test/fail2ban_action.py
  python3 test/fail2ban_action.py --local FILE --expires N --host H
reads the role-written gen0sec.local FILE through Fail2Ban's ActionReader and
checks the ban command it renders sends expires_in N (omit --expires for the
jail's bantime, 600 here) and a rule_ref with host H (omit --host for the
short hostname).

GEN0SEC_FAIL2BAN_PYTHONPATH, if set, is searched first for the fail2ban package
(make install unpacks one there when the system has none).
"""
import json, os, subprocess, sys, threading, shutil
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, '/usr/lib/python3/dist-packages')
if os.environ.get("GEN0SEC_FAIL2BAN_PYTHONPATH"):
    sys.path.insert(0, os.environ["GEN0SEC_FAIL2BAN_PYTHONPATH"])
from fail2ban.client.actionreader import ActionReader
from fail2ban.server.action import CommandAction
from fail2ban.server.ipdns import IPAddr

import os, tempfile
here = os.path.dirname(os.path.abspath(__file__))
basedir = tempfile.mkdtemp()
os.makedirs(f"{basedir}/action.d")
shutil.copy(os.path.join(here, "..", "roles", "fail2ban", "files", "gen0sec.conf"), f"{basedir}/action.d/gen0sec.conf")
args = sys.argv[1:]
def opt(name):
    return args[args.index(name) + 1] if name in args else None
local_file = opt("--local")
if local_file:
    shutil.copy(local_file, f"{basedir}/action.d/gen0sec.local")
reply = {"code": 200}; seen = []

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        seen.append((self.path, self.headers.get("Authorization"), json.loads(body)))
        self.send_response(reply["code"]); self.end_headers(); self.wfile.write(b"{}")
    def log_message(self, *a): pass

srv = HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_port}/v2/signal"

# The key lives in a header file, so it never appears in the command that
# Fail2Ban runs (and logs in full when the command fails).
headers = f"{basedir}/gen0sec.headers"
with open(headers, "w") as f:
    f.write("Authorization: Bearer TESTKEY\n")

def render(cmd, ip="203.0.113.7", bantime=600):
    r = ActionReader("gen0sec", "sshd", {"g0sheaders": headers, "g0surl": url}, basedir=basedir)
    assert r.read(), "read failed"; r.getOptions({})
    a = CommandAction(None, "gen0sec")
    for k, v in r.getCombined().items():
        try: setattr(a, k, v)
        except Exception: pass
    if not getattr(a, cmd, ""):
        return None
    out = CommandAction.replaceTag(f"<{cmd}>", a._properties, conditional="family=inet4", cache=a._substCache)
    return CommandAction.replaceDynamicTags(out, {"ip": IPAddr(ip), "bantime": bantime, "failures": 5, "time": 0})

fails = 0
def check(name, ok):
    global fails
    print(("ok   " if ok else "FAIL ") + name); fails += 0 if ok else 1

if local_file:
    import socket
    reply["code"] = 200
    c = render("actionban")
    check("actionban is defined", c is not None)
    subprocess.run(["/bin/sh", "-c", c], capture_output=True)
    sent = seen[0][2][0] if seen else {}
    want_exp = int(opt("--expires") or 600)
    want_host = opt("--host") or socket.gethostname().split(".")[0]
    check(f"gen0sec.local gives expires_in {want_exp} (got {sent.get('expires_in')})", sent.get("expires_in") == want_exp)
    want_ref = f"fail2ban-{want_host}-sshd-203.0.113.7"
    check(f"gen0sec.local gives rule_ref {want_ref} (got {sent.get('rule_ref')})", sent.get("rule_ref") == want_ref)
    sys.exit(1 if fails else 0)

for cmd in ("actionban", "actionunban", "actionprolong"):
    c = render(cmd)
    check(f"{cmd} is defined", c is not None)
    if c is None: continue
    check(f"{cmd} does not carry the API key in its command line", "TESTKEY" not in c)
    for code, want in ((200, 0), (206, 1), (403, 1), (500, 1)):
        reply["code"] = code; seen.clear()
        rc = subprocess.run(["/bin/sh", "-c", c], capture_output=True).returncode
        check(f"{cmd} on HTTP {code} exits {'0' if want == 0 else 'non-zero'} (rc={rc})", (rc == 0) == (want == 0))
        check(f"{cmd} on HTTP {code} reached the API with the key", len(seen) == 1 and seen[0][1] == "Bearer TESTKEY")
# The rule name carries the host, so one host's unban cannot lift another host's block.
import socket
host = socket.gethostname().split(".")[0]
refs = {}
for cmd in ("actionban", "actionunban", "actionprolong"):
    reply["code"] = 200; seen.clear()
    subprocess.run(["/bin/sh", "-c", render(cmd)], capture_output=True)
    refs[cmd] = seen[0][2][0]["rule_ref"] if seen else None
want = f"fail2ban-{host}-sshd-203.0.113.7"
for cmd, ref in refs.items():
    check(f"{cmd} names the rule {want} (got {ref})", ref == want)
srv.shutdown()
# control: an unreachable API must also fail
c = render("actionban").replace(url, "http://127.0.0.1:1/v2/signal")
check("actionban with the API unreachable exits non-zero", subprocess.run(["/bin/sh", "-c", c], capture_output=True).returncode != 0)
sys.exit(1 if fails else 0)
