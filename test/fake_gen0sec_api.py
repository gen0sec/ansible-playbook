#!/usr/bin/env python3
"""A small in-memory stand-in for the Gen0Sec management API, enough to test
roles/policy/library/gen0sec_policy.py: Bearer auth, paged lists (2 items per
page, to exercise paging), POST/PUT/DELETE with If-Match versions, server-side
defaults, the managed IDS and smart firewall catalogues, and the batch endpoint
(POST .../batch: the operations in order, all or nothing; each one is logged in
_calls as if sent alone, after a "BATCH <n>" entry). GET /_batch/off and
/_batch/on switch the batch endpoint off (404, like an older API) and on.

usage: fake_gen0sec_api.py PORT [KEY=WORKSPACE:AGENT ...]

Each workspace has its own rules and catalogues and holds one agent. Repeat a
key to give it several workspaces. Default: test-key=ws-1:firewall. A key used
on a workspace it was not given gets 403.
"""
import copy
import json
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PAGE = 2
DEFAULTS = {
    "firewall-rules": {"ip_version": 4, "protocol": "any", "enabled": True},
    "smart-firewall-rules": {"enabled": True},
    "waf-rules": {"enabled": True},
    "access-rules": {},
}
WRITABLE = {
    "firewall-rules": ["name", "direction", "action", "ip_version", "protocol", "source", "destination",
                       "source_ports", "destination_ports", "conn_state", "tcp_flags", "priority",
                       "enabled", "description", "expires_at", "tags"],
    "access-rules": ["type", "value", "action", "description", "expires_at", "tags"],
    "smart-firewall-rules": ["name", "expression", "action", "enabled", "order", "description", "expires_at", "tags"],
    "waf-rules": ["name", "expression", "action", "enabled", "order", "description", "expires_at", "tags"],
}
ORDER_FIELD = {"firewall-rules": "priority", "smart-firewall-rules": "order", "waf-rules": "order"}


def new_workspace(agent):
    ids, sfw = {}, {}
    for cls in ("recon", "malware", "exploit"):
        i = str(uuid.uuid4())
        ids[i] = {"id": i, "managed_rule_id": i, "threat_class": cls, "name": cls.title(), "enabled": False,
                  "default_tier": "alert", "tier_override": None, "version": 0}
    for n in ("ja4-scanners", "tor-exits"):
        i = str(uuid.uuid4())
        sfw[i] = {"id": i, "managed_rule_id": i, "name": n, "enabled": False, "version": 0}
    return {"store": {k: {} for k in WRITABLE}, "ids": ids, "sfw": sfw, "calls": [],
            "agents": [{"id": "a-" + agent, "hostname": agent, "online": True, "version": "0.8.9", "mode": "agent"}]}


KEYS = {}        # API key -> workspace ids
WORKSPACES = {}  # workspace id -> state
BATCH = {"enabled": True}


class Headers(dict):
    """Case-insensitive header lookup for the operations of a batch."""
    def get(self, k, default=None):
        for key, v in self.items():
            if key.lower() == k.lower():
                return v
        return default

def ids_view(e):
    v = dict(e)
    v["tier"] = e["tier_override"] or e["default_tier"]
    return v


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body=None):
        raw = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json" if code < 400 else "application/problem+json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def problem(self, code, detail):
        self.reply(code, {"status": code, "detail": detail, "code": "test"})

    def body(self):
        if hasattr(self, "_body"):
            return self._body
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else {}

    def version_ok(self, obj):
        want = self.headers.get("If-Match")
        return want is None or want == '"%s"' % obj["version"]

    def paged(self, items, q):
        if q.get("all"):  # test helper: everything in one page
            return self.reply(200, {"items": items, "next_page_token": ""})
        start = int((q.get("page_token") or ["0"])[0])
        page = items[start:start + PAGE]
        nxt = str(start + PAGE) if start + PAGE < len(items) else ""
        self.reply(200, {"items": page, "next_page_token": nxt})

    def route(self, method):
        auth = self.headers.get("Authorization") or ""
        allowed = KEYS.get(auth[len("Bearer "):]) if auth.startswith("Bearer ") else None
        if allowed is None:
            return self.problem(401, "bad key")
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/_calls":  # test helper: writes seen so far, per workspace
            return self.reply(200, {"items": {w: WORKSPACES[w]["calls"] for w in sorted(allowed)}})
        if u.path in ("/_batch/off", "/_batch/on"):  # test helper
            BATCH["enabled"] = u.path.endswith("on")
            return self.reply(200, BATCH)
        m = re.match(r"^/management/v1/workspaces/([^/]+)/([a-z-]+)(?:/([^/]+))?$", u.path)
        if not m or m.group(1) not in WORKSPACES:
            return self.problem(404, "no such path")
        if m.group(1) not in allowed:
            return self.problem(403, "key has no access to this workspace")
        ws = WORKSPACES[m.group(1)]
        STORE, IDS, SFW, AGENTS, CALLS = ws["store"], ws["ids"], ws["sfw"], ws["agents"], ws["calls"]
        coll, item = m.group(2), m.group(3)
        if coll == "batch" and not item and method == "POST":
            if not BATCH["enabled"]:
                return self.problem(404, "no such path")
            return self.batch(m.group(1))
        if method != "GET":
            CALLS.append("%s %s" % (method, coll))
            if method == "POST" and coll in ("firewall-rules", "smart-firewall-rules"):
                # Peek at the body for the write-order test, then let the
                # handlers below read it as usual (a batch operation has it set).
                if not hasattr(self, "_body"):
                    n = int(self.headers.get("Content-Length") or 0)
                    raw = self.rfile.read(n) if n else b""
                    self._body = json.loads(raw) if raw else {}
                CALLS[-1] += " " + str(self._body.get("action"))
        if coll == "agents" and method == "GET":
            return self.paged(AGENTS, q)
        if coll in ("managed-ids-rules", "managed-smart-firewall-rules"):
            cat = IDS if coll == "managed-ids-rules" else SFW
            view = ids_view if cat is IDS else dict
            if method == "GET" and not item:
                return self.paged([view(e) for e in cat.values()], q)
            if method == "POST":
                b = self.body()
                e = cat.get(b.get("managed_rule_id"))
                if e is None:
                    return self.problem(422, "unknown managed_rule_id")
                if e["version"] > 0:
                    return self.problem(409, "setting exists")
                e.update(enabled=b.get("enabled", True), version=1)
                if cat is IDS:
                    e["tier_override"] = b.get("tier_override")
                return self.reply(201, view(e))
            e = cat.get(item)
            if e is None:
                return self.problem(404, "not found")
            if not self.version_ok(e):
                return self.problem(412, "version mismatch")
            if method == "PUT":
                b = self.body()
                e.update(enabled=b.get("enabled", True), version=e["version"] + 1)
                if cat is IDS:
                    e["tier_override"] = b.get("tier_override")
                return self.reply(200, view(e))
            if method == "DELETE":
                e.update(enabled=False, version=0)
                if cat is IDS:
                    e["tier_override"] = None
                return self.reply(204)
        if coll in STORE:
            store, fields = STORE[coll], WRITABLE[coll]
            if method == "GET" and not item:
                return self.paged(list(store.values()), q)
            if method == "POST":
                b = self.body()
                obj = {"id": str(uuid.uuid4()), "version": 1}
                obj.update(DEFAULTS[coll])
                obj.update({k: b[k] for k in fields if k in b})
                of = ORDER_FIELD.get(coll)
                if of and obj.get(of) is None:
                    obj[of] = 1 + max([o.get(of) or 0 for o in store.values()] or [0])
                store[obj["id"]] = obj
                return self.reply(201, obj)
            obj = store.get(item)
            if obj is None:
                return self.problem(404, "not found")
            if not self.version_ok(obj):
                return self.problem(412, "version mismatch")
            if method == "PUT":
                b = self.body()
                keep = {k: obj.get(k) for k in (ORDER_FIELD.get(coll),) if k}
                new = {"id": obj["id"], "version": obj["version"] + 1}
                new.update(DEFAULTS[coll])
                new.update({k: b[k] for k in fields if k in b})
                for k, v in keep.items():
                    new.setdefault(k, v)
                store[item] = new
                return self.reply(200, new)
            if method == "DELETE":
                del store[item]
                return self.reply(204)
        return self.problem(405, "method not allowed")

    def batch(self, ws_id):
        ops = self.body().get("operations") or []
        if not 1 <= len(ops) <= 100:
            return self.problem(422, "operations: 1 to 100 items")
        saved = copy.deepcopy(WORKSPACES[ws_id])
        WORKSPACES[ws_id]["calls"].append("BATCH %d" % len(ops))
        outer_path, outer_headers = self.path, self.headers
        results, failure = [], None
        for i, o in enumerate(ops):
            got = {}
            self.reply = lambda code, body=None, got=got: got.update(code=code, body=body)
            self.path = "/management/v1/workspaces/%s/%s" % (ws_id, o.get("path", ""))
            hdrs = Headers({k: v for k, v in outer_headers.items() if k.lower() not in ("if-match", "content-length")})
            if o.get("if_match"):
                hdrs["If-Match"] = o["if_match"]
            self.headers = hdrs
            self._body = o.get("body") or {}
            try:
                self.route(o.get("method", ""))
            finally:
                del self.reply
                del self._body
            if not 200 <= got.get("code", 500) < 300:
                failure = (i, o, got)
                break
            results.append({"status": got["code"], "body": got.get("body")})
        self.path, self.headers = outer_path, outer_headers
        if failure:
            i, o, got = failure
            calls = WORKSPACES[ws_id]["calls"]
            WORKSPACES[ws_id] = saved
            WORKSPACES[ws_id]["calls"] = calls + ["BATCH rolled back"]
            detail = (got.get("body") or {}).get("detail", "")
            return self.problem(got["code"], "operations[%d] (%s %s): %s; nothing in the batch was applied"
                                % (i, o.get("method"), o.get("path"), detail))
        return self.reply(200, {"results": results})

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def do_DELETE(self):
        self.route("DELETE")


if __name__ == "__main__":
    for spec in sys.argv[2:] or ["test-key=ws-1:firewall"]:
        key, rest = spec.split("=", 1)
        ws_id, agent = rest.split(":", 1)
        KEYS.setdefault(key, set()).add(ws_id)
        WORKSPACES.setdefault(ws_id, new_workspace(agent))
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
