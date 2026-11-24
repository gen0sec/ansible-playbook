#!/usr/bin/python
# -*- coding: utf-8 -*-
# Reconcile a Gen0Sec workspace's policy through the management API.

from __future__ import annotations

DOCUMENTATION = r"""
module: gen0sec_policy
short_description: Reconcile a Gen0Sec workspace's features and rules
description:
  - Brings one workspace of the Gen0Sec management API to the desired policy in
    a single call: managed IDS threat classes, managed smart firewall rules,
    L3/L4 firewall rules, access rules, smart firewall rules and custom WAF
    rules (proxy mode).
  - Only rules carrying I(owner_tag) are managed. Rules made in the dashboard or
    by other tools are left alone, unless I(unowned=delete).
  - Firewall, smart firewall and WAF rules are matched by a C([ansible:<key>]) marker
    at the end of their description; access rules by their type and value.
  - All writes are sent as one batch (C(POST .../batch)): applied in order, in one
    transaction, all or nothing, so agents receive the new policy as one
    configuration instead of one intermediate state per write. More than 100
    writes go in several batches, in the same order. Without the batch endpoint
    (HTTP 404/405) the writes are sent one by one, allow rules first.
  - Supports check mode and diff mode.
options:
  api_key: {type: str, required: true, no_log: true, description: Management API key with read/write/delete on the managed types.}
  endpoint: {type: str, default: "https://api.gen0sec.com", description: API base URL. https only, except localhost.}
  user_agent: {type: str, default: "gen0sec-policy-ansible/1.0", description: "User-Agent header of every request: a product/version string the API's bot protection accepts."}
  workspace_id: {type: str, required: true}
  owner_tag: {type: str, default: ansible, description: Tag marking the rules this module owns.}
  extra_tags: {type: list, elements: str, default: [], description: More tags put on every owned rule.}
  prune: {type: bool, default: true, description: Delete owned rules that are no longer in the desired policy.}
  unowned: {type: str, default: keep, choices: [keep, delete], description: "What to do with rules not carrying I(owner_tag) (dashboard or other tools): keep, or delete so the workspace holds only the desired policy. Applies to firewall, access and smart firewall rules. Unowned WAF rules are always kept: signal integrations write rules there too."}
  firewall_rules: {type: dict, default: {}, description: "key -> rule (name, direction, action, ip_version, protocol, source, destination, source_ports, destination_ports, conn_state, tcp_flags, priority, enabled, description, expires_at)."}
  access_rules: {type: dict, default: {}, description: "label -> rule (type, value, action, description, expires_at). Matched by type and value; the label is only for you."}
  smart_firewall_rules: {type: dict, default: {}, description: "key -> rule (name, expression, action, enabled, order, description, expires_at)."}
  waf_rules: {type: dict, default: {}, description: "key -> custom WAF rule (name, expression, action, enabled, order, description, expires_at). Evaluated by agents in proxy mode; order lower runs first, managed WAF rules run at 100."}
  managed_ids: {type: dict, description: "Omit to leave IDS classes alone. Keys: default_tier (alert|block|null), tiers (class -> tier), disabled (list of classes)."}
  managed_smart_firewall: {type: dict, description: "Omit to leave managed smart firewall rules alone. Keys: enabled (bool), excluded (list of rule ids)."}
  batch: {type: str, default: auto, choices: [auto, always, never], description: "auto: one batch, single calls if the API has no batch endpoint; always: fail without it; never: single calls."}
  timeout: {type: int, default: 30}
"""

RETURN = r"""
requests: {description: "How the writes were sent: number of batches and of single calls.", type: dict}
actions: {description: What was (or in check mode would be) created, updated and deleted, per collection., type: dict}
agents: {description: The workspace's agents (hostname, online, version, mode)., type: list}
ids_classes: {description: "threat class -> alert, block or off, after the run.", type: dict}
"""

import json
import re
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from ansible.module_utils.basic import AnsibleModule

# Agents apply every change as soon as the platform pushes it, one write at a
# time, so the order of writes matters: a deny that lands before its allows
# can cut an agent off (from SSH, or from the platform, so the allows never
# arrive). Writes therefore open before they close: creations and updates in
# allow-first order, deletions deny-first.
DENY_ACTIONS = ("drop", "reject", "block")


def open_first(spec):
    """Sort key: allow/log rules first, deny rules last, then by priority/order."""
    deny = (spec.get("action") or "") in DENY_ACTIONS
    rank = spec.get("priority", spec.get("order"))
    return (deny, rank if isinstance(rank, int) else 1 << 30)


MARKER = re.compile(r"\s*\[ansible:([A-Za-z0-9_.-]+)\]\s*$")
PAGE_SIZE = 100
# Operations per batch (the API's MaxBatchOperations).
BATCH_MAX = 100
BATCH_FAILED_OP = re.compile(r"operations\[(\d+)\]")

# Writable fields per collection (as the Terraform provider sends them), and
# the server-side defaults of optional fields left out.
FIREWALL_FIELDS = ["name", "direction", "action", "ip_version", "protocol", "source",
                   "destination", "source_ports", "destination_ports", "conn_state",
                   "tcp_flags", "priority", "enabled", "description", "expires_at", "tags"]
FIREWALL_DEFAULTS = {"ip_version": 4, "protocol": "any", "enabled": True}
ACCESS_FIELDS = ["type", "value", "action", "description", "expires_at", "tags"]
SMART_FIELDS = ["name", "expression", "action", "enabled", "order", "description", "expires_at", "tags"]
SMART_DEFAULTS = {"enabled": True}
WAF_FIELDS = ["name", "expression", "action", "enabled", "order", "description", "expires_at", "tags"]
WAF_DEFAULTS = {"enabled": True}
# Left out, these keep the server's value (a new rule goes last).
KEEP_IF_OMITTED = {"priority", "order"}


class ApiError(Exception):
    def __init__(self, status, detail, code=None):
        super().__init__("%s (HTTP %s)" % (detail, status))
        self.detail = detail
        self.status = status
        self.code = code


class Client:
    def __init__(self, endpoint, api_key, timeout, user_agent="gen0sec-policy-ansible/1.0"):
        u = urlparse(endpoint)
        if u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1")):
            raise ValueError("endpoint must be https (plain http only for localhost): %s" % endpoint)
        self.base = endpoint.rstrip("/")
        self.key = api_key
        self.timeout = timeout
        self.user_agent = user_agent

    def do(self, method, path, body=None, headers=None, retry_network=True):
        payload = json.dumps(body).encode() if body is not None else None
        hdrs = {"Authorization": "Bearer " + self.key, "Accept": "application/json",
                "User-Agent": self.user_agent}
        if payload is not None:
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        last = None
        for attempt in range(1, 5):
            req = Request(self.base + path, data=payload, method=method, headers=hdrs)
            try:
                with urlopen(req, timeout=self.timeout) as res:
                    raw = res.read()
                    return json.loads(raw) if raw else {}
            except HTTPError as e:
                raw = e.read()
                try:
                    p = json.loads(raw)
                except ValueError:
                    p = {}
                detail = p.get("detail") or raw.decode(errors="replace").strip() or e.reason
                errs = "; ".join("%s: %s" % (x.get("location"), x.get("message")) for x in p.get("errors") or [])
                last = ApiError(e.code, detail + (" [" + errs + "]" if errs else ""), p.get("code"))
                if e.code != 429 and e.code < 500:
                    raise last
            except URLError as e:
                last = ApiError(0, "%s %s: %s" % (method, path, e.reason))
                if not retry_network:
                    # Unknown whether the request was applied: do not resend.
                    raise last
            if attempt < 4:
                time.sleep(0.25 * (2 ** attempt))
        raise last

    def list(self, path, query=None):
        q = dict(query or {})
        q["page_size"] = PAGE_SIZE
        items = []
        while True:
            res = self.do("GET", path + "?" + urlencode(q))
            items.extend(res.get("items") or [])
            token = res.get("next_page_token")
            if not token:
                return items
            q["page_token"] = token


def if_match(obj):
    return {"If-Match": '"%s"' % obj.get("version", 0)}


def body_of(desired, fields):
    return {k: desired[k] for k in fields if desired.get(k) is not None}


def differs(desired, current, fields, defaults):
    """Fields whose desired value the current object does not hold."""
    out = []
    for f in fields:
        want = desired.get(f)
        if want is None and f in KEEP_IF_OMITTED:
            continue
        if want is None:
            want = defaults.get(f)
        have = current.get(f)
        if f == "tags":
            if sorted(want or []) != sorted(have or []):
                out.append(f)
        elif want != have and not (want in (None, "") and have in (None, "")):
            out.append(f)
    return out


class Reconciler:
    def __init__(self, module, client):
        self.m = module
        self.c = client
        self.check = module.check_mode
        p = module.params
        self.ws = "/management/v1/workspaces/" + p["workspace_id"]
        self.owner = p["owner_tag"]
        self.tags = sorted(set([self.owner] + list(p["extra_tags"])))
        self.prune = p["prune"]
        self.unowned = p["unowned"]
        self.actions = {}
        self.diff = {"before": {}, "after": {}}
        self.batch_mode = p["batch"]
        # Writes collected in order, sent by flush().
        self.ops = []
        self.sent = {"batches": 0, "single": 0}

    def note(self, coll, action, key, before=None, after=None):
        self.actions.setdefault(coll, {"created": [], "updated": [], "deleted": []})[action].append(key)
        label = "%s/%s" % (coll, key)
        if before is not None:
            self.diff["before"][label] = before
        if after is not None:
            self.diff["after"][label] = after

    # --- writes ---------------------------------------------------------------------
    def write(self, method, path, body=None, current=None, missing_ok=False):
        """Queue one write. path is relative to the workspace (collection or item)."""
        if self.check:
            return
        self.ops.append({"method": method, "path": path.lstrip("/"), "body": body,
                         "if_match": if_match(current)["If-Match"] if current is not None else None,
                         "missing_ok": missing_ok})

    def flush(self):
        ops, self.ops = self.ops, []
        if not ops:
            return
        if self.batch_mode != "never":
            for start in range(0, len(ops), BATCH_MAX):
                chunk = ops[start:start + BATCH_MAX]
                if not self.send_batch(chunk):
                    if self.batch_mode == "always":
                        raise ApiError(404, "the API has no batch endpoint (batch=always)")
                    # Older API: the rest one by one (none of this chunk was applied).
                    ops = ops[start:]
                    break
            else:
                return
        for op in ops:
            self.send_single(op)

    def send_batch(self, ops):
        """Send ops as one batch. False when the API has no batch endpoint."""
        while ops:
            body = {"operations": [
                {k: v for k, v in (("method", o["method"]), ("path", o["path"]),
                                   ("if_match", o["if_match"]), ("body", o["body"])) if v is not None}
                for o in ops]}
            try:
                # A batch that failed applied nothing, so 429/5xx are retried; a
                # network error may have hit after the commit, so it is not.
                self.c.do("POST", self.ws + "/batch", body, retry_network=False)
                self.sent["batches"] += 1
                return True
            except ApiError as e:
                m = BATCH_FAILED_OP.search(str(e))
                if m is None and e.status in (404, 405):
                    return False
                i = int(m.group(1)) if m else -1
                if 0 <= i < len(ops) and e.status == 404 and ops[i]["missing_ok"]:
                    ops = ops[:i] + ops[i + 1:]   # already gone: drop it and resend
                    continue
                if 0 <= i < len(ops):
                    raise ApiError(e.status, "batch: %s %s: %s" % (ops[i]["method"], ops[i]["path"], e.detail), e.code)
                raise
        return True

    def send_single(self, op):
        path = self.ws + "/" + op["path"]
        headers = {"If-Match": op["if_match"]} if op["if_match"] else {}
        if op["method"] == "POST":
            headers["Idempotency-Key"] = str(uuid.uuid4())
        try:
            self.c.do(op["method"], path, op["body"], headers)
            self.sent["single"] += 1
        except ApiError as e:
            if not (e.status == 404 and op["missing_ok"]):
                raise

    # --- owned rule collections -------------------------------------------------
    def rules(self, coll, path, desired_map, fields, defaults, identity, desired_identity=None,
              keep_unowned=False):
        if desired_identity is not None:
            rekeyed = {}
            for label, spec in desired_map.items():
                ident = desired_identity(spec)
                if ident in rekeyed:
                    self.m.fail_json(msg="%s: %r and another entry are the same rule (%s)" % (coll, label, ident))
                rekeyed[ident] = spec
            desired_map = rekeyed
        owned = {}
        unowned = []
        for obj in self.c.list(self.ws + path):
            if self.owner not in (obj.get("tags") or []):
                unowned.append(obj)
                continue
            key = identity(obj)
            if key is None or key in owned:
                # A tagged rule without a marker, or a duplicate: leave it alone.
                continue
            owned[key] = obj

        for key, spec in sorted(desired_map.items(), key=lambda kv: (open_first(kv[1]), kv[0])):
            want = dict(spec)
            # Send the defaults of omitted fields too: the API requires some of
            # them (ip_version) in the body although it documents a default.
            for f, v in defaults.items():
                want.setdefault(f, v)
            want["tags"] = self.tags
            if coll != "access_rules":
                desc = (want.get("description") or "").strip()
                want["description"] = (desc + " " if desc else "") + "[ansible:%s]" % key
            cur = owned.pop(key, None)
            body = body_of(want, fields)
            if cur is None:
                self.note(coll, "created", key, after=body)
                self.write("POST", path, body)
            else:
                changed = differs(want, cur, fields, defaults)
                if changed:
                    self.note(coll, "updated", key,
                              before={f: cur.get(f) for f in changed},
                              after={f: want.get(f, defaults.get(f)) for f in changed})
                    self.write("PUT", "%s/%s" % (path, cur["id"]), body, cur)

        if self.unowned == "delete" and not keep_unowned:
            for cur in sorted(unowned, key=lambda o: (not open_first(o)[0], o.get("name") or o.get("value") or "", o["id"])):
                label = "unowned:%s#%s" % (cur.get("name") or "%s:%s" % (cur.get("type"), cur.get("value")), cur["id"][:8])
                self.note(coll, "deleted", label, before=body_of(cur, fields))
                self.write("DELETE", "%s/%s" % (path, cur["id"]), current=cur, missing_ok=True)

        if self.prune:
            for key, cur in sorted(owned.items(), key=lambda kv: (not open_first(kv[1])[0], kv[0])):
                self.note(coll, "deleted", key, before=body_of(cur, fields))
                self.write("DELETE", "%s/%s" % (path, cur["id"]), current=cur, missing_ok=True)

    @staticmethod
    def marker_key(obj):
        m = MARKER.search(obj.get("description") or "")
        return m.group(1) if m else None

    # --- managed catalogues (switches) --------------------------------------------
    def managed(self, coll, path, desired_for):
        """desired_for(entry) -> None (leave), False (off) or a dict of writable fields (on)."""
        for entry in self.c.list(self.ws + path):
            want = desired_for(entry)
            if want is None:
                continue
            key = entry.get("threat_class") or entry.get("name") or entry["id"]
            item = "%s/%s" % (path, entry["id"])
            if want is False:
                if entry.get("enabled") and entry.get("version", 0) > 0:
                    self.note(coll, "deleted", key, before={"enabled": True}, after={"enabled": False})
                    self.write("DELETE", item, current=entry)
                continue
            changed = [f for f, v in want.items() if entry.get(f) != v]
            if not changed:
                continue
            body = dict(want, managed_rule_id=entry["id"])
            before = {f: entry.get(f) for f in changed}
            if entry.get("version", 0) == 0:
                self.note(coll, "created", key, before=before, after=want)
                self.write("POST", path, body)
            else:
                self.note(coll, "updated", key, before=before, after=want)
                self.write("PUT", item, body, entry)

    def run(self):
        p = self.m.params
        if p.get("managed_ids") is not None:
            cfg = p["managed_ids"]
            tiers = cfg.get("tiers") or {}
            default = cfg.get("default_tier", "alert")
            disabled = set(cfg.get("disabled") or [])
            for t in list(tiers.values()) + ([default] if default is not None else []):
                if t not in ("alert", "block"):
                    self.m.fail_json(msg="managed_ids tiers must be alert or block, got %r" % t)

            def ids_want(e):
                cls = e.get("threat_class")
                if cls in disabled:
                    return False
                want = {"enabled": True}
                tier = tiers.get(cls, default)
                if tier is not None:
                    want["tier_override"] = tier
                return want
            self.managed("managed_ids", "/managed-ids-rules", ids_want)

        if p.get("managed_smart_firewall") is not None:
            cfg = p["managed_smart_firewall"]
            on = bool(cfg.get("enabled", True))
            excluded = set(cfg.get("excluded") or [])
            self.managed("managed_smart_firewall", "/managed-smart-firewall-rules",
                         lambda e: False if (not on or e["id"] in excluded) else {"enabled": True})

        self.rules("firewall_rules", "/firewall-rules", p["firewall_rules"],
                   FIREWALL_FIELDS, FIREWALL_DEFAULTS, self.marker_key)
        ident = lambda o: "%s:%s" % (o.get("type"), o.get("value"))  # noqa: E731
        self.rules("access_rules", "/access-rules", p["access_rules"],
                   ACCESS_FIELDS, {}, ident, desired_identity=ident)
        self.rules("smart_firewall_rules", "/smart-firewall-rules", p["smart_firewall_rules"],
                   SMART_FIELDS, SMART_DEFAULTS, self.marker_key)
        self.rules("waf_rules", "/waf-rules", p["waf_rules"],
                   WAF_FIELDS, WAF_DEFAULTS, self.marker_key, keep_unowned=True)
        self.flush()

    def report(self):
        agents = [{k: a.get(k) for k in ("hostname", "online", "version", "mode")}
                  for a in self.c.list(self.ws + "/agents")]
        ids = {}
        if not self.check:
            for e in self.c.list(self.ws + "/managed-ids-rules"):
                ids[e.get("threat_class")] = (e.get("tier") or "alert") if e.get("enabled") else "off"
        return agents, ids


def main():
    module = AnsibleModule(
        argument_spec=dict(
            api_key=dict(type="str", required=True, no_log=True),
            endpoint=dict(type="str", default="https://api.gen0sec.com"),
            user_agent=dict(type="str", default="gen0sec-policy-ansible/1.0"),
            workspace_id=dict(type="str", required=True),
            owner_tag=dict(type="str", default="ansible"),
            extra_tags=dict(type="list", elements="str", default=[]),
            prune=dict(type="bool", default=True),
            unowned=dict(type="str", default="keep", choices=["keep", "delete"]),
            firewall_rules=dict(type="dict", default={}),
            access_rules=dict(type="dict", default={}),
            smart_firewall_rules=dict(type="dict", default={}),
            waf_rules=dict(type="dict", default={}),
            managed_ids=dict(type="dict"),
            managed_smart_firewall=dict(type="dict"),
            batch=dict(type="str", default="auto", choices=["auto", "always", "never"]),
            timeout=dict(type="int", default=30),
        ),
        supports_check_mode=True,
    )
    p = module.params
    for coll in ("firewall_rules", "smart_firewall_rules", "waf_rules"):
        for key in p[coll]:
            if not re.match(r"^[A-Za-z0-9_.-]+$", key):
                module.fail_json(msg="%s key %r: use letters, digits, '_', '.', '-'" % (coll, key))
    try:
        client = Client(p["endpoint"], p["api_key"], p["timeout"], p["user_agent"])
        r = Reconciler(module, client)
        r.run()
        agents, ids = r.report()
    except (ApiError, ValueError) as e:
        module.fail_json(msg=str(e))
    changed = any(v for a in r.actions.values() for v in a.values())
    result = dict(changed=changed, actions=r.actions, agents=agents, ids_classes=ids, requests=r.sent)
    if module._diff:
        result["diff"] = r.diff
    module.exit_json(**result)


if __name__ == "__main__":
    main()
