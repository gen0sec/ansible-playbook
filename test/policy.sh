#!/usr/bin/env bash
# The policy role and its module against an in-memory fake of the management
# API (test/fake_gen0sec_api.py): the module tests (test/policy_module.yml), then
# policy.yml end to end. No network and no real key.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=18080
python3 test/fake_gen0sec_api.py "$PORT" &
FAKE=$!
TMP=$(mktemp -d)
trap 'kill "$FAKE"; rm -rf "$TMP"' EXIT
until curl -s -o /dev/null "http://127.0.0.1:$PORT/"; do sleep 0.1; done

fails=0
ok() { echo "ok   $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }

if ANSIBLE_LIBRARY="$PWD/roles/policy/library" ansible-playbook test/policy_module.yml >"$TMP/module.log" 2>&1; then
  ok "module tests"
else
  fail "module tests"; tail -30 "$TMP/module.log"
fi

# policy.yml with one policy file against workspace ws-1 of the fake.
mkdir -p "$TMP/policies"
cat >"$TMP/policies/test.yml" <<'YAML'
workspace_id: ws-2
smart_firewall_rules:
  telnet_outside: { name: Telnet from outside, expression: "tcp.dst_port == 23", action: log, order: 100 }
access_rules:
  scanner: { type: ipv4, value: 203.0.113.7, action: block }
YAML
play() {  # play KEY: run policy.yml on the temporary policy files
  GEN0SEC_MANAGEMENT_API_KEY="$1" GEN0SEC_ENDPOINT="http://127.0.0.1:$PORT" \
    ansible-playbook -i localhost, policy.yml -e "{\"policy_files\": [\"$TMP/policies/test.yml\"]}" 2>&1
}

out=$(play "") || true
if grep -q "Policy skipped: no management API key" <<<"$out"; then ok "no key: skipped with a warning"; else fail "no key: skipped with a warning"; fi

# The fake gives test-key workspace ws-2 for this run.
kill "$FAKE"; wait "$FAKE" 2>/dev/null || true
python3 test/fake_gen0sec_api.py "$PORT" test-key=ws-2:edge &
FAKE=$!
until curl -s -o /dev/null "http://127.0.0.1:$PORT/"; do sleep 0.1; done

if out=$(play test-key); then ok "apply: succeeds"; else fail "apply: succeeds"; echo "$out" | tail -20; fi
if grep -q '"batches": 1, "single": 0' <<<"$out"; then ok "apply: one batch"; else fail "apply: one batch"; fi
if grep -q '"created": \["telnet_outside"\]' <<<"$out"; then ok "apply: rule created"; else fail "apply: rule created"; fi
if grep -q "test-key" <<<"$out"; then fail "apply: key not in the output"; else ok "apply: key not in the output"; fi
out=$(play test-key) || true
if grep -q 'changes: {}' <<<"$out" && grep -q '"batches": 0, "single": 0' <<<"$out"; then ok "again: nothing changed, nothing sent"; else fail "again: nothing changed, nothing sent"; fi

cp "$TMP/policies/test.yml" "$TMP/policies/dup.yml"
out=$(GEN0SEC_MANAGEMENT_API_KEY=test-key GEN0SEC_ENDPOINT="http://127.0.0.1:$PORT" ansible-playbook -i localhost, policy.yml \
      -e "{\"policy_files\": [\"$TMP/policies/test.yml\", \"$TMP/policies/dup.yml\"]}" 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 0 ] && grep -q "same workspace_id" <<<"$out"; then ok "two files for one workspace: refused"; else fail "two files for one workspace: refused"; fi

if [ "$fails" -ne 0 ]; then
  echo "$fails failed"
  exit 1
fi
echo "all passed"
