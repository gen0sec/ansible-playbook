#!/usr/bin/env bash
# Runs roles/fail2ban against a throwaway root (connection: local, no root, no
# fail2ban package, no service) and checks what it writes:
#   - the header file holds `Authorization: Bearer <key>` and is mode 0600;
#   - gen0sec.local is absent by default and holds exactly the override keys;
#   - an empty key fails with a message naming the variable;
#   - the key never appears in the ansible output (-v --diff);
#   - a second run changes nothing.
# The role is pointed at the temp root with fail2ban_config_dir, and
# fail2ban_manage_service=false skips the package install and the service.
# The file owner is the current user here (fail2ban_file_owner/_group); the
# defaults are checked to be root.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "FAIL: ansible-playbook not found" >&2
  exit 1
fi

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
KEY="MARKERKEY-7f3a91c2d5e84b60"
failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

mkdir -p "$OUT/roles"
ln -s "$ROOT/roles/fail2ban" "$OUT/roles/fail2ban"
cat > "$OUT/play.yml" <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: false
  roles:
    - role: fail2ban
PLAY
printf '[defaults]\nroles_path = %s/roles\n' "$OUT" > "$OUT/ansible.cfg"

# run_play <name> <extra-vars-json>: runs the role into $OUT/<name>/etc.
# Leaves the output in $OUT/<name>.log and the exit code in $rc.
run_play() {
  local name="$1" vars="$2"
  mkdir -p "$OUT/$name/etc/action.d"
  printf '%s' "$vars" | sed "s#@ETC@#$OUT/$name/etc#" > "$OUT/$name/vars.json"
  ANSIBLE_CONFIG="$OUT/ansible.cfg" ANSIBLE_LOCALHOST_WARNING=False \
    ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
    ansible-playbook -i localhost, -v --diff "$OUT/play.yml" \
    -e "@$OUT/$name/vars.json" > "$OUT/$name.log" 2>&1
  rc=$?
}

me_owner="$(id -un)"
me_group="$(id -gn)"
base='"fail2ban_enabled":true,"fail2ban_manage_service":false,"fail2ban_config_dir":"@ETC@","fail2ban_file_owner":"'"$me_owner"'","fail2ban_file_group":"'"$me_group"'"'

# --- default: key only
run_play default "{$base,\"gen0sec_api_key\":\"$KEY\"}"
etc="$OUT/default/etc"
[ "$rc" -eq 0 ] || { fail "default run exited $rc"; cat "$OUT/default.log" >&2; }
[ "$(cat "$etc/gen0sec.headers" 2>/dev/null)" = "Authorization: Bearer $KEY" ] \
  || fail "header file content is not 'Authorization: Bearer <key>'"
[ "$(stat -c %a "$etc/gen0sec.headers" 2>/dev/null)" = "600" ] \
  || fail "header file mode is not 0600"
cmp -s "$ROOT/roles/fail2ban/files/gen0sec.conf" "$etc/action.d/gen0sec.conf" \
  || fail "installed action differs from roles/fail2ban/files/gen0sec.conf"
[ ! -e "$etc/action.d/gen0sec.local" ] || fail "gen0sec.local exists with no override set"
if /usr/bin/grep -rqF "$KEY" "$OUT/default.log"; then fail "the key appears in the ansible output"; fi
if /usr/bin/grep -rlF "$KEY" "$etc" | /usr/bin/grep -v 'gen0sec.headers$' | /usr/bin/grep -q .; then
  fail "the key was written to a file other than gen0sec.headers"
fi
/usr/bin/grep -q 'banaction = gen0sec' "$etc/jail.local" 2>/dev/null || fail "jail.local lacks the gen0sec banaction"

# --- second run changes nothing
ANSIBLE_CONFIG="$OUT/ansible.cfg" ANSIBLE_LOCALHOST_WARNING=False \
  ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
  ansible-playbook -i localhost, -v --diff "$OUT/play.yml" \
  -e "@$OUT/default/vars.json" > "$OUT/default2.log" 2>&1 || fail "second run failed"
/usr/bin/grep -q 'changed=0 ' "$OUT/default2.log" || fail "second run did not report changed=0"
if /usr/bin/grep -qF "$KEY" "$OUT/default2.log"; then fail "the key appears in the second run output"; fi

# --- overrides
run_play overrides "{$base,\"gen0sec_api_key\":\"$KEY\",\"gen0sec_expiration\":900,\"fail2ban_host\":\"web-1\"}"
etc="$OUT/overrides/etc"
[ "$rc" -eq 0 ] || { fail "overrides run exited $rc"; cat "$OUT/overrides.log" >&2; }
want=$'[Init]\nexpiration = 900\ng0shost = web-1'
[ "$(cat "$etc/action.d/gen0sec.local" 2>/dev/null)" = "$want" ] \
  || fail "gen0sec.local is not exactly the override keys"
ANSIBLE_CONFIG="$OUT/ansible.cfg" ANSIBLE_LOCALHOST_WARNING=False \
  ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
  ansible-playbook -i localhost, -v --diff "$OUT/play.yml" \
  -e "@$OUT/overrides/vars.json" > "$OUT/overrides2.log" 2>&1 || fail "overrides second run failed"
/usr/bin/grep -q 'changed=0 ' "$OUT/overrides2.log" || fail "overrides second run did not report changed=0"

# only the expiration set: no host key
run_play expiry "{$base,\"gen0sec_api_key\":\"$KEY\",\"gen0sec_expiration\":300}"
[ "$(cat "$OUT/expiry/etc/action.d/gen0sec.local" 2>/dev/null)" = $'[Init]\nexpiration = 300' ] \
  || fail "gen0sec.local with only an expiration is not just that key"

# overrides removed again: the file goes away
printf '%s' "{$base,\"gen0sec_api_key\":\"$KEY\"}" | sed "s#@ETC@#$etc#" > "$OUT/overrides/vars-unset.json"
ANSIBLE_CONFIG="$OUT/ansible.cfg" ANSIBLE_LOCALHOST_WARNING=False \
  ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
  ansible-playbook -i localhost, "$OUT/play.yml" -e "@$OUT/overrides/vars-unset.json" \
  > "$OUT/unset.log" 2>&1 || fail "run with the overrides unset failed"
[ ! -e "$etc/action.d/gen0sec.local" ] || fail "gen0sec.local was not removed when no override is set"

# --- empty key fails, naming the variable
run_play nokey "{$base,\"gen0sec_api_key\":\"\"}"
[ "$rc" -ne 0 ] || fail "an empty key did not fail the run"
/usr/bin/grep -q 'gen0sec_api_key' "$OUT/nokey.log" || fail "the failure does not name gen0sec_api_key"
[ ! -e "$OUT/nokey/etc/gen0sec.headers" ] || fail "a header file was written for an empty key"

# --- null overrides are the same as unset: no .local, no empty key
run_play nulls "{$base,\"gen0sec_api_key\":\"$KEY\",\"gen0sec_expiration\":null,\"fail2ban_host\":null}"
[ "$rc" -eq 0 ] || { fail "null overrides run exited $rc"; cat "$OUT/nulls.log" >&2; }
[ ! -e "$OUT/nulls/etc/action.d/gen0sec.local" ] || fail "gen0sec.local exists for null overrides"
# one null, one set: only the set key is written
run_play nullhost "{$base,\"gen0sec_api_key\":\"$KEY\",\"gen0sec_expiration\":120,\"fail2ban_host\":null}"
[ "$(cat "$OUT/nullhost/etc/action.d/gen0sec.local" 2>/dev/null)" = $'[Init]\nexpiration = 120' ] \
  || fail "gen0sec.local with a null host is not just the expiration"
run_play nullexp "{$base,\"gen0sec_api_key\":\"$KEY\",\"gen0sec_expiration\":null,\"fail2ban_host\":\"web-2\"}"
[ "$(cat "$OUT/nullexp/etc/action.d/gen0sec.local" 2>/dev/null)" = $'[Init]\ng0shost = web-2' ] \
  || fail "gen0sec.local with a null expiration is not just the host"

# --- a bad expiration fails, naming the variable
for bad in '-5' '"abc"' '"1.5"' '"0600"' '"00"' 0 1 59 '"59"' 315360001 99999999999999999999; do
  run_play badexp "{$base,\"gen0sec_api_key\":\"$KEY\",\"gen0sec_expiration\":$bad}"
  [ "$rc" -ne 0 ] || fail "expiration $bad did not fail the run"
  /usr/bin/grep -q 'gen0sec_expiration' "$OUT/badexp.log" || fail "the failure for expiration $bad does not name gen0sec_expiration"
  [ ! -e "$OUT/badexp/etc/action.d/gen0sec.local" ] || fail "gen0sec.local written for expiration $bad"
done

# --- the accepted range is 60 seconds to 10 years, both ends included
for good in 60 315360000 '"60"'; do
  run_play goodexp "{$base,\"gen0sec_api_key\":\"$KEY\",\"gen0sec_expiration\":$good}"
  [ "$rc" -eq 0 ] || fail "expiration $good failed the run"
  want="${good//\"/}"
  [ "$(cat "$OUT/goodexp/etc/action.d/gen0sec.local" 2>/dev/null)" = "$(printf '[Init]\nexpiration = %s' "$want")" ] \
    || fail "gen0sec.local for expiration $good is not just the expiration"
done

# --- disabled: a no-op, even with an empty key
run_play disabled "$(printf '%s' "{$base,\"gen0sec_api_key\":\"\"}" | sed 's/"fail2ban_enabled":true/"fail2ban_enabled":false/')"
[ "$rc" -eq 0 ] || { fail "disabled run exited $rc"; cat "$OUT/disabled.log" >&2; }
if [ -n "$(find "$OUT/disabled/etc" -type f)" ]; then
  fail "the role wrote files while fail2ban_enabled is false: $(find "$OUT/disabled/etc" -type f | tr '\n' ' ')"
fi

# --- the role-written .local, read through Fail2Ban itself
if python3 -c 'import sys; sys.path[:0] = ["/usr/lib/python3/dist-packages", __import__("os").environ.get("GEN0SEC_FAIL2BAN_PYTHONPATH", "")]; import fail2ban' 2>/dev/null; then
  python3 "$ROOT/test/fail2ban_action.py" --local "$OUT/nullexp/etc/action.d/gen0sec.local" --host web-2 \
    > "$OUT/local1.log" 2>&1 || { fail "ActionReader did not read the host-only .local as expected"; cat "$OUT/local1.log" >&2; }
  python3 "$ROOT/test/fail2ban_action.py" --local "$OUT/nullhost/etc/action.d/gen0sec.local" --expires 120 \
    > "$OUT/local2.log" 2>&1 || { fail "ActionReader did not read the expiration-only .local as expected"; cat "$OUT/local2.log" >&2; }
else
  echo "SKIP: fail2ban Python package not found; the .local is not read through ActionReader (make install fetches it)"
fi

# --- the header task must carry no_log and diff: false (each one alone is enough
# to keep the key out of the output on its own, so check both)
tasks="${F2B_TASKS:-$ROOT/roles/fail2ban/tasks/enabled.yml}"
block="$(awk '/^- name:/ { on = ($0 ~ /API key header file/) } on' "$tasks")"
[ -n "$block" ] || fail "the header file task was not found in $tasks"
printf '%s\n' "$block" | /usr/bin/grep -q '^  no_log: true$' || fail "the header file task lacks no_log: true"
printf '%s\n' "$block" | /usr/bin/grep -q '^  diff: false$' || fail "the header file task lacks diff: false"

# --- defaults: root-owned, 0600 header, service managed
/usr/bin/grep -q '^fail2ban_file_owner: root$' "$ROOT/roles/fail2ban/defaults/main.yml" || fail "default owner is not root"
/usr/bin/grep -q '^fail2ban_file_group: root$' "$ROOT/roles/fail2ban/defaults/main.yml" || fail "default group is not root"
/usr/bin/grep -q '^fail2ban_config_dir: /etc/fail2ban$' "$ROOT/roles/fail2ban/defaults/main.yml" || fail "default config dir is not /etc/fail2ban"
/usr/bin/grep -q '^fail2ban_manage_service: true$' "$ROOT/roles/fail2ban/defaults/main.yml" || fail "the service is not managed by default"

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "fail2ban_render: all checks passed"
