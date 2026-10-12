#!/usr/bin/env bash
# Runs roles/fail2ban on the ansible-core that Oracle Linux 9 ships (2.14), in
# docker, to keep the roles working on the oldest supported control machine
# (README: ansible-core 2.14 or newer). Checks, with connection: local into a
# throwaway directory and no repository key:
#   - fail2ban disabled: the run succeeds and writes nothing;
#   - fail2ban enabled with a test key: the run succeeds and writes the files;
#   - fail2ban enabled with an empty key: the run fails naming the variable;
#   - playbook.yml passes --syntax-check.
# Needs docker and network (dnf); not part of `make test`, run `make test-old-core`.
# Exits 77 (skip) without docker.
#   IMAGE=oraclelinux:9 overrides the image.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ "${1:-}" != "--inside" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not found" >&2
    exit 77
  fi
  exec docker run --rm -v "$ROOT:/repo:ro" "${IMAGE:-oraclelinux:9}" \
    bash -c 'dnf -y -q install ansible-core python3 >/dev/null && bash /repo/test/old_ansible_core.sh --inside'
fi

ROOT=/repo
version_line="$(ansible --version | head -1)"
echo "$version_line"
# The point is the oldest supported core: if the image ever ships another one,
# this test would pass without testing it.
case "$version_line" in
  *"[core 2.14."*) ;;
  *) echo "FAIL: expected ansible-core 2.14.x, got: $version_line" >&2; exit 1 ;;
esac
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

mkdir -p "$OUT/roles"
cp -r "$ROOT/roles/fail2ban" "$OUT/roles/fail2ban"
cat > "$OUT/play.yml" <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: false
  roles:
    - role: fail2ban
PLAY
printf '[defaults]\nroles_path = %s/roles\n' "$OUT" > "$OUT/ansible.cfg"

# run_play <name> <enabled> <key>: leaves the output in $OUT/<name>.log, the exit code in $rc.
run_play() {
  local name="$1" enabled="$2" key="$3"
  mkdir -p "$OUT/$name/etc/action.d"
  ANSIBLE_CONFIG="$OUT/ansible.cfg" ANSIBLE_LOCALHOST_WARNING=False \
    ANSIBLE_INVENTORY_UNPARSED_WARNING=False \
    ansible-playbook -i localhost, "$OUT/play.yml" \
    -e "fail2ban_enabled=$enabled fail2ban_manage_service=false fail2ban_config_dir=$OUT/$name/etc" \
    -e "gen0sec_api_key=$key" > "$OUT/$name.log" 2>&1
  rc=$?
}

run_play disabled false ""
[ "$rc" -eq 0 ] || { fail "disabled run exited $rc"; cat "$OUT/disabled.log" >&2; }
[ -z "$(find "$OUT/disabled/etc" -type f)" ] || fail "the role wrote files while disabled"

run_play enabled true "TESTKEY-0123456789"
[ "$rc" -eq 0 ] || { fail "enabled run exited $rc"; cat "$OUT/enabled.log" >&2; }
[ -f "$OUT/enabled/etc/gen0sec.headers" ] || fail "enabled run wrote no gen0sec.headers"
[ -f "$OUT/enabled/etc/jail.local" ] || fail "enabled run wrote no jail.local"

run_play nokey true ""
[ "$rc" -ne 0 ] || fail "enabled run with an empty key succeeded"
/usr/bin/grep -q 'gen0sec_api_key is empty' "$OUT/nokey.log" || { fail "empty-key failure does not name gen0sec_api_key"; cat "$OUT/nokey.log" >&2; }

(cd "$ROOT" && ansible-playbook -i localhost, --syntax-check playbook.yml) > "$OUT/syntax.log" 2>&1 \
  || { fail "playbook.yml --syntax-check failed"; cat "$OUT/syntax.log" >&2; }

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "ok   fail2ban role works on this ansible-core"
